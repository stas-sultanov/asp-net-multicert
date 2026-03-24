// Authored by Stas Sultanov
// Copyright © Stas Sultanov

using System.Buffers;
using System.Net;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

/// <summary>
/// A self-contained HTTPS test server built on Kestrel that demonstrates certificate selection
/// based on the certificate authentication algorithms advertised in the TLS ClientHello message.
/// Supports both ECDsa and RSA certificates.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class TestServer
{
	#region Fields

	/// <summary>
	/// The key used to store the parsed <see cref="AuthenticationAlgorithm"/> value
	/// in <see cref="ConnectionContext"/> during the TLS handshake.
	/// </summary>
	private const String AuthenticationAlgorithmKey = "AuthenticationAlgorithm";

	/// <summary>
	/// The set of TLS cipher suites the server is restricted to.
	/// Includes both TLS 1.3 and TLS 1.2 suites for ECDsa and RSA key exchange.
	/// </summary>
	private static readonly TlsCipherSuite[] tlsCipherSuites =
	[
		// TLS 1.3 cipher suites
		TlsCipherSuite.TLS_AES_128_GCM_SHA256,
		TlsCipherSuite.TLS_AES_256_GCM_SHA384,
		// TLS 1.2 cipher suites
		TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
		TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384
	];

	/// <summary>Self-signed ECDsa certificate used when the client supports ECDSA certificate authentication.</summary>
	private readonly X509Certificate2 certificateECDsa;

	/// <summary>Self-signed RSA certificate used when the client supports RSA certificate authentication.</summary>
	private readonly X509Certificate2 certificate_rsa_pkcs1_sha256;

	#endregion

	#region Constructors

	/// <summary>
	/// Initializes a new <see cref="TestServer"/> instance by generating self-signed
	/// ECDsa and RSA certificates via <see cref="CertificateHelper"/>.
	/// </summary>
	public TestServer()
	{
		var certificateHelper = new CertificateHelper();

		certificateECDsa = certificateHelper.CreateSelfSignedCertificateECDsa();

		// rsa_pkcs1_sha256
		certificate_rsa_pkcs1_sha256 = certificateHelper.CreateSelfSignedCertificateRSA(RSASignaturePadding.Pkcs1, HashAlgorithmName.SHA256);
	}

	#endregion

	/// <summary>
	/// Builds and configures a <see cref="WebApplication"/> that listens on the specified
	/// <paramref name="port"/> using the given <paramref name="sslProtocols"/>.
	/// </summary>
	/// <param name="sslProtocols">The TLS protocol versions to accept.</param>
	/// <param name="port">The TCP port on the loopback interface to listen on.</param>
	/// <returns>
	/// A configured <see cref="WebApplication"/> ready to be started.
	/// The application exposes a single GET endpoint at "/" that returns HTTP 200 OK.
	/// </returns>
	public WebApplication Build
	(
		SslProtocols sslProtocols = SslProtocols.None,
		Int32 port = 0
	)
	{
		// Create builder
		var builder = WebApplication.CreateBuilder();

		_ = builder.WebHost.ConfigureKestrel(ConfigureServerOptions);

		void ConfigureServerOptions(KestrelServerOptions serverOptions)
		{
			serverOptions.ConfigureHttpsDefaults(ConfigureHttpsDefaults);
			serverOptions.Listen(IPAddress.Loopback, port, ConfigureListenOptions);
		}

		void ConfigureHttpsDefaults(HttpsConnectionAdapterOptions configureOptions)
		{
			configureOptions.OnAuthenticate = OnAuthenticate;
		}

		void ConfigureListenOptions(ListenOptions listenOptions)
		{
			_ = listenOptions.UseHttps(ConfigureHttpsOptions);
		}

		void ConfigureHttpsOptions(HttpsConnectionAdapterOptions httpsOptions)
		{
			// Set TLS protocols
			httpsOptions.SslProtocols = sslProtocols;

			// Subscribe to TLS ClientHello callback to capture the offered cipher suites
			httpsOptions.TlsClientHelloBytesCallback = OnTlsClientHelloBytes;

			// Add function to select certificate
			httpsOptions.ServerCertificateSelector = SelectCertifiacte;
		}

		var result = builder.Build();

		// Add default endpoint for testing
		_ = result.MapGet("/", HandleDefaultEndpoint);

		return result;
	}

	#region Methods: Private

	/// <summary>
	/// Applies the restricted <see cref="tlsCipherSuites"/> policy to every new TLS connection.
	/// Called once per connection after the connection is established but before the handshake completes.
	/// </summary>
	private static void OnAuthenticate(ConnectionContext _, SslServerAuthenticationOptions sslOptions)
	{
		sslOptions.CipherSuitesPolicy = new CipherSuitesPolicy(tlsCipherSuites);
	}

	/// <summary>
	/// Parses the raw TLS ClientHello bytes to extract the client's supported certificate authentication algorithms
	/// and stores them in <see cref="ConnectionContext"/> for later use by <see cref="SelectCertifiacte"/>.
	/// If parsing fails, the error code is stored instead.
	/// </summary>
	/// <param name="connectionContext">The connection context for the incoming TLS connection.</param>
	/// <param name="data">The raw bytes of the TLS ClientHello message.</param>
	private static void OnTlsClientHelloBytes(ConnectionContext connectionContext, ReadOnlySequence<Byte> data)
	{
		var parseResult = TlsClientHelloParser.TryParse(data, out var clientHelloInfo);

		if (parseResult != TlsClientHelloParseErrorCode.None)
		{
			connectionContext.Items["CipherSuiteParseErrorCode"] = parseResult;
			return;
		}

		if (CertificateSelector.TrySelectAlogrithm(clientHelloInfo, out var authenticationAlgorithm))
		{
			connectionContext.Items[AuthenticationAlgorithmKey] = authenticationAlgorithm;
		}
	}

	/// <summary>Returns HTTP 200 OK for the root endpoint.</summary>
	private static IResult HandleDefaultEndpoint()
	{
		return Results.Ok();
	}

	/// <summary>
	/// Selects the appropriate server certificate based on the certificate authentication algorithms
	/// advertised by the client in its TLS ClientHello message.
	/// Prefers ECDsa over RSA when both are supported by the client.
	/// </summary>
	/// <param name="context">The connection context carrying the parsed certificate authentication algorithms.</param>
	/// <param name="_">The server name indication value (unused).</param>
	/// <returns>
	/// The <see cref="certificateECDsa"/> if the client supports ECDSA,
	/// the <see cref="certificate_rsa_pkcs1_sha256"/> if the client supports RSA,
	/// or <see langword="null"/> if the context is missing or parsing failed.
	/// </returns>
	private X509Certificate2? SelectCertifiacte(ConnectionContext? context, String? _)
	{
		if (context is null)
		{
			return null;
		}

		if (!context.Items.TryGetValue(AuthenticationAlgorithmKey, out var authenticationAlgorithmsObj))
		{
			return null;
		}

		if (authenticationAlgorithmsObj is not AuthenticationAlgorithm authenticationAlgorithms)
		{
			return null;
		}

		if (authenticationAlgorithms.HasFlag(AuthenticationAlgorithm.ECDSA))
		{
			return certificateECDsa;
		}

		if (authenticationAlgorithms.HasFlag(AuthenticationAlgorithm.RSA))
		{
			return certificate_rsa_pkcs1_sha256;
		}

		return null;
	}

	#endregion
}
