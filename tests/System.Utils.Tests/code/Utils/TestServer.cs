// Authored by Stas Sultanov
// Copyright © Stas Sultanov

using System.Buffers;
using System.Collections.Frozen;
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
/// based on the client capabilities advertised in the TLS ClientHello message.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class TestServer
{
	#region Fields

	private const String SignatureSchemeKey = "SignatureScheme";

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

	/// <summary>
	/// A store of server certificates keyed by the signature scheme.
	/// </summary>
	private readonly FrozenDictionary<TlsSignatureScheme, X509Certificate2> certificateStore;

	#endregion

	#region Constructors

	/// <summary>Initializes a new <see cref="TestServer"/>.</summary>
	public TestServer()
	{
		// create self-signed certificates for testing
		var certificateHelper = new CertificateHelper();

		var certificate_ecdsa_secp256r1_sha256 = certificateHelper.CreateSelfSignedCertificateECDsa(ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256);
		var certificate_rsa_pkcs1_sha256 = certificateHelper.CreateSelfSignedCertificateRSA(RSASignaturePadding.Pkcs1, HashAlgorithmName.SHA256);
		var certificate_rsa_pkcs1_sha512 = certificateHelper.CreateSelfSignedCertificateRSA(RSASignaturePadding.Pkcs1, HashAlgorithmName.SHA512);

		// Order of keys defines behaviour of certificate selection when client supports multiple signature schemes.
		certificateStore = new OrderedDictionary<TlsSignatureScheme, X509Certificate2>
		{
			{ TlsSignatureScheme.rsa_pkcs1_sha256, certificate_rsa_pkcs1_sha256 },
			{ TlsSignatureScheme.rsa_pkcs1_sha512, certificate_rsa_pkcs1_sha512 },
			{ TlsSignatureScheme.ecdsa_secp256r1_sha256, certificate_ecdsa_secp256r1_sha256 }
		}.ToFrozenDictionary();
	}

	#endregion

	#region Methods: Public

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

	#endregion

	#region Methods: Private

	private void OnTlsClientHelloBytes
	(
		ConnectionContext connectionContext,
		ReadOnlySequence<Byte> data
	)
	{
		var parseResult = TlsClientHelloParser.TryParse(data, out var clientHelloInfo);

		if (parseResult != TlsClientHelloParseErrorCode.None)
		{
			connectionContext.Items["CipherSuiteParseErrorCode"] = parseResult;
			return;
		}

		if (TrySelectSignatureScheme(clientHelloInfo, out var authenticationAlgorithm))
		{
			connectionContext.Items[SignatureSchemeKey] = authenticationAlgorithm;
		}
	}

	private X509Certificate2? SelectCertifiacte(ConnectionContext? context, String? name)
	{
		if (context is null)
		{
			return null;
		}

		if (!context.Items.TryGetValue(SignatureSchemeKey, out var signatureSchemeObj))
		{
			return null;
		}

		if (signatureSchemeObj is not TlsSignatureScheme signatureScheme)
		{
			return null;
		}

		_ = certificateStore.TryGetValue(signatureScheme, out var certificate);

		return certificate;
	}

	private static void OnAuthenticate(ConnectionContext _, SslServerAuthenticationOptions sslOptions)
	{
		sslOptions.CipherSuitesPolicy = new CipherSuitesPolicy(tlsCipherSuites);
	}

	/// <summary>Returns HTTP 200 OK for the root endpoint.</summary>
	private static IResult HandleDefaultEndpoint()
	{
		return Results.Ok();
	}

	/// <summary>
	/// Tries to select a TLS signature scheme supported by both the client and the server.
	/// </summary>
	/// <param name="clientHelloInfo">The client hello information.</param>
	/// <param name="signatureScheme">The selected TLS signature scheme.</param>
	/// <returns><c>true</c> if a compatible signature scheme is found; otherwise, <c>false</c>.</returns>
	private Boolean TrySelectSignatureScheme
	(
		in TlsClientHelloInfo clientHelloInfo,
		out TlsSignatureScheme signatureScheme
	)
	{
		// TLS 1.3: Get signature schemes from signature_algorithms_cert extension
		if (clientHelloInfo.SignatureAlgorithmsCertCount != 0)
		{
			// Allocate memory from the stack
			Span<TlsSignatureScheme> clientSignatureSchemes = stackalloc TlsSignatureScheme[clientHelloInfo.SignatureAlgorithmsCertCount];

			if (clientHelloInfo.TryCopySignatureAlgorithmsCert(clientSignatureSchemes))
			{
				// Walk through certificates available on the server
				foreach (var serverSignatureScheme in certificateStore.Keys)
				{
					if (clientSignatureSchemes.Contains(serverSignatureScheme))
					{
						signatureScheme = serverSignatureScheme;
						return true;
					}
				}
			}
		}

		// TLS 1.3 and 1.2: Get algorithms from signature_algorithms extension
		if (clientHelloInfo.SignatureAlgorithmsCount != 0)
		{
			// Allocate memory from the stack
			Span<TlsSignatureScheme> clientSignatureSchemes = stackalloc TlsSignatureScheme[clientHelloInfo.SignatureAlgorithmsCount];

			if (clientHelloInfo.TryCopySignatureAlgorithms(clientSignatureSchemes))
			{
				// Walk through certificates available on the server
				foreach (var serverSignatureScheme in certificateStore.Keys)
				{
					if (clientSignatureSchemes.Contains(serverSignatureScheme))
					{
						// Here maybe additional logic in case of TLS 1.2
						// to check if the signature scheme is compatible with the negotiated cipher suite
						// but for simplicity we assume it is
						signatureScheme = serverSignatureScheme;
						return true;
					}
				}
			}
		}

		signatureScheme = default;
		return false;
	}

	#endregion
}
