// Authored by Stas Sultanov
// Copyright © Stas Sultanov

using System.Buffers;
using System.Net;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

[SupportedOSPlatform("linux")]
internal sealed class TestServer
{
	#region Fields

	private const String ConnectionContextItemsKeySignatureAlgorithmsName = "SignatureAlgorithms";

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

	private readonly X509Certificate2 certificateECDsa;

	private readonly X509Certificate2 certificateRSA;

	public TestServer()
	{
		var certificateHelper = new CertificateHelper();

		certificateECDsa = certificateHelper.CreateSelfSignedCertificateECDsa();

		certificateRSA = certificateHelper.CreateSelfSignedCertificateRSA();
	}

	#endregion

	public WebApplication Build
	(
		Int32 port,
		SslProtocols sslProtocols
	)
	{
		// Crete builder
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

	private static void OnAuthenticate(ConnectionContext _, SslServerAuthenticationOptions sslOptions)
	{
		sslOptions.CipherSuitesPolicy = new CipherSuitesPolicy(tlsCipherSuites);
	}

	private static void OnTlsClientHelloBytes(ConnectionContext connectionContext, ReadOnlySequence<Byte> data)
	{
		var cipherSuitParseResult = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		if (cipherSuitParseResult == ClientHelloParseErrorCode.None)
		{
			connectionContext.Items[ConnectionContextItemsKeySignatureAlgorithmsName] = signatureAlgorithms;
		}
		else
		{
			connectionContext.Items["CipherSuiteParseErrorCode"] = cipherSuitParseResult;
		}
	}

	private static IResult HandleDefaultEndpoint()
	{
		return Results.Ok();
	}

	private X509Certificate2? SelectCertifiacte(ConnectionContext? context, String? _)
	{
		if (context is null)
		{
			return null;
		}

		if (!context.Items.TryGetValue(ConnectionContextItemsKeySignatureAlgorithmsName, out var signatureAlgorithmsObj))
		{
			return null;
		}

		if (signatureAlgorithmsObj is not TlsSignatureAlgorithms signatureAlgorithms)
		{
			return null;
		}

		if ((signatureAlgorithms & TlsSignatureAlgorithms.ECDSA) != 0)
		{
			return certificateECDsa;
		}

		if ((signatureAlgorithms & TlsSignatureAlgorithms.RSA) != 0)
		{
			return certificateRSA;
		}

		return null;
	}
}
