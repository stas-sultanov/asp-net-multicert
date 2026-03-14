// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Utils.IntegrationTests;

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

[SupportedOSPlatform("linux")]
[TestClass]
public sealed class CipherSuitesIntegrationTests
{
	[TestMethod]
	public async Task Tls12_ClientHello_ShouldIncludeConfiguredCipherSuite()
	{
		var expectedSuite = TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
		var allowedSuites = new[]
		{
			TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384
		};
		var resultSignal = new TaskCompletionSource<(CipherSuitesParseErrorCode ParseResult, IReadOnlyCollection<TlsCipherSuite> Suites)>(TaskCreationOptions.RunContinuationsAsynchronously);
		var port = GetFreeTcpPort();

		await using var app = await StartServerAsync(port, SslProtocols.Tls12, resultSignal, allowedSuites);

		await ConnectWithTlsAsync(
			port,
			SslProtocols.Tls12,
			new CipherSuitesPolicy([expectedSuite])
		);

		var (parseResult, suites) = await resultSignal.Task.WaitAsync(TimeSpan.FromSeconds(10));

		Assert.AreEqual(CipherSuitesParseErrorCode.None, parseResult);
		Assert.Contains(expectedSuite, suites);
	}

	[TestMethod]
	public async Task Tls13_ClientHello_ShouldIncludeConfiguredCipherSuite()
	{
		var expectedSuite = TlsCipherSuite.TLS_AES_128_GCM_SHA256;
		var allowedSuites = new[]
		{
			TlsCipherSuite.TLS_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_AES_256_GCM_SHA384
		};
		var resultSignal = new TaskCompletionSource<(CipherSuitesParseErrorCode ParseResult, IReadOnlyCollection<TlsCipherSuite> Suites)>(TaskCreationOptions.RunContinuationsAsynchronously);
		var port = GetFreeTcpPort();

		await using var app = await StartServerAsync(port, SslProtocols.Tls13, resultSignal, allowedSuites);

		await ConnectWithTlsAsync(
			port,
			SslProtocols.Tls13,
			new CipherSuitesPolicy([expectedSuite])
		);

		var (parseResult, suites) = await resultSignal.Task.WaitAsync(TimeSpan.FromSeconds(10));

		Assert.AreEqual(CipherSuitesParseErrorCode.None, parseResult);
		Assert.Contains(expectedSuite, suites);
	}

	private static async Task<WebApplication> StartServerAsync
	(
		Int32 port,
		SslProtocols sslProtocols,
		TaskCompletionSource<(CipherSuitesParseErrorCode ParseResult, IReadOnlyCollection<TlsCipherSuite> Suites)> resultSignal,
		TlsCipherSuite[] allowedSuites
	)
	{

		var certificates = new List<X509Certificate2>(allowedSuites.Length);

		foreach (var suite in allowedSuites)
		{
			certificates.Add(CreateSelfSignedCertificate(suite));
		}

		var certificate = certificates[0];

		// Crete builder
		var builder = WebApplication.CreateBuilder();

		_ = builder.WebHost.ConfigureKestrel
		(
			options =>
			{
				/*
				options.ConfigureHttpsDefaults(o =>
				{
					o.OnAuthenticate = (context, sslOptions) =>
					{
						sslOptions.CipherSuitesPolicy = new CipherSuitesPolicy(allowedSuites);
					};
				});
				*/

				options.Listen(IPAddress.Loopback, port, listenOptions =>
				{
					_ = listenOptions.UseHttps(httpsOptions =>
					{
						// Set TLS protocols
						httpsOptions.SslProtocols = sslProtocols;

						// Subscribe to TLS ClientHello callback to capture the offered cipher suites
						httpsOptions.TlsClientHelloBytesCallback = (connectionContext, data) =>
						{
							var cipherSuitParseResult = CipherSuitesParser.TryParse(data, out var cipherSuites);

							if (cipherSuitParseResult == CipherSuitesParseErrorCode.None)
							{
								connectionContext.Items["CipherSuites"] = cipherSuites;
							}
							else
							{
								connectionContext.Items["CipherSuiteParseErrorCode"] = cipherSuitParseResult;
							}
						};

						httpsOptions.ServerCertificateSelector = (connectionContext, name) => certificate;
					});
				});
			}
		);

		var app = builder.Build();
		_ = app.MapGet("/", () => Results.Ok());
		await app.StartAsync();
		return app;
	}

	private static async Task ConnectWithTlsAsync(Int32 port, SslProtocols protocol, CipherSuitesPolicy cipherSuitesPolicy)
	{
		using var tcpClient = new TcpClient();
		await tcpClient.ConnectAsync(IPAddress.Loopback, port);

		using var sslStream = new SslStream(tcpClient.GetStream(), false);

		await sslStream.AuthenticateAsClientAsync(
			new SslClientAuthenticationOptions
			{
				TargetHost = "localhost",
				EnabledSslProtocols = protocol,
				CipherSuitesPolicy = cipherSuitesPolicy,
				CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
#pragma warning disable CA5359
				RemoteCertificateValidationCallback = static (_, _, _, _) => true
#pragma warning restore CA5359
			}
		);
	}

	private static Int32 GetFreeTcpPort()
	{
		var listener = new TcpListener(IPAddress.Loopback, 0);
		listener.Start();
		var port = ((IPEndPoint) listener.LocalEndpoint).Port;
		listener.Stop();
		return port;
	}

	private static X509Certificate2 CreateSelfSignedCertificate(TlsCipherSuite cipherSuite)
	{
		// Cipher suites are not embedded in certificates. We derive certificate key algorithm
		// from suite name to ensure the generated cert is compatible with that suite.
		var suiteName = cipherSuite.ToString();
		var requiresEcdsa = suiteName.Contains("ECDSA", StringComparison.Ordinal);

		return requiresEcdsa
			? CreateEcdsaSelfSignedCertificate()
			: CreateRsaSelfSignedCertificate();
	}

	private static X509Certificate2 CreateEcdsaSelfSignedCertificate()
	{
		using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		var request = new CertificateRequest("CN=localhost", ecdsa, HashAlgorithmName.SHA256);
		request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
		request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
		request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

		var eku = new OidCollection
		{
			new("1.3.6.1.5.5.7.3.1")
		};
		request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));

		return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
	}

	private static X509Certificate2 CreateRsaSelfSignedCertificate()
	{
		using var rsa = RSA.Create(2048);
		var request = new CertificateRequest(
			"CN=localhost",
			rsa,
			HashAlgorithmName.SHA256,
			RSASignaturePadding.Pkcs1
		);

		request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
		request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
		request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

		var eku = new OidCollection
		{
			new("1.3.6.1.5.5.7.3.1")
		};
		request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));

		return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
	}
}
