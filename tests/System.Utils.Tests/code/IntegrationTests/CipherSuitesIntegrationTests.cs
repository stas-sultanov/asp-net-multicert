// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Utils.IntegrationTests;

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

[SupportedOSPlatform("linux")]
[TestClass]
public sealed class CipherSuitesIntegrationTests
{
	#region Fields

	public TestContext TestContext { get; set; }
	private const String PublicKeyOidRsa = "1.2.840.113549.1.1.1";
	private const String PublicKeyOidEcPublicKey = "1.2.840.10045.2.1";

	#endregion

	[TestMethod]
	public async Task Server_Success_WhenOfferRightCertificate_TLS12_RSA()
	{
		await ServerShouldPresentRightCertificate(SslProtocols.Tls12, TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.RSA);
	}

	[TestMethod]
	public async Task Server_Success_WhenOfferRightCertificate_TLS12_ECDSA()
	{
		await ServerShouldPresentRightCertificate(SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA);
	}

	[TestMethod]
	public async Task Server_Success_WhenOfferRightCertificate_TLS13_ECDSA()
	{
		await ServerShouldPresentRightCertificate(SslProtocols.Tls13, TlsCipherSuite.TLS_AES_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA);
	}

	public async Task ServerShouldPresentRightCertificate
	(
		SslProtocols protocol,
		TlsCipherSuite cipherSuite,
		TlsSignatureAlgorithms expectedSignatureAlgorithm
	)
	{
		var port = GetFreeTcpPort();

		// Create server.
		var server = new TestServer();

		// Build server application.
		using var serverApplication = server.Build(port, SslProtocols.Tls12 | SslProtocols.Tls13);

		// Start listening for incoming connections.
		await serverApplication.StartAsync(TestContext.CancellationToken);

		// Connect to the server with a client configured to use the expected cipher suite.
		var actualCertificateKeyType = await ConnectAndGetInfo(port, protocol, [cipherSuite], TestContext.CancellationToken);

		// Stop the server application.
		await serverApplication.StopAsync(TestContext.CancellationToken);

		Assert.AreEqual(expectedCertificateKeyType, actualCertificateKeyType);
	}

	[Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5359:Do Not Disable Certificate Validation", Justification = "<Pending>")]
	private async Task<TlsSignatureAlgorithms> ConnectAndGetInfo
	(
		Int32 port,
		SslProtocols protocol,
		IEnumerable<TlsCipherSuite> cipherSuites,
		CancellationToken cancellationToken = default
	)
	{
		using var tcpClient = new TcpClient();
		await tcpClient.ConnectAsync(IPAddress.Loopback, port, cancellationToken);

		using var sslStream = new SslStream(tcpClient.GetStream(), false);

		var cipherSuitesPolicy = new CipherSuitesPolicy(cipherSuites);

		var sslClientAuthenticationOptions = new SslClientAuthenticationOptions
		{
			TargetHost = "localhost",
			EnabledSslProtocols = protocol,
			CipherSuitesPolicy = cipherSuitesPolicy,
			CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
			RemoteCertificateValidationCallback = static (_, _, _, _) => true
		};

		try
		{
			await sslStream.AuthenticateAsClientAsync(sslClientAuthenticationOptions, cancellationToken);
		}
		catch (Exception ex)
		{
			TestContext.WriteLine($"TLS handshake failed: {ex}");
			throw;
		}

		if (sslStream.RemoteCertificate is null)
		{
			throw new InvalidOperationException("Server did not provide a certificate during TLS negotiation.");
		}

		var serverCertificate = new X509Certificate2(sslStream.RemoteCertificate);
		var serverCertificateKeyType = GetCertificateKeyType(serverCertificate);

		return serverCertificateKeyType;
	}

	private static TlsSignatureAlgorithms GetCertificateKeyType(X509Certificate2 certificate)
	{
		var publicKeyOid = certificate.PublicKey.Oid?.Value;

		return publicKeyOid switch
		{
			PublicKeyOidRsa => TlsSignatureAlgorithms.RSA,
			PublicKeyOidEcPublicKey => TlsSignatureAlgorithms.ECDSA,
			_ => TlsSignatureAlgorithms.None
		};
	}

	private static Int32 GetFreeTcpPort()
	{
		var listener = new TcpListener(IPAddress.Loopback, 0);
		listener.Start();
		var port = ((IPEndPoint) listener.LocalEndpoint).Port;
		listener.Stop();
		return port;
	}
}
