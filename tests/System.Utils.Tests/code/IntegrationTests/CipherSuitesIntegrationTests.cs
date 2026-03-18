// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Utils.IntegrationTests;

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Integration tests for TLS cipher suite certificate selection.
/// </summary>
[SupportedOSPlatform("linux")]
[TestClass]
public sealed class CipherSuitesIntegrationTests
{
	#region Fields

	private const String PublicKeyOidEcPublicKey = "1.2.840.10045.2.1";
	private const String PublicKeyOidRsa = "1.2.840.113549.1.1.1";

	#endregion

	public TestContext TestContext { get; set; }

	#region Test Methods: Success

	[TestMethod]
	public async Task Server_PresentRightCertificate_If_Tls12_RsaCipherSuite()
	{
		await TestServerPresentsRightCertificate(SslProtocols.Tls12, TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.RSA);
	}

	[TestMethod]
	public async Task Server_PresentRightCertificate_If_Tls12_EcdsaCipherSuite()
	{
		await TestServerPresentsRightCertificate(SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA);
	}

	[TestMethod]
	public async Task Server_PresentRightCertificate_If_Tls13_EcdsaCipherSuite()
	{
		await TestServerPresentsRightCertificate(SslProtocols.Tls13, TlsCipherSuite.TLS_AES_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA);
	}

	#endregion

	#region Helper Methods

	/// <summary>
	/// A helper method to connect to the server and retrieve the signature algorithm of the presented certificate.
	/// </summary>
	[Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5359:Do Not Disable Certificate Validation", Justification = "<Pending>")]
	private async Task<TlsSignatureAlgorithms> ConnectAndGetCertificateSignatureAlgorithm
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

		return GetCertificateSignatureAlgorithm(serverCertificate);
	}

	private static TlsSignatureAlgorithms GetCertificateSignatureAlgorithm(X509Certificate2 certificate)
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

	/// <summary>
	/// A helper method to verify that the server presents the right certificate based on the offered cipher suite.
	/// </summary>
	private async Task TestServerPresentsRightCertificate
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
		var actualSignatureAlgorithm = await ConnectAndGetCertificateSignatureAlgorithm(port, protocol, [cipherSuite], TestContext.CancellationToken);

		// Stop the server application.
		await serverApplication.StopAsync(TestContext.CancellationToken);

		Assert.AreEqual(expectedSignatureAlgorithm, actualSignatureAlgorithm);
	}

	#endregion
}
