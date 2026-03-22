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
	private const String PublicKeyOidEd25519 = "1.3.101.112";
	private const String PublicKeyOidEd448 = "1.3.101.113";
	private const String PublicKeyOidRsa = "1.2.840.113549.1.1.1";

	#endregion

	public TestContext TestContext { get; set; }

	#region Test Methods: Success

	[TestMethod]
	public async Task Server_Present_RSA_When_Client_Offers_Tls12_CipherSuite_RSA()
	{
		const TlsCertificateAuthenticationAlgorithms expectedAuthenticationAlgorithm = TlsCertificateAuthenticationAlgorithms.RSA;
		const SslProtocols protocol = SslProtocols.Tls12;
		var cipherSuites = new TlsCipherSuite[]
		{
			TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256
		};

		await TestServerPresentsRightCertificate(expectedAuthenticationAlgorithm, protocol, cipherSuites);
	}

	[TestMethod]
	public async Task Server_Present_RSA_When_Client_Offers_Tls12_CipherSuite_RSAMultiple()
	{
		const TlsCertificateAuthenticationAlgorithms expectedAuthenticationAlgorithm = TlsCertificateAuthenticationAlgorithms.RSA;
		const SslProtocols protocol = SslProtocols.Tls12;
		var cipherSuites = new TlsCipherSuite[]
		{
			TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
			TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
			TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
		};

		await TestServerPresentsRightCertificate(expectedAuthenticationAlgorithm, protocol, cipherSuites);
	}

	[TestMethod]
	public async Task Server_Present_ECDSA_When_Client_Offers_Tls12_CipherSuite_ECDSA()
	{
		const TlsCertificateAuthenticationAlgorithms expectedAuthenticationAlgorithm = TlsCertificateAuthenticationAlgorithms.ECDSA;
		const SslProtocols protocol = SslProtocols.Tls12;
		var cipherSuites = new TlsCipherSuite[]
		{
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		};

		await TestServerPresentsRightCertificate(expectedAuthenticationAlgorithm, protocol, cipherSuites);
	}

	[TestMethod]
	public async Task Server_Present_ECDSA_When_Client_Offers_Tls12_CipherSuite_ECDSAMultiple()
	{
		const TlsCertificateAuthenticationAlgorithms expectedAuthenticationAlgorithm = TlsCertificateAuthenticationAlgorithms.ECDSA;
		const SslProtocols protocol = SslProtocols.Tls12;
		var cipherSuites = new TlsCipherSuite[]
		{
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384
		};

		await TestServerPresentsRightCertificate(expectedAuthenticationAlgorithm, protocol, cipherSuites);
	}

	[TestMethod]
	public async Task Server_Present_ECDSA_When_Client_Offers_Tls12_CipherSuite_Multiple()
	{
		const TlsCertificateAuthenticationAlgorithms expectedAuthenticationAlgorithm = TlsCertificateAuthenticationAlgorithms.ECDSA;
		const SslProtocols protocol = SslProtocols.Tls12;
		var cipherSuites = new TlsCipherSuite[]
		{
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384
		};

		await TestServerPresentsRightCertificate(expectedAuthenticationAlgorithm, protocol, cipherSuites);
	}

	[TestMethod]
	public async Task Server_Present_ECDSA_When_Client_Offers_Tls13_CipherSuite_ECDSA()
	{
		const TlsCertificateAuthenticationAlgorithms expectedAuthenticationAlgorithm = TlsCertificateAuthenticationAlgorithms.ECDSA;
		const SslProtocols protocol = SslProtocols.Tls13;
		var cipherSuites = new TlsCipherSuite[]
		{
			TlsCipherSuite.TLS_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_AES_256_GCM_SHA384
		};

		// On the time of writing this test,
		// .NET does not support configuring Signature Algorithms for TLS 1.3
		// so client will send signature_algorithms extension which are configured within the OS.
		// And I am too laizy to write code for this purpose.
		await TestServerPresentsRightCertificate(expectedAuthenticationAlgorithm, protocol, cipherSuites);
	}

	#endregion

	#region Helper Methods

	/// <summary>
	/// A helper method to verify that the server presents the right certificate based on the offered cipher suite.
	/// </summary>
	private async Task TestServerPresentsRightCertificate
	(
		TlsCertificateAuthenticationAlgorithms expectedAuthenticationAlgorithm,
		SslProtocols protocol,
		IEnumerable<TlsCipherSuite> cipherSuites
	)
	{
		// Create server.
		var server = new TestServer();

		// Build server application.
		using var serverApplication = server.Build();

		// Start listening for incoming connections.
		await serverApplication.StartAsync(TestContext.CancellationToken);

		// Retrieve the port the server is actually bound to (port 0 lets the OS assign one).
		var port = new Uri(serverApplication.Urls.First()).Port;

		// Connect to the server with a client configured to use the expected cipher suite.
		var actualAuthenticationAlgorithm = await ConnectAndGetCertificateAuthenticationAlgorithm(port, protocol, cipherSuites, TestContext.CancellationToken);

		// Stop the server application.
		await serverApplication.StopAsync(TestContext.CancellationToken);

		Assert.AreEqual(expectedAuthenticationAlgorithm, actualAuthenticationAlgorithm);
	}

	/// <summary>
	/// A helper method to connect to the server and retrieve the certificate authentication algorithm of the presented certificate.
	/// </summary>
	[Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5359:Do Not Disable Certificate Validation", Justification = "<Pending>")]
	private async Task<TlsCertificateAuthenticationAlgorithms> ConnectAndGetCertificateAuthenticationAlgorithm
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

		return GetCertificateAuthenticationAlgorithm(serverCertificate);
	}

	private static TlsCertificateAuthenticationAlgorithms GetCertificateAuthenticationAlgorithm(X509Certificate2 certificate)
	{
		var publicKeyOid = certificate.PublicKey.Oid?.Value;

		return publicKeyOid switch
		{
			PublicKeyOidRsa => TlsCertificateAuthenticationAlgorithms.RSA,
			PublicKeyOidEcPublicKey => TlsCertificateAuthenticationAlgorithms.ECDSA,
			PublicKeyOidEd25519 => TlsCertificateAuthenticationAlgorithms.EdDSA,
			PublicKeyOidEd448 => TlsCertificateAuthenticationAlgorithms.EdDSA,
			_ => TlsCertificateAuthenticationAlgorithms.None
		};
	}

	#endregion
}
