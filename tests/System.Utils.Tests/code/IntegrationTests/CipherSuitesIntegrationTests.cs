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
	public TestContext TestContext { get; set; }

	#region Test Methods: Success

	[TestMethod]
	public async Task Server_Present_RSA_When_Client_Offers_Tls12_With_RSA()
	{
		const SslProtocols protocol = SslProtocols.Tls12;
		var cipherSuites = new TlsCipherSuite[]
		{
			TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384
		};
		var expectedSignatureScheme = TlsSignatureScheme.rsa_pkcs1_sha256;

		var actualSignatureScheme = await RunServerAndConnect(protocol, cipherSuites, true, true, TestContext.CancellationToken);

		Assert.AreEqual(expectedSignatureScheme, actualSignatureScheme, $"Server Certificate Signature Scheme is invalid.");
	}

	[TestMethod]
	public async Task Server_Present_ECDSA_When_Client_Offers_Tls12_Without_RSA()
	{
		const SslProtocols protocol = SslProtocols.Tls12;
		var cipherSuites = new TlsCipherSuite[]
		{
			TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		};
		var expectedSignatureScheme = TlsSignatureScheme.ecdsa_secp256r1_sha256;

		var actualSignatureScheme = await RunServerAndConnect(protocol, cipherSuites, false, true, TestContext.CancellationToken);

		Assert.AreEqual(expectedSignatureScheme, actualSignatureScheme, $"Server Certificate Signature Scheme is invalid.");
	}

	[TestMethod]
	public async Task Server_Present_ECDSA_When_Client_Offers_Tls13_Without_RSA()
	{
		const SslProtocols protocol = SslProtocols.Tls13;
		var cipherSuites = new TlsCipherSuite[]
		{
			TlsCipherSuite.TLS_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_AES_256_GCM_SHA384
		};
		var expectedSignatureScheme = TlsSignatureScheme.ecdsa_secp256r1_sha256;

		var actualSignatureScheme = await RunServerAndConnect(protocol, cipherSuites, false, true, TestContext.CancellationToken);

		Assert.AreEqual(expectedSignatureScheme, actualSignatureScheme, $"Server Certificate Signature Scheme is invalid.");
	}

	#endregion

	#region Helper Methods

	/// <summary>
	/// A helper method to verify that the server presents the right certificate based on the offered cipher suite.
	/// </summary>
	private async Task<TlsSignatureScheme> RunServerAndConnect
	(
		SslProtocols protocol,
		IEnumerable<TlsCipherSuite> cipherSuites,
		Boolean clientUse_rsa_pkcs1,
		Boolean clientUse_rsa_pss,
		CancellationToken cancellationToken = default
	)
	{
		// Create server.
		var server = new TestServer();

		// Build server application.
		using var serverApplication = server.Build();

		// Start listening for incoming connections.
		await serverApplication.StartAsync(cancellationToken);

		// Retrieve the port the server is actually bound to (port 0 lets the OS assign one).
		var port = new Uri(serverApplication.Urls.First()).Port;

		// Connect to the server with a client configured to use the expected cipher suite.
		var result = await ConnectAndGetServerCertificate(port, protocol, cipherSuites, clientUse_rsa_pkcs1, clientUse_rsa_pss, cancellationToken);

		// Stop the server application.
		await serverApplication.StopAsync(cancellationToken);

		return result;
	}

	/// <summary>
	/// A helper method to connect to the server and retrieve the certificate presented by the server.
	/// </summary>
	[Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5359:Do Not Disable Certificate Validation", Justification = "<Pending>")]
	private async Task<TlsSignatureScheme> ConnectAndGetServerCertificate
	(
		Int32 port,
		SslProtocols protocol,
		IEnumerable<TlsCipherSuite> cipherSuites,
		Boolean use_rsa_pkcs1,
		Boolean use_rsa_pss,
		CancellationToken cancellationToken = default
	)
	{
		using var tcpClient = new TcpClient();
		await tcpClient.ConnectAsync(IPAddress.Loopback, port, cancellationToken);

		using var sslStream = new SslStream(tcpClient.GetStream(), false);

		var cipherSuitesPolicy = new CipherSuitesPolicy(cipherSuites);

		var sslClientAuthenticationOptions = new SslClientAuthenticationOptions
		{
			AllowRsaPkcs1Padding = use_rsa_pkcs1,
			AllowRsaPssPadding = use_rsa_pss,
			CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
			CipherSuitesPolicy = cipherSuitesPolicy,
			EnabledSslProtocols = protocol,
			RemoteCertificateValidationCallback = static (_, _, _, _) => true,
			TargetHost = "localhost",
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

		return CertificateHelper.GetSignatureScheme(serverCertificate);
	}

	#endregion
}
