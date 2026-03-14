using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
// Authored by Stas Sultanov
// Copyright © Stas Sultanov

internal sealed class CertificateHelper
{
	public HashAlgorithmName HashAlgorithmName { get; init; } = HashAlgorithmName.SHA256;

	/// <summary>
	/// Subject Name Identifier.
	/// </summary>
	public String SubjectName { get; init; } = "CN=localhost";

	public X509BasicConstraintsExtension ExtensionBasicConstraints { get; init; } = new(false, false, 0, false);

	/// <summary>
	/// Extended Key Usage (EKU): TLS Web Server Authentication (1.3.6.1.5.5.7.3.1). Ensures browsers/clients trust it for TLS.
	/// </summary>
	public X509EnhancedKeyUsageExtension ExtensionEnhancedKeyUsage { get; init; } = new X509EnhancedKeyUsageExtension(
		[
			new("1.3.6.1.5.5.7.3.1")
		], false);

	public DateTimeOffset NotAfter { get; init; } = DateTimeOffset.UtcNow.AddDays(1);
	public DateTimeOffset NotBefore { get; init; } = DateTimeOffset.UtcNow.AddDays(-1);

	private X509Certificate2 CreateEcdsaSelfSignedCertificate
	(
		ECCurve curve // = ECCurve.NamedCurves.nistP256
	)
	{
		// Create instance of aglorithm
		using var ecdsa = ECDsa.Create(curve);

		var request = new CertificateRequest(SubjectName, ecdsa, HashAlgorithmName);

		request.CertificateExtensions.Add(ExtensionBasicConstraints);
		request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
		request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
		request.CertificateExtensions.Add(ExtensionEnhancedKeyUsage);

		return request.CreateSelfSigned(NotBefore, NotAfter);
	}

	private X509Certificate2 CreateRsaSelfSignedCertificate
	(
		Int32 keySizeInBits = 2048
	)
	{
		// Create instance of aglorithm
		using var rsa = RSA.Create(keySizeInBits);

		var request = new CertificateRequest(SubjectName, rsa, HashAlgorithmName, RSASignaturePadding.Pkcs1);

		request.CertificateExtensions.Add(ExtensionBasicConstraints);
		request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
		request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
		request.CertificateExtensions.Add(ExtensionEnhancedKeyUsage);

		return request.CreateSelfSigned(NotBefore, NotAfter);
	}
}
