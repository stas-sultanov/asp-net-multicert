// Authored by Stas Sultanov
// Copyright © Stas Sultanov

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Helper class for creating self-signed certificates for testing purposes.
/// </summary>
internal sealed class CertificateHelper
{
	#region Properties

	/// <summary>
	/// Basic Constraints (BC).
	/// </summary>
	public X509BasicConstraintsExtension ExtensionBasicConstraints { get; init; } = new(false, false, 0, false);

	/// <summary>
	/// Extended Key Usage (EKU).
	/// </summary>
	public X509EnhancedKeyUsageExtension ExtensionEnhancedKeyUsage { get; init; } = new X509EnhancedKeyUsageExtension(
		[
			// TLS Web Server Authentication (1.3.6.1.5.5.7.3.1)
			new("1.3.6.1.5.5.7.3.1")
		], false);

	/// <summary>
	/// The hash algorithm to use when signing the certificate or certificate request.
	/// </summary>
	public HashAlgorithmName HashAlgorithmName { get; init; } = HashAlgorithmName.SHA256;

	/// <summary>
	/// The date and time when this certificate is no longer considered valid.
	/// </summary>
	public DateTimeOffset NotAfter { get; init; } = DateTimeOffset.UtcNow.AddMinutes(1);

	/// <summary>
	/// The oldest date and time when this certificate is considered valid.
	/// </summary>
	public DateTimeOffset NotBefore { get; init; } = DateTimeOffset.UtcNow.AddMinutes(-1);

	/// <summary>
	/// The string representation of the subject name for the certificate or certificate request.
	/// </summary>
	public String SubjectName { get; init; } = "CN=localhost";

	#endregion

	#region Methods: Public

	/// <summary>
	/// Creates a self-signed certificate using the ECDsa algorithm with the specified curve.
	/// </summary>
	/// <param name="curve">The elliptic curve to use for the ECDsa algorithm.</param>
	/// <returns>A self-signed X509Certificate2 instance.</returns>
	public X509Certificate2 CreateSelfSignedCertificateECDsa
	(
		ECCurve? curve = null
	)
	{
		curve ??= ECCurve.NamedCurves.nistP256;

		// Create instance of key algorithm
		using var key = ECDsa.Create(curve.Value);

		var request = new CertificateRequest(SubjectName, key, HashAlgorithmName);

		var keyUsageExtension = new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false);

		request.CertificateExtensions.Add(keyUsageExtension);

		return CreateSelfSignedCertificate(request);
	}

	/// <summary>
	/// Creates a self-signed certificate using the RSA algorithm with the specified key size.
	/// </summary>
	/// <param name="keySizeInBits">The size of the RSA key in bits.</param>
	/// <returns>A self-signed X509Certificate2 instance.</returns>
	public X509Certificate2 CreateSelfSignedCertificateRSA
	(
		Int32 keySizeInBits = 2048
	)
	{
		// Create instance of key algorithm
		using var key = RSA.Create(keySizeInBits);

		// RSA signatures require a padding scheme.
		// RSASignaturePadding.Pkcs1 implements PKCS#1 v1.5 signature encoding
		var request = new CertificateRequest(SubjectName, key, HashAlgorithmName, RSASignaturePadding.Pkcs1);

		var keyUsageExtension = new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false);

		request.CertificateExtensions.Add(keyUsageExtension);

		return CreateSelfSignedCertificate(request);
	}

	#endregion

	#region Methods: Private

	private X509Certificate2 CreateSelfSignedCertificate
	(
		CertificateRequest request
	)
	{
		var subjectKeyIdentifierExtension = new X509SubjectKeyIdentifierExtension(request.PublicKey, false);

		request.CertificateExtensions.Add(ExtensionBasicConstraints);
		request.CertificateExtensions.Add(ExtensionEnhancedKeyUsage);
		request.CertificateExtensions.Add(subjectKeyIdentifierExtension);

		return request.CreateSelfSigned(NotBefore, NotAfter);
	}

	#endregion
}
