// Authored by Stas Sultanov
// Copyright © Stas Sultanov

using System.Net.Security;
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
			// TLS Web Server Authentication
			new("1.3.6.1.5.5.7.3.1")
		], false);

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
	/// <param name="hashAlgorithm">The hash algorithm to use when signing the certificate.</param>
	/// <returns>A self-signed X509Certificate2 instance.</returns>
	public X509Certificate2 CreateSelfSignedCertificateECDsa
	(
		ECCurve curve,
		HashAlgorithmName hashAlgorithm
	)
	{
		// Create instance of key algorithm
		using var key = ECDsa.Create(curve);

		var request = new CertificateRequest(SubjectName, key, hashAlgorithm);

		var keyUsageExtension = new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false);

		request.CertificateExtensions.Add(keyUsageExtension);

		return CreateSelfSignedCertificate(request);
	}

	/// <summary>
	/// Creates a self-signed certificate using the RSA algorithm with the specified key size.
	/// </summary>
	/// <param name="keySizeInBits">The size of the RSA key in bits.</param>
	/// <param name="hashAlgorithm">The hash algorithm to use when signing the certificate.</param>
	/// <param name="padding">The RSA signature padding mode to use when signing the certificate.</param>
	/// <returns>A self-signed X509Certificate2 instance.</returns>
	public X509Certificate2 CreateSelfSignedCertificateRSA
	(
		RSASignaturePadding padding,
		HashAlgorithmName hashAlgorithm,
		Int32 keySizeInBits = 2048
	)
	{
		// Create instance of key algorithm
		using var key = RSA.Create(keySizeInBits);

		// RSA signatures require a padding scheme.
		// RSASignaturePadding.Pkcs1 implements PKCS#1 v1.5 signature encoding
		var request = new CertificateRequest(SubjectName, key, hashAlgorithm, padding);

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

	/// <summary>
	/// Gets the TLS signature scheme (RFC 8446) from an X509Certificate2.
	/// </summary>
	/// <param name="certificate">The certificate to extract information from.</param>
	/// <returns>A tuple containing the TlsSignatureScheme, key algorithm, hash algorithm, padding (if RSA), and ECC curve name (if ECDSA).</returns>
	public static TlsSignatureScheme GetSignatureScheme(X509Certificate2 certificate)
	{
		if (certificate == null)
		{
			throw new ArgumentNullException(nameof(certificate));
		}

		// OIDs
		const String oidRsaEncryption = "1.2.840.113549.1.1.1";
		const String oidEcPublicKey = "1.2.840.10045.2.1";
		var pubKeyOid = certificate.PublicKey.Oid.Value;
		var sigAlgOid = certificate.SignatureAlgorithm.Value;

		if (pubKeyOid == oidRsaEncryption)
		{
			// RSA
			return sigAlgOid switch
			{
				// sha1RSA
				"1.2.840.113549.1.1.5" => TlsSignatureScheme.rsa_pkcs1_sha1,
				// sha256RSA
				"1.2.840.113549.1.1.11" => TlsSignatureScheme.rsa_pkcs1_sha256,
				// sha384RSA
				"1.2.840.113549.1.1.12" => TlsSignatureScheme.rsa_pkcs1_sha384,
				// sha512RSA
				"1.2.840.113549.1.1.13" => TlsSignatureScheme.rsa_pkcs1_sha512,
				_ => TlsSignatureScheme.None,
			};
		}
		else if (pubKeyOid == oidEcPublicKey)
		{
			using var ecdsa = certificate.GetECDsaPublicKey();

			if (ecdsa == null)
			{
				return TlsSignatureScheme.None;
			}

			var curve = ecdsa.ExportParameters(false).Curve;
			var eccCurveName = curve.Oid.FriendlyName ?? curve.Oid.Value;

			// Map curve+hash to TlsSignatureScheme
			switch (sigAlgOid)
			{
				case "1.2.840.10045.4.3.2": // ecdsa-with-SHA256
					if (eccCurveName != null && eccCurveName.Contains("384"))
					{
						return TlsSignatureScheme.ecdsa_secp384r1_sha384;
					}
					else if (eccCurveName != null && eccCurveName.Contains("521"))
					{
						return TlsSignatureScheme.ecdsa_secp521r1_sha512;
					}
					else
					{
						return TlsSignatureScheme.ecdsa_secp256r1_sha256;
					}

				case "1.2.840.10045.4.3.3": // ecdsa-with-SHA384
					return TlsSignatureScheme.ecdsa_secp384r1_sha384;
				case "1.2.840.10045.4.3.4": // ecdsa-with-SHA512
					return TlsSignatureScheme.ecdsa_secp521r1_sha512;
				case "1.2.840.10045.4.1": // ecdsa-with-SHA1
					return TlsSignatureScheme.ecdsa_sha1;
			}
		}

		return TlsSignatureScheme.None;
	}
}
