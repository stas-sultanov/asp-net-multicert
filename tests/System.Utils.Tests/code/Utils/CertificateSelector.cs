// Authored by Stas Sultanov
// Copyright © Stas Sultanov

using System.Collections.Frozen;
using System.Net.Security;

internal static class CertificateSelector
{

	/// <summary>
	/// TLS 1.2 lookup table to infer certificate authentication algorithms from the cipher suites advertised in ClientHello.
	/// </summary>
	private static readonly FrozenDictionary<TlsCipherSuite, AuthenticationAlgorithm> tls12AuthSALookup
		= new Dictionary<TlsCipherSuite, AuthenticationAlgorithm>
	{
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_DES_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_DES_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA, AuthenticationAlgorithm.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_CCM, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_CCM_8, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_CCM, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_CCM_8, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_DES_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_NULL_MD5, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_NULL_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_NULL_SHA256, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_SEED_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, AuthenticationAlgorithm.RSA },
		{ TlsCipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA, AuthenticationAlgorithm.RSA },
	}.ToFrozenDictionary();

	/// <summary>
	/// TLS 1.3 lookup table to infer certificate authentication algorithms from the signature_algorithms extension advertised in ClientHello.
	/// </summary>
	private static readonly FrozenDictionary<TlsSignatureScheme, AuthenticationAlgorithm> tls13AuthSALookup
		= new Dictionary<TlsSignatureScheme, AuthenticationAlgorithm>
	{
		{ TlsSignatureScheme.ecdsa_secp256r1_sha256, AuthenticationAlgorithm.ECDSA },
		{ TlsSignatureScheme.ecdsa_secp384r1_sha384, AuthenticationAlgorithm.ECDSA },
		{ TlsSignatureScheme.ecdsa_secp521r1_sha512, AuthenticationAlgorithm.ECDSA },
		{ TlsSignatureScheme.ecdsa_sha1, AuthenticationAlgorithm.ECDSA },
		{ TlsSignatureScheme.ed25519, AuthenticationAlgorithm.EdDSA },
		{ TlsSignatureScheme.ed448, AuthenticationAlgorithm.EdDSA },
		{ TlsSignatureScheme.rsa_pkcs1_sha1, AuthenticationAlgorithm.RSA },
		{ TlsSignatureScheme.rsa_pkcs1_sha256, AuthenticationAlgorithm.RSA },
		{ TlsSignatureScheme.rsa_pkcs1_sha384, AuthenticationAlgorithm.RSA },
		{ TlsSignatureScheme.rsa_pkcs1_sha512, AuthenticationAlgorithm.RSA },
		{ TlsSignatureScheme.rsa_pss_pss_sha256, AuthenticationAlgorithm.RSA },
		{ TlsSignatureScheme.rsa_pss_pss_sha384, AuthenticationAlgorithm.RSA },
		{ TlsSignatureScheme.rsa_pss_pss_sha512, AuthenticationAlgorithm.RSA },
		{ TlsSignatureScheme.rsa_pss_rsae_sha256, AuthenticationAlgorithm.RSA },
		{ TlsSignatureScheme.rsa_pss_rsae_sha384, AuthenticationAlgorithm.RSA },
		{ TlsSignatureScheme.rsa_pss_rsae_sha512, AuthenticationAlgorithm.RSA },
	}.ToFrozenDictionary();

	/// <summary>
	/// Determines the client's supported certificate authentication algorithms based on the parsed TLS ClientHello information.
	/// </summary>
	/// <param name="clientHelloInfo">The parsed TLS ClientHello information.</param>
	/// <param name="authenticationAlgorithm">The selected authentication algorithm.</param>
	/// <returns><c>true</c> if a supported authentication algorithm was found; otherwise, <c>false</c>.</returns>
	public static Boolean TrySelectAlogrithm
	(
		in TlsClientHelloInfo clientHelloInfo,
		out AuthenticationAlgorithm authenticationAlgorithm
	)
	{
		// TLS 1.3: Get algorithms from signature_algorithms_cert extension
		if (clientHelloInfo.SignatureAlgorithmsCertCount != 0)
		{
			var signatureAlgorithmsCert = new TlsSignatureScheme[clientHelloInfo.SignatureAlgorithmsCertCount];

			if (clientHelloInfo.TryCopySignatureAlgorithmsCert(signatureAlgorithmsCert))
			{
				foreach (var signatureAlgorithm in signatureAlgorithmsCert)
				{
					if (tls13AuthSALookup.TryGetValue(signatureAlgorithm, out authenticationAlgorithm))
					{
						return true;
					}
				}
			}
		}

		// TLS 1.3 and 1.2: Get algorithms from signature_algorithms extension
		if (clientHelloInfo.SignatureAlgorithmsCount != 0)
		{
			var signatureAlgorithms = new TlsSignatureScheme[clientHelloInfo.SignatureAlgorithmsCount];

			if (clientHelloInfo.TryCopySignatureAlgorithms(signatureAlgorithms))
			{
				foreach (var signatureAlgorithm in signatureAlgorithms)
				{
					if (tls13AuthSALookup.TryGetValue(signatureAlgorithm, out authenticationAlgorithm))
					{
						return true;
					}
				}
			}
		}

		// TLS 1.2: Get algorithms from cipher suites
		if (clientHelloInfo.CipherSuitesCount != 0)
		{
			var cipherSuites = new TlsCipherSuite[clientHelloInfo.CipherSuitesCount];

			if (clientHelloInfo.TryCopyCipherSuites(cipherSuites))
			{
				foreach (var cipherSuite in cipherSuites)
				{
					if (tls12AuthSALookup.TryGetValue(cipherSuite, out authenticationAlgorithm))
					{
						return true;
					}
				}
			}
		}

		authenticationAlgorithm = AuthenticationAlgorithm.None;

		return false;
	}
}
