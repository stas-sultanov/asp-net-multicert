// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

/// <summary>
/// SignatureScheme enum as defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3">RFC 8446 Section 4.2.3</see>.
/// </summary>
public enum TlsSignatureScheme : UInt16
{
	/// <summary>
	/// Indicates that no signature scheme is offered.
	/// </summary>
	None = 0x0000,

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-256.
	/// </summary>
	rsa_pkcs1_sha256 = 0x0401,

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-384.
	/// </summary>
	rsa_pkcs1_sha384 = 0x0501,

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-512.
	/// </summary>
	rsa_pkcs1_sha512 = 0x0601,

	/// <summary>
	/// ECDSA over the secp256r1 curve with SHA-256.
	/// </summary>
	ecdsa_secp256r1_sha256 = 0x0403,

	/// <summary>
	/// ECDSA over the secp384r1 curve with SHA-384.
	/// </summary>
	ecdsa_secp384r1_sha384 = 0x0503,

	/// <summary>
	/// ECDSA over the secp521r1 curve with SHA-512.
	/// </summary>
	ecdsa_secp521r1_sha512 = 0x0603,

	/// <summary>
	/// RSASSA-PSS with SHA-256 and a public key with OID rsaEncryption.
	/// </summary>
	rsa_pss_rsae_sha256 = 0x0804,

	/// <summary>
	/// RSASSA-PSS with SHA-384 and a public key with OID rsaEncryption.
	/// </summary>
	rsa_pss_rsae_sha384 = 0x0805,

	/// <summary>
	/// RSASSA-PSS with SHA-512 and a public key with OID rsaEncryption.
	/// </summary>
	rsa_pss_rsae_sha512 = 0x0806,

	/// <summary>
	/// Ed25519.
	/// </summary>
	ed25519 = 0x0807,

	/// <summary>
	/// Ed448.
	/// </summary>
	ed448 = 0x0808,

	/// <summary>
	/// RSASSA-PSS with SHA-256 and a public key with OID RSASSA-PSS.
	/// </summary>
	rsa_pss_pss_sha256 = 0x0809,

	/// <summary>
	/// RSASSA-PSS with SHA-384 and a public key with OID RSASSA-PSS.
	/// </summary>
	rsa_pss_pss_sha384 = 0x080a,

	/// <summary>
	/// RSASSA-PSS with SHA-512 and a public key with OID RSASSA-PSS.
	/// </summary>
	rsa_pss_pss_sha512 = 0x080b,

	/// <summary>
	/// Legacy RSASSA-PKCS1-v1_5 with SHA-1.
	/// </summary>
	rsa_pkcs1_sha1 = 0x0201,

	/// <summary>
	/// Legacy ECDSA with SHA-1.
	/// </summary>
	ecdsa_sha1 = 0x0203
}
