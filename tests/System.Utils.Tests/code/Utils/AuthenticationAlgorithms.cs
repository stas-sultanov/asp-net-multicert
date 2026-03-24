// Authored by Stas Sultanov
// Copyright © Stas Sultanov

/// <summary>
/// Represents the coarse certificate authentication algorithm families.
/// </summary>
/// <remarks>
/// Designed according to <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2.2">RFC 8446 Section 4.4.2.2</see>.
/// </remarks>
internal enum AuthenticationAlgorithm
{
	/// <summary>
	/// Indicates that no certificate authentication algorithm is supported or selected.
	/// </summary>
	None = 0,

	/// <summary>
	/// Indicates support for or selection of the RSA certificate authentication algorithm.
	/// </summary>
	RSA = 1 << 1,

	/// <summary>
	/// Indicates support for or selection of the ECDSA certificate authentication algorithm.
	/// </summary>
	ECDSA = 1 << 3,

	/// <summary>
	/// Indicates support for or selection of the EdDSA certificate authentication algorithm.
	/// </summary>
	EdDSA = 1 << 4,
}
