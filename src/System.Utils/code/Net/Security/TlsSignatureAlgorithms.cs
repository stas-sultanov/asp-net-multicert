// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

/// <summary>
/// Enumeration representing the signature algorithms.
/// </summary>
[Flags]
public enum TlsSignatureAlgorithms
{
	/// <summary>
	/// Indicates that no signature algorithm is supported or selected.
	/// </summary>
	None = 0,

	/// <summary>
	/// Indicates support for or selection of the RSA signature algorithm.
	/// </summary>
	RSA = 1 << 1,

	/// <summary>
	/// Indicates support for or selection of the ECDSA signature algorithm.
	/// </summary>
	ECDSA = 1 << 2,
}
