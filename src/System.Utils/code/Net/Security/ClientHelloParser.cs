// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

using System.Buffers;
using System.Collections.Frozen;
using System.Runtime.CompilerServices;

/// <summary>
/// Provides functionality to parse TLSPlainText that contains a Handshake message with a ClientHello.
/// </summary>
/// <remarks>
/// Designed according to <see href="https://www.rfc-editor.org/rfc/rfc8446">RFC 8446</see>.
/// And implemented to support TLS versions 1.2 and 1.3, as these are the versions supported by .NET SslStream.
/// </remarks>
public static class ClientHelloParser
{
	#region Constants and Static Fields

	/// <summary>
	/// <c>Handshake</c> header size in bytes, as: <c>msg_type(1) + length(3) = 4</c>.
	/// </summary>
	/// <remarks>According to <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.</remarks>
	private const UInt32 HandshakeHeaderSize = 4;

	/// <summary>
	/// TLS 1.2 cipher suite lookup table used to infer the server authentication algorithm.
	/// </summary>
	private static readonly FrozenDictionary<TlsCipherSuite, TlsSignatureAlgorithms> tls12ServerAuthLookup
		= new Dictionary<TlsCipherSuite, TlsSignatureAlgorithms>
	{
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_DES_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_DES_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA, TlsSignatureAlgorithms.ECDSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_CCM, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_CCM_8, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_CCM, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_CCM_8, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_DES_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_NULL_MD5, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_NULL_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_NULL_SHA256, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_RSA_WITH_SEED_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, TlsSignatureAlgorithms.RSA },
		{ TlsCipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA, TlsSignatureAlgorithms.RSA },
	}.ToFrozenDictionary();

	/// <summary>
	/// SignatureScheme lookup table used to infer certificate signature algorithm support.
	/// </summary>
	private static readonly FrozenDictionary<UInt16, TlsSignatureAlgorithms> signatureSchemeLookup
		= new Dictionary<UInt16, TlsSignatureAlgorithms>
	{
		{ 0x0201, TlsSignatureAlgorithms.RSA },
		{ 0x0301, TlsSignatureAlgorithms.RSA },
		{ 0x0401, TlsSignatureAlgorithms.RSA },
		{ 0x0501, TlsSignatureAlgorithms.RSA },
		{ 0x0601, TlsSignatureAlgorithms.RSA },
		{ 0x0804, TlsSignatureAlgorithms.RSA },
		{ 0x0805, TlsSignatureAlgorithms.RSA },
		{ 0x0806, TlsSignatureAlgorithms.RSA },
		{ 0x0809, TlsSignatureAlgorithms.RSA },
		{ 0x080A, TlsSignatureAlgorithms.RSA },
		{ 0x080B, TlsSignatureAlgorithms.RSA },
		{ 0x0203, TlsSignatureAlgorithms.ECDSA },
		{ 0x0303, TlsSignatureAlgorithms.ECDSA },
		{ 0x0403, TlsSignatureAlgorithms.ECDSA },
		{ 0x0503, TlsSignatureAlgorithms.ECDSA },
		{ 0x0603, TlsSignatureAlgorithms.ECDSA },
	}.ToFrozenDictionary();

	#endregion

	#region Public Methods

	/// <summary>
	/// Tries to parse the given bytes as a ClientHello message carried in TLS,
	/// and extract the supported signature algorithms.
	/// </summary>
	/// <param name="data">The bytes that should represent the TLS ClientHello message, starting from the beginning of the TLS record.</param>
	/// <param name="signatureAlgorithms">The output bitwise flags of signature algorithms extracted from the ClientHello message, if parsing is successful; otherwise, <see cref="TlsSignatureAlgorithms.None"/>.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ClientHelloParseErrorCode TryParse
	(
		ReadOnlySequence<Byte> data,
		out TlsSignatureAlgorithms signatureAlgorithms
	)
	{
		if (data.IsEmpty)
		{
			signatureAlgorithms = TlsSignatureAlgorithms.None;
			return ClientHelloParseErrorCode.DataIsEmpty;
		}

		// Validate data.length
		// must be at least the TLSPlaintext header size (5 bytes)
		if (data.Length < 5)
		{
			signatureAlgorithms = TlsSignatureAlgorithms.None;
			return ClientHelloParseErrorCode.DataLengthIsInvalid;
		}

		// Create reader
		var reader = new SequenceReader<Byte>(data);

		// TLSPlaintext record containing a Handshake message
		var result = TryProcessRecord(ref reader, out var handshakeLength);

		if (result != ClientHelloParseErrorCode.None)
		{
			signatureAlgorithms = TlsSignatureAlgorithms.None;
			return result;
		}

		// Handshake message containing a ClientHello message
		result = TryProcessHandshake(ref reader, handshakeLength, out var clientHelloLength);

		if (result != ClientHelloParseErrorCode.None)
		{
			signatureAlgorithms = TlsSignatureAlgorithms.None;
			return result;
		}

		// ClientHello message containing signature algorithms
		result = TryProcessClientHello(ref reader, clientHelloLength, out signatureAlgorithms);

		return result;
	}

	#endregion

	#region Private Methods

	/// <summary>
	/// Tries to parse the given bytes as a TLSPlaintext struct containing a Handshake.
	/// </summary>
	/// <remarks>TLSPlaintext struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see>.</remarks>
	/// <param name="reader">The byte sequence reader.</param>
	/// <param name="handshakeLength">The output length of the Handshake message payload as declared in the TLS record header, if parsing is successful; otherwise, zero.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryProcessRecord
	(
		ref SequenceReader<Byte> reader,
		out UInt16 handshakeLength
	)
	{
		// ContentType.handshake enum value.
		const Byte ContentTypeHandshake = 0x16;

		// Read TLSPlaintext.type, 1 byte
		if (!reader.TryRead(out var type))
		{
			handshakeLength = default;
			return ClientHelloParseErrorCode.DataReadError;
		}

		// Validate TLSPlaintext.type
		// must be ContentType.handshake
		if (type != ContentTypeHandshake)
		{
			handshakeLength = default;
			return ClientHelloParseErrorCode.RecordField_Type_ValueIsNotHandshake;
		}

		// Skip TLSPlaintext.legacy_record_version, 2 bytes
		reader.Advance(2);

		// Read TLSPlaintext.length, 2 bytes
		if (!reader.TryReadBigEndian(out handshakeLength))
		{
			return ClientHelloParseErrorCode.DataReadError;
		}

		// Validate TLSPlaintext.length
		// must be at least as Handshake header size to contain a valid Handshake message
		// must not exceed the remaining bytes in the reader
		if ((handshakeLength < HandshakeHeaderSize) || (handshakeLength > reader.Remaining))
		{
			return ClientHelloParseErrorCode.RecordField_Length_ValueIsInvalid;
		}

		return ClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a Handshake struct containing a ClientHello.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.</remarks>
	/// <param name="reader">The byte sequence reader.</param>
	/// <param name="handshakeLength">The Handshake message payload length declared in the TLS record header.</param>
	/// <param name="clientHelloLength">The output length of the ClientHello message body as declared in the Handshake message header, if parsing is successful; otherwise, zero.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryProcessHandshake
	(
		ref SequenceReader<Byte> reader,
		UInt32 handshakeLength,
		out Int32 clientHelloLength
	)
	{
		// HandshakeType.client_hello enum value.
		const Byte HandshakeTypeClientHello = 0x01;

		// Read Handshake.msg_type, 1 byte
		if (!reader.TryRead(out var handshakeType))
		{
			clientHelloLength = default;
			return ClientHelloParseErrorCode.DataReadError;
		}

		// Validate Handshake.msg_type
		// must be HandshakeType.client_hello
		if (handshakeType != HandshakeTypeClientHello)
		{
			clientHelloLength = default;
			return ClientHelloParseErrorCode.HandshakeField_MessageType_ValueIsNotClientHello;
		}

		// Read Handshake.length, 3 bytes
		if (!reader.TryReadBigEndian24(out clientHelloLength))
		{
			return ClientHelloParseErrorCode.DataReadError;
		}

		// Validate Handshake.length
		// must be at least the minimum size of TLS 1.2 ClientHello body (41 bytes)
		// must not exceed the remaining bytes in the Handshake message
		if ((clientHelloLength < 41) || (clientHelloLength > handshakeLength - HandshakeHeaderSize))
		{
			return ClientHelloParseErrorCode.HandshakeField_Length_ValueIsInvalid;
		}

		return ClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a ClientHello struct and extract supported signature algorithms.
	/// </summary>
	/// <remarks>ClientHello struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2">RFC 8446 Section 4.1.2</see>.</remarks>
	/// <param name="reader">The byte sequence reader instance from which the Handshake bytes are to be read.</param>
	/// <param name="clientHelloLength">The ClientHello message body length declared in the Handshake header.</param>
	/// <param name="signatureAlgorithms">The output bitwise flags of signature algorithms extracted from the ClientHello message, if parsing is successful; otherwise, <see cref="TlsSignatureAlgorithms.None"/>.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryProcessClientHello
	(
		ref SequenceReader<Byte> reader,
		Int32 clientHelloLength,
		out TlsSignatureAlgorithms signatureAlgorithms
	)
	{
		signatureAlgorithms = TlsSignatureAlgorithms.None;

		// Skip ClientHello.legacy_version and ClientHello.random, 34 bytes
		reader.Advance(34);

		// Read ClientHello.legacy_session_id.length, 1 byte
		if (!reader.TryRead(out var legacySessionIdLength))
		{
			return ClientHelloParseErrorCode.DataReadError;
		}

		// Remaining length of the ClientHello body in bytes.
		// 38 is the minimum size of the ClientHello message body in bytes according to TLS 1.2
		var remainingLength = clientHelloLength - 38 - legacySessionIdLength;

		// Validate ClientHello.legacy_session_id.length
		// must not be greater than 32
		// must not exceed bytes remaining in the declared ClientHello body
		if (remainingLength < 0 || legacySessionIdLength > 32)
		{
			return ClientHelloParseErrorCode.ClientHelloField_LegacySessionIdLength_ValueIsInvalid;
		}

		// Skip ClientHello.legacy_session_id.data, length bytes
		reader.Advance(legacySessionIdLength);

		// Read ClientHello.cipher_suites.length, 2 bytes
		if (!reader.TryReadBigEndian(out UInt16 cipherSuitesLength))
		{
			return ClientHelloParseErrorCode.DataReadError;
		}

		// Adjust remaning length
		remainingLength -= cipherSuitesLength;

		// Validate ClientHello.cipher_suites.length
		// must be non-zero and a multiple of 2, since each cipher suite is represented by 2 bytes
		// must not exceed bytes remaining in the declared ClientHello body
		if (remainingLength < 0 || cipherSuitesLength == 0 || (cipherSuitesLength % 2) != 0)
		{
			return ClientHelloParseErrorCode.ClientHelloField_CipherSuitesLength_ValueIsInvalid;
		}

		// Read ClientHello.cipher_suites.data
		for (var suiteIndex = 0; suiteIndex < cipherSuitesLength / 2; suiteIndex++)
		{
			// Read each cipher suite, 2 bytes
			if (!reader.TryReadBigEndian(out UInt16 cipherSuite))
			{
				return ClientHelloParseErrorCode.DataReadError;
			}

			// Infer server auth algorithms from TLS 1.2 cipher suites.
			if (tls12ServerAuthLookup.TryGetValue((TlsCipherSuite) cipherSuite, out var cipherSuiteSignatureAlgorithm))
			{
				signatureAlgorithms |= cipherSuiteSignatureAlgorithm;
			}
		}

		// TLS 1.2 path: cipher suites should reveal the auth algorithm, so extension parsing is not needed.
		// TLS 1.3 path: cipher suites do not encode auth algorithm; continue and parse signature_algorithms extension.
		if (signatureAlgorithms != TlsSignatureAlgorithms.None)
		{
			return ClientHelloParseErrorCode.None;
		}

		// Read ClientHello.legacy_compression_methods.length, 1 byte
		if (!reader.TryRead(out var legacyCompressionMethodsLength))
		{
			return ClientHelloParseErrorCode.DataReadError;
		}

		// Adjust remaning length
		remainingLength -= legacyCompressionMethodsLength;

		// Validate ClientHello.legacy_compression_methods.length
		// must be betwen 1 and 255
		// must not exceed the remaining bytes in the declared ClientHello body
		if (remainingLength < 0 || legacyCompressionMethodsLength < 1)
		{
			return ClientHelloParseErrorCode.ClientHelloField_LegacyCompressionMethodsLength_ValueIsInvalid;
		}

		// Skip ClientHello.legacy_compression_methods.data, length bytes
		reader.Advance(legacyCompressionMethodsLength);

		// Check if end is reached
		// If so than protocol is TLS 1.2 and no signature algorithms found.
		if (remainingLength == 0)
		{
			return ClientHelloParseErrorCode.None;
		}

		return TryProcessClientHelloExtensions(ref reader, remainingLength, ref signatureAlgorithms);
	}

	/// <summary>
	/// Tries to parse the ClientHello extensions and extract supported signature algorithms from the signature_algorithms extension, if present.
	/// </summary>
	/// <param name="reader">The byte sequence reader instance from which the ClientHello extensions bytes are to be read.</param>
	/// <param name="remainingLength">The remaining length of the ClientHello message body.</param>
	/// <param name="signatureAlgorithms">The bitwise flags of signature algorithms extracted so far from the ClientHello message; will be updated with any additional algorithms found in the extensions.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryProcessClientHelloExtensions
	(
		ref SequenceReader<Byte> reader,
		Int32 remainingLength,
		ref TlsSignatureAlgorithms signatureAlgorithms
	)
	{
		// Read ClientHello.extensions.length, 2 bytes
		if (!reader.TryReadBigEndian(out UInt16 extensionsLength))
		{
			return ClientHelloParseErrorCode.DataReadError;
		}

		// Adjust remaning length
		remainingLength -= 2 + extensionsLength;

		// Validate ClientHello.extensions.length
		// must be betwen 8 and 65535
		// must not exceed the remaining bytes in the declared ClientHello body
		if (remainingLength < 0 || extensionsLength < 8)
		{
			return ClientHelloParseErrorCode.ClientHelloField_ExtensionsLength_ValueIsInvalid;
		}

		UInt32 processedExtensionsLength = 0;

		while (processedExtensionsLength < extensionsLength)
		{
			if (!reader.TryReadBigEndian(out UInt16 extensionType) || !reader.TryReadBigEndian(out UInt16 extensionDataLength))
			{
				return ClientHelloParseErrorCode.DataReadError;
			}

			processedExtensionsLength += 4;

			if (processedExtensionsLength > extensionsLength || extensionDataLength > (extensionsLength - processedExtensionsLength))
			{
				return ClientHelloParseErrorCode.DataReadError;
			}

			// signature_algorithms
			if (extensionType == 13)
			{
				if (extensionDataLength < 2)
				{
					return ClientHelloParseErrorCode.DataReadError;
				}

				if (!reader.TryReadBigEndian(out UInt16 signatureSchemesListLength))
				{
					return ClientHelloParseErrorCode.DataReadError;
				}

				if (signatureSchemesListLength == 0 || (signatureSchemesListLength % 2) != 0 || signatureSchemesListLength != (extensionDataLength - 2))
				{
					return ClientHelloParseErrorCode.DataReadError;
				}

				for (var signatureSchemeIndex = 0; signatureSchemeIndex < signatureSchemesListLength / 2; signatureSchemeIndex++)
				{
					if (!reader.TryReadBigEndian(out UInt16 signatureScheme))
					{
						return ClientHelloParseErrorCode.DataReadError;
					}

					signatureAlgorithms |= GetSignatureAlgorithmsFromSignatureScheme(signatureScheme);
				}
			}
			else
			{
				reader.Advance(extensionDataLength);
			}

			processedExtensionsLength += extensionDataLength;
		}

		if (processedExtensionsLength != extensionsLength)
		{
			return ClientHelloParseErrorCode.DataReadError;
		}

		return ClientHelloParseErrorCode.None;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TlsSignatureAlgorithms GetSignatureAlgorithmsFromSignatureScheme(UInt16 signatureScheme)
	{
		return signatureSchemeLookup.TryGetValue(signatureScheme, out var signatureAlgorithms)
			? signatureAlgorithms
			: TlsSignatureAlgorithms.None;
	}

	#endregion
}
