// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

using System.Buffers;
using System.Runtime.CompilerServices;

/// <summary>
/// Provides functionality to parse TLSPlaintext that contains a Handshake message with a ClientHello.
/// </summary>
/// <remarks>
/// Designed according to <see href="https://www.rfc-editor.org/rfc/rfc8446">RFC 8446</see> and <see href="https://www.rfc-editor.org/rfc/rfc5246">RFC 5246</see>.
/// With performance considerations in mind, to be used in the hot path of TLS record processing for server certificate selection based on ClientHello capabilities.
/// </remarks>
public static class TlsClientHelloParser
{
	#region Constants and Static Fields

	/// <summary>
	/// <c>Handshake</c> header size in bytes, as: <c>msg_type(1) + length(3) = 4</c>.
	/// </summary>
	/// <remarks>According to <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.</remarks>
	private const UInt32 HandshakeHeaderSize = 4;

	#endregion

	#region Public Methods

	/// <summary>
	/// Tries to parse the given bytes as a ClientHello message carried in TLS,
	/// and extract the certificate authentication algorithms inferred from that ClientHello
	/// for server certificate selection.
	/// </summary>
	/// <param name="data">The bytes that should represent the TLS ClientHello message, starting from the beginning of the TLS record.</param>
	/// <param name="info">The output <see cref="TlsClientHelloInfo"/> containing information about the ClientHello message, if parsing is successful; otherwise, <c>default</c>.</param>
	/// <returns>A <see cref="TlsClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static TlsClientHelloParseErrorCode TryParse
	(
		ReadOnlySequence<Byte> data,
		out TlsClientHelloInfo info
	)
	{
		if (data.IsEmpty)
		{
			info = default;
			return TlsClientHelloParseErrorCode.Data_IsEmpty;
		}

		// Validate data.length
		// must be at least the TLSPlaintext header size (5 bytes)
		if (data.Length < 5)
		{
			info = default;
			return TlsClientHelloParseErrorCode.Data_LengthIsInvalid;
		}

		// Create reader
		var reader = new SequenceReader<Byte>(data);

		// TLSPlaintext record containing a Handshake message
		var result = TryProcessRecord(ref reader, out var handshakeLength);

		if (result != TlsClientHelloParseErrorCode.None)
		{
			info = default;
			return result;
		}

		// Handshake message containing a ClientHello message
		result = TryProcessHandshake(ref reader, handshakeLength, out var clientHelloLength);

		if (result != TlsClientHelloParseErrorCode.None)
		{
			info = default;
			return result;
		}

		// ClientHello message containing capabilities
		result = TryProcessClientHello(reader, clientHelloLength, out info);

		return result;
	}

	#endregion

	#region Private Methods

	/// <summary>
	/// Tries to parse the given bytes as a TLSPlaintext struct containing a Handshake.
	/// </summary>
	/// <remarks>TLSPlaintext struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see> and <see href="https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1">RFC 5246 Section 6.2.1</see>.</remarks>
	/// <param name="reader">The byte sequence reader.</param>
	/// <param name="handshakeLength">The output length of the Handshake message payload as declared in the TLS record header, if parsing is successful; otherwise, zero.</param>
	/// <returns>A <see cref="TlsClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TlsClientHelloParseErrorCode TryProcessRecord
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
			return TlsClientHelloParseErrorCode.ReadError;
		}

		// Validate TLSPlaintext.type
		// must be ContentType.handshake
		if (type != ContentTypeHandshake)
		{
			handshakeLength = default;
			return TlsClientHelloParseErrorCode.TLSPlaintextField_Type_ValueIsNotHandshake;
		}

		// Skip TLSPlaintext.legacy_record_version, 2 bytes
		reader.Advance(2);

		// Read TLSPlaintext.length, 2 bytes
		if (!reader.TryReadBigEndian(out handshakeLength))
		{
			return TlsClientHelloParseErrorCode.ReadError;
		}

		// Validate TLSPlaintext.length
		// must be at least the Handshake header size to contain a valid Handshake message
		// must not exceed the remaining bytes in the reader
		if ((handshakeLength < HandshakeHeaderSize) || (handshakeLength > reader.Remaining))
		{
			return TlsClientHelloParseErrorCode.TLSPlaintextField_Length_ValueIsInvalid;
		}

		return TlsClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a Handshake struct containing a ClientHello.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see> and <see href="https://www.rfc-editor.org/rfc/rfc5246#section-7.4">RFC 5246 Section 7.4</see>.</remarks>
	/// <param name="reader">The byte sequence reader.</param>
	/// <param name="handshakeLength">The Handshake message payload length declared in the TLS record header.</param>
	/// <param name="clientHelloLength">The output length of the ClientHello message body as declared in the Handshake message header, if parsing is successful; otherwise, zero.</param>
	/// <returns>A <see cref="TlsClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TlsClientHelloParseErrorCode TryProcessHandshake
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
			return TlsClientHelloParseErrorCode.ReadError;
		}

		// Validate Handshake.msg_type
		// must be HandshakeType.client_hello
		if (handshakeType != HandshakeTypeClientHello)
		{
			clientHelloLength = default;
			return TlsClientHelloParseErrorCode.Handshake_MessageType_ValueIsNotClientHello;
		}

		// Read Handshake.length, 3 bytes
		if (!reader.TryReadBigEndian24(out clientHelloLength))
		{
			return TlsClientHelloParseErrorCode.ReadError;
		}

		// Validate Handshake.length
		// must be at least the minimum size of TLS 1.2 ClientHello body (41 bytes)
		// must not exceed the remaining bytes in the Handshake message
		if ((clientHelloLength < 41) || (clientHelloLength > handshakeLength - HandshakeHeaderSize))
		{
			return TlsClientHelloParseErrorCode.Handshake_Length_ValueIsInvalid;
		}

		return TlsClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a ClientHello struct and extract the certificate authentication algorithms
	/// inferred from it.
	/// </summary>
	/// <remarks>ClientHello struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2">RFC 8446 Section 4.1.2</see> and <see href="https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2">RFC 5246 Section 7.4.1.2</see>.</remarks>
	/// <param name="reader">The byte sequence reader instance from which the ClientHello bytes are to be read.</param>
	/// <param name="clientHelloLength">The ClientHello message body length declared in the Handshake header.</param>
	/// <param name="info">The output bitwise flags of certificate authentication algorithms inferred from the ClientHello message, if parsing is successful; otherwise, default.</param>
	/// <returns>A <see cref="TlsClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TlsClientHelloParseErrorCode TryProcessClientHello
	(
		SequenceReader<Byte> reader,
		Int32 clientHelloLength,
		out TlsClientHelloInfo info
	)
	{
		// Skip ClientHello.legacy_version and ClientHello.random, 34 bytes
		reader.Advance(34);

		// Read ClientHello.legacy_session_id.length, 1 byte
		if (!reader.TryRead(out var legacySessionIdLength))
		{
			info = default;
			return TlsClientHelloParseErrorCode.ReadError;
		}

		// Remaining length of the ClientHello body in bytes.
		// 38 accounts for: 34 bytes already consumed (legacy_version + random), 1 byte just read (legacy_session_id.length),
		// 2 bytes for the cipher_suites.length field, and 1 byte for the legacy_compression_methods.length field.
		var remainingLength = clientHelloLength - 38 - legacySessionIdLength;

		// Validate ClientHello.legacy_session_id.length
		// must not be greater than 32
		// must not exceed bytes remaining in the declared ClientHello body
		if (remainingLength < 0 || legacySessionIdLength > 32)
		{
			info = default;
			return TlsClientHelloParseErrorCode.ClientHello_LegacySessionIdLength_ValueIsInvalid;
		}

		// Skip ClientHello.legacy_session_id.data, length bytes
		reader.Advance(legacySessionIdLength);

		// Read ClientHello.cipher_suites.length, 2 bytes
		if (!reader.TryReadBigEndian(out UInt16 cipherSuitesLength))
		{
			info = default;
			return TlsClientHelloParseErrorCode.ReadError;
		}

		// Adjust remaining length
		remainingLength -= cipherSuitesLength;

		// Validate ClientHello.cipher_suites.length
		// must be non-zero and a multiple of 2, since each cipher suite is represented by 2 bytes
		// must not exceed bytes remaining in the declared ClientHello body
		if (remainingLength < 0 || cipherSuitesLength == 0 || (cipherSuitesLength % 2) != 0)
		{
			info = default;
			return TlsClientHelloParseErrorCode.ClientHello_CipherSuitesLength_ValueIsInvalid;
		}

		// Create a slice of the cipher suites bytes.
		var cipherSuites = reader.UnreadSequence.Slice(0, cipherSuitesLength);

		// Skip ClientHello.cipher_suites.data, length bytes
		reader.Advance(cipherSuitesLength);

		// Read ClientHello.legacy_compression_methods.length, 1 byte
		if (!reader.TryRead(out var legacyCompressionMethodsLength))
		{
			info = default;
			return TlsClientHelloParseErrorCode.ReadError;
		}

		// Adjust remaining length
		remainingLength -= legacyCompressionMethodsLength;

		// Validate ClientHello.legacy_compression_methods.length
		// must be between 1 and 255
		// must not exceed the remaining bytes in the declared ClientHello body
		if (remainingLength < 0 || legacyCompressionMethodsLength < 1)
		{
			info = default;
			return TlsClientHelloParseErrorCode.ClientHello_LegacyCompressionMethodsLength_ValueIsInvalid;
		}

		// Skip ClientHello.legacy_compression_methods.data, length bytes
		reader.Advance(legacyCompressionMethodsLength);

		// Check if end is reached.
		// If not, parse the extensions block so its structure is validated and relevant extension payloads can be captured.
		if (remainingLength == 0)
		{
			info = new TlsClientHelloInfo(cipherSuites, default, default);
			return TlsClientHelloParseErrorCode.None;
		}

		var result = TryProcessClientHelloExtensions(ref reader, remainingLength, out var signatureAlgorithms, out var signatureAlgorithmsCert);

		info = result == TlsClientHelloParseErrorCode.None
			? new TlsClientHelloInfo(cipherSuites, signatureAlgorithms, signatureAlgorithmsCert)
			: default;

		return result;
	}

	/// <summary>
	/// Tries to parse the ClientHello extensions and capture the raw values of the
	/// <c>signature_algorithms</c> and <c>signature_algorithms_cert</c> extensions, if present.
	/// </summary>
	/// <param name="reader">The byte sequence reader instance from which the ClientHello extensions bytes are to be read.</param>
	/// <param name="remainingLength">The remaining length of the ClientHello message body.</param>
	/// <param name="signatureAlgorithms">The raw bytes of the <c>signature_algorithms</c> extension payload, if present; otherwise, <c>default</c>.</param>
	/// <param name="signatureAlgorithmsCert">The raw bytes of the <c>signature_algorithms_cert</c> extension payload, if present; otherwise, <c>default</c>.</param>
	/// <returns>A <see cref="TlsClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TlsClientHelloParseErrorCode TryProcessClientHelloExtensions
	(
		ref SequenceReader<Byte> reader,
		Int32 remainingLength,
		out ReadOnlySequence<Byte> signatureAlgorithms,
		out ReadOnlySequence<Byte> signatureAlgorithmsCert
	)
	{
		signatureAlgorithms = default;
		signatureAlgorithmsCert = default;

		// ExtensionType.signature_algorithms enum value
		const Int32 ExtensionTypeSignatureAlgorithms = 13;
		// ExtensionType.signature_algorithms_cert enum value
		const Int32 ExtensionTypeSignatureAlgorithmsCert = 50;

		// Read ClientHello.extensions.length, 2 bytes
		if (!reader.TryReadBigEndian(out UInt16 extensionsLength))
		{
			return TlsClientHelloParseErrorCode.ReadError;
		}

		// Adjust remaining length
		remainingLength -= 2;

		// Validate ClientHello.extensions.length
		// must be between 8 and 65535
		// must not exceed the remaining bytes in the declared ClientHello body
		if ((remainingLength - extensionsLength) < 0 || extensionsLength < 8)
		{
			return TlsClientHelloParseErrorCode.ClientHello_ExtensionsLength_ValueIsInvalid;
		}

		// Read ClientHello.extensions.data
		while (remainingLength > 0)
		{
			// Read Extension.extension_type
			if (!reader.TryReadBigEndian(out UInt16 extensionType))
			{
				return TlsClientHelloParseErrorCode.ReadError;
			}

			// Read Extension.extension_data.length
			if (!reader.TryReadBigEndian(out UInt16 extensionDataLength))
			{
				return TlsClientHelloParseErrorCode.ReadError;
			}

			// Adjust remaining length
			remainingLength -= 4 + extensionDataLength;

			// Validate Extension.extension_data.length
			// must not exceed the remaining bytes in the extensions block
			if (remainingLength < 0)
			{
				return TlsClientHelloParseErrorCode.Extension_ExtensionDataLength_ValueIsInvalid;
			}

			switch (extensionType)
			{
				case ExtensionTypeSignatureAlgorithms:
					{
						var parseResult = TryProcessClientHelloExtensionSignatureAlgorithms(ref reader, extensionDataLength, out signatureAlgorithms);
						if (parseResult != TlsClientHelloParseErrorCode.None)
						{
							return parseResult;
						}

						break;
					}
				case ExtensionTypeSignatureAlgorithmsCert:
					{
						var parseResult = TryProcessClientHelloExtensionSignatureAlgorithms(ref reader, extensionDataLength, out signatureAlgorithmsCert);
						if (parseResult != TlsClientHelloParseErrorCode.None)
						{
							return parseResult;
						}

						break;
					}
				default:
					// Skip other extensions
					reader.Advance(extensionDataLength);
					break;
			}
		}

		return TlsClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the <c>signature_algorithms</c>-style extension and capture its raw payload.
	/// </summary>
	/// <remarks>SignatureSchemeList struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3">RFC 8446 Section 4.2.3</see> and <see href="https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4.1">RFC 5246 Section 7.4.1.4.1</see>.</remarks>
	/// <param name="reader">The byte sequence reader instance from which the extension bytes are to be read.</param>
	/// <param name="extensionDataLength">The length of the extension data.</param>
	/// <param name="signatureAlgorithms">The raw bytes of the signature schemes list, if parsing is successful; otherwise, <c>default</c>.</param>
	/// <returns>A <see cref="TlsClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TlsClientHelloParseErrorCode TryProcessClientHelloExtensionSignatureAlgorithms
	(
		ref SequenceReader<Byte> reader,
		Int32 extensionDataLength,
		out ReadOnlySequence<Byte> signatureAlgorithms
	)
	{
		// Read supported_signature_algorithms.length, 2 bytes
		if (!reader.TryReadBigEndian(out UInt16 supportedSignatureAlgorithmsLength))
		{
			signatureAlgorithms = default;
			return TlsClientHelloParseErrorCode.ReadError;
		}

		// Validate supported_signature_algorithms.length
		// must be non-zero and a multiple of 2, since each signature scheme is represented by 2 bytes
		// must not exceed the bytes available inside this extension (extensionDataLength - 2 bytes already read for the length field)
		if (supportedSignatureAlgorithmsLength == 0 || (supportedSignatureAlgorithmsLength % 2) != 0 || (2 + supportedSignatureAlgorithmsLength) > extensionDataLength)
		{
			signatureAlgorithms = default;
			return TlsClientHelloParseErrorCode.SignatureAlgorithm_SupportedSignatureAlgorithmsLength_ValueIsInvalid;
		}

		signatureAlgorithms = reader.UnreadSequence.Slice(0, supportedSignatureAlgorithmsLength);
		reader.Advance(supportedSignatureAlgorithmsLength);

		return TlsClientHelloParseErrorCode.None;
	}

	#endregion
}
