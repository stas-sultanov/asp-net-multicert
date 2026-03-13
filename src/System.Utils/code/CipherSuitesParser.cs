// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

using System.Buffers;
using System.Runtime.CompilerServices;

/// <summary>
/// Parses a TLS ClientHello message and extracts the advertised cipher suites.
/// </summary>
/// <remarks>
/// Designed according to <see href="https://www.rfc-editor.org/rfc/rfc8446">RFC 8446</see>.
/// </remarks>
public static class CipherSuitesParser
{
	#region Constants

	/// <summary>
	/// <c>Handshake</c> header size in bytes, as: <c>msg_type(1) + length(3) = 4</c>.
	/// </summary>
	/// <remarks>According to <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.</remarks>
	private const UInt32 HandshakeHeaderSize = 4;

	#endregion

	#region Public Methods

	/// <summary>
	/// Tries to parse the given bytes as a ClientHello message carried in TLS,
	/// and extract the supported cipher suites.
	/// </summary>
	/// <param name="data">The bytes that should represent the TLS ClientHello message, starting from the beginning of the TLS record.</param>
	/// <param name="cipherSuites">The output collection of cipher suites extracted from the ClientHello message, if parsing is successful; otherwise, an empty collection.</param>
	/// <returns>A <see cref="CipherSuitesParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static CipherSuitesParseErrorCode TryParse
	(
		ReadOnlySequence<Byte> data,
		out IReadOnlyCollection<TlsCipherSuite> cipherSuites
	)
	{
		if (data.IsEmpty)
		{
			cipherSuites = [];
			return CipherSuitesParseErrorCode.DataIsEmpty;
		}

		// Validate data.length:
		// must be at least the TLSPlaintext header size (5 bytes)
		if (data.Length < 5)
		{
			cipherSuites = [];
			return CipherSuitesParseErrorCode.DataLengthIsInvalid;
		}

		// Create reader
		var reader = new SequenceReader<Byte>(data);

		// Layer 0: TLSPlaintext record containing a Handshake message
		var result = TryProcessRecord(ref reader, out var handshakeLength);

		if (result != CipherSuitesParseErrorCode.None)
		{
			cipherSuites = [];
			return result;
		}

		// Layer 1: Handshake message containing a ClientHello message
		result = TryProcessHandshake(ref reader, handshakeLength, out var clientHelloLength);

		if (result != CipherSuitesParseErrorCode.None)
		{
			cipherSuites = [];
			return result;
		}

		// Layer 2: ClientHello message containing the cipher suites
		result = TryProcessClientHello(ref reader, clientHelloLength, out cipherSuites);

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
	/// <returns>A <see cref="CipherSuitesParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static CipherSuitesParseErrorCode TryProcessRecord
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
			return CipherSuitesParseErrorCode.DataReadError;
		}

		// Validate TLSPlaintext.type, must be ContentType.handshake
		if (type != ContentTypeHandshake)
		{
			handshakeLength = default;
			return CipherSuitesParseErrorCode.RecordField_Type_ValueIsNotHandshake;
		}

		// Skip TLSPlaintext.legacy_record_version, 2 bytes
		reader.Advance(2);

		// Read TLSPlaintext.length, 2 bytes
		if (!reader.TryReadBigEndian(out handshakeLength))
		{
			return CipherSuitesParseErrorCode.DataReadError;
		}

		// Validate TLSPlaintext.length
		// must be at least as Handshake header size to contain a valid Handshake message
		// must not exceed the remaining bytes in the reader
		if ((handshakeLength < HandshakeHeaderSize) || (handshakeLength > reader.Remaining))
		{
			return CipherSuitesParseErrorCode.RecordField_Length_ValueIsInvalid;
		}

		return CipherSuitesParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a Handshake struct containing a ClientHello.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.</remarks>
	/// <param name="reader">The byte sequence reader.</param>
	/// <param name="handshakeLength">The Handshake message payload length declared in the TLS record header.</param>
	/// <param name="clientHelloLength">The output length of the ClientHello message body as declared in the Handshake message header, if parsing is successful; otherwise, zero.</param>
	/// <returns>A <see cref="CipherSuitesParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static CipherSuitesParseErrorCode TryProcessHandshake
	(
		ref SequenceReader<Byte> reader,
		UInt32 handshakeLength,
		out UInt32 clientHelloLength
	)
	{
		// HandshakeType.client_hello enum value.
		const Byte HandshakeTypeClientHello = 0x01;

		// Read Handshake.msg_type, 1 byte
		if (!reader.TryRead(out var handshakeType))
		{
			clientHelloLength = default;
			return CipherSuitesParseErrorCode.DataReadError;
		}

		// Validate Handshake.msg_type, must be HandshakeType.client_hello
		if (handshakeType != HandshakeTypeClientHello)
		{
			clientHelloLength = default;
			return CipherSuitesParseErrorCode.HandshakeField_MessageType_ValueIsNotClientHello;
		}

		// Read Handshake.length, 3 bytes
		if (!reader.TryReadBigEndian24(out clientHelloLength))
		{
			return CipherSuitesParseErrorCode.DataReadError;
		}

		// Validate Handshake.length:
		// must be at least the minimum ClientHello body size (49 bytes)
		// must not exceed the remaining bytes in the Handshake message
		if ((clientHelloLength < 49) || (clientHelloLength > handshakeLength - HandshakeHeaderSize))
		{
			return CipherSuitesParseErrorCode.HandshakeField_Length_ValueIsInvalid;
		}

		return CipherSuitesParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a ClientHello struct and extract the cipher suites.
	/// </summary>
	/// <remarks>ClientHello struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2">RFC 8446 Section 4.1.2</see>.</remarks>
	/// <param name="reader">The byte sequence reader instance from which the Handshake bytes are to be read.</param>
	/// <param name="clientHelloLength">The ClientHello message body length declared in the Handshake header.</param>
	/// <param name="cipherSuites">The output collection of cipher suites extracted from the ClientHello message, if parsing is successful; otherwise, an empty collection.</param>
	/// <returns>A <see cref="CipherSuitesParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static CipherSuitesParseErrorCode TryProcessClientHello
	(
		ref SequenceReader<Byte> reader,
		UInt32 clientHelloLength,
		out IReadOnlyCollection<TlsCipherSuite> cipherSuites
	)
	{
		// Skip ClientHello.legacy_version and ClientHello.random, 34 bytes
		reader.Advance(34);

		// Read ClientHello.legacy_session_id.length, 1 byte
		if (!reader.TryRead(out var legacySessionIdLength))
		{
			cipherSuites = [];
			return CipherSuitesParseErrorCode.DataReadError;
		}

		// Validate ClientHello.legacy_session_id.length
		// must not be greater than 32
		// must not exceed bytes remaining in the declared ClientHello body; 35 is the current read position and at least 2 bytes must remain for the cipher_suites.length field
		if (legacySessionIdLength > 32 || legacySessionIdLength > clientHelloLength - 37)
		{
			cipherSuites = [];
			return CipherSuitesParseErrorCode.ClientHelloField_LegacySessionIdLength_ValueIsInvalid;
		}

		// Skip ClientHello.legacy_session_id.data, length bytes
		reader.Advance(legacySessionIdLength);

		// Read ClientHello.cipher_suites.length, 2 bytes
		if (!reader.TryReadBigEndian(out UInt16 cipherSuitesLength))
		{
			cipherSuites = [];
			return CipherSuitesParseErrorCode.DataReadError;
		}

		// Validate ClientHello.cipher_suites.length:
		// must be non-zero and a multiple of 2, since each cipher suite is represented by 2 bytes
		// must not exceed the remaining bytes in the declared ClientHello body; 37 is the minimum offset at this position
		if (cipherSuitesLength == 0 || (cipherSuitesLength % 2) != 0 || (cipherSuitesLength > clientHelloLength - (37 + legacySessionIdLength)))
		{
			cipherSuites = [];
			return CipherSuitesParseErrorCode.ClientHelloField_CipherSuitesLength_ValueIsInvalid;
		}

		var suites = new TlsCipherSuite[cipherSuitesLength / 2];

		for (var suiteIndex = 0; suiteIndex < suites.Length; suiteIndex++)
		{
			// Read each cipher suite, 2 bytes
			if (!reader.TryReadBigEndian(out UInt16 suite))
			{
				cipherSuites = [];
				return CipherSuitesParseErrorCode.DataReadError;
			}

			suites[suiteIndex] = (TlsCipherSuite) suite;
		}

		cipherSuites = suites;
		return CipherSuitesParseErrorCode.None;
	}

	#endregion
}
