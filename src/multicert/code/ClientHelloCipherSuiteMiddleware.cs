using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Security;
using System.Runtime.CompilerServices;

using Microsoft.AspNetCore.Connections;

/// <summary>
/// This middleware processes the TLS ClientHello message
/// to extract the supported cipher suites
/// and store them in the connection context for later use during the TLS handshake.
/// </summary>
static class ClientHelloCipherSuiteMiddleware
{
	/// <summary>
	/// <c>ContentType.handshake</c> enum value as defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see>
	/// </summary>
	private const Byte ContentType_Handshake = 22;

	/// <summary>
	/// <c>HandshakeType.client_hello</c> enum value as defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>
	/// </summary>
	private const Byte HandshakeType_ClientHello = 1;

	/// <summary>
	/// Computed length of <c>TLSPlaintext</c> record header in bytes.
	/// </summary>
	/// <remarks>
	/// Computed from <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see> as: <c>type(1) + legacy_record_version(2) + length(2) = 5</c>.
	/// <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">TLSPlaintext Structure</see>
	/// </remarks>
	private const Int32 RecordHeaderSize = 5;

	/// <summary>
	/// TLS handshake message header length in bytes.
	/// Computed from RFC 8446 section 4 as: <c>msg_type(1) + length(uint24 = 3) = 4</c>.
	/// <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">Handshake Message Structure</see>
	/// </summary>
	private const Int32 HandshakeHeaderSize = 4;

	/// <summary>
	/// TLS <c>ProtocolVersion</c> field length in bytes.
	/// Source: protocol version is two octets (<c>uint16</c>) in TLS message structures.
	/// <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2">ClientHello.legacy_version</see>
	/// </summary>
	private const Int32 ProtocolVersionSize = 2;

	/// <summary>
	/// ClientHello <c>Random</c> field length in bytes.
	/// Source: RFC 8446 defines <c>random[32]</c> in ClientHello.
	/// <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2">ClientHello Structure</see>
	/// </summary>
	private const Int32 RandomSize = 32;

	/// <summary>
	/// The key used to store the supported cipher suites in the connection context items.
	/// </summary>
	public const String ContextKeyName = "CipherSuites";

	public static void Process
	(
		ConnectionContext context,
		ReadOnlySequence<Byte> message
	)
	{
		if (TryParseCipherSuits(message.ToArray(), out var cipherSuites) == ClientHelloParseErrorCode.None)
		{
			context.Items[ContextKeyName] = cipherSuites;
		}
	}

	public static ClientHelloParseErrorCode TryParseCipherSuits
	(
		ReadOnlySpan<Byte> bytes,
		out IReadOnlyCollection<TlsCipherSuite>? supportedCipherSuites
	)
	{
		supportedCipherSuites = null;

		ClientHelloParseErrorCode errorCode;

		errorCode = TryParseAsRecordWithHandshake(bytes, out var handshake);

		if (errorCode != ClientHelloParseErrorCode.None)
		{
			return errorCode;
		}

		errorCode = TryParseAsHandshakeWithtClientHello(handshake, out var clientHello);

		if (errorCode != ClientHelloParseErrorCode.None)
		{
			return errorCode;
		}

		if (!TryGetCipherSuites(clientHello, out var cipherSuites))
		{
			return ClientHelloParseErrorCode.None;
		}

		supportedCipherSuites = cipherSuites;
		return ClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a TLS record containing a handshake message,
	/// and extracts the Handshake bytes if successful.
	/// </summary>
	/// <param name="data">The bytes that should represen the <c>TLSPlaintext</c> struct.</param>
	/// <param name="handshakePayload">The bytes that should represent the <c>Handshake</c> struct.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryParseAsRecordWithHandshake
	(
		ReadOnlySpan<Byte> data,
		out ReadOnlySpan<Byte> handshakePayload
	)
	{
		// Basic sanity check
		if (data.IsEmpty)
		{
			handshakePayload = null;
			return ClientHelloParseErrorCode.DataIsEmpty;
		}

		// Check that data length enough to contain valid TLSPlaintext
		if (data.Length < RecordHeaderSize)
		{
			handshakePayload = null;
			return ClientHelloParseErrorCode.DataLengthIsLessThanRequiredByPlaintext;
		}

		// The first byte of a TLS record indicates the content type
		// for a ClientHello message it must be 'handshake'.
		// as defined in https://www.rfc-editor.org/rfc/rfc8446#section-5.1
		if (data[0] != ContentType_Handshake)
		{
			handshakePayload = null;
			return ClientHelloParseErrorCode.RecordContentTypeIsNotHandshake;
		}

		// The length field of the TLS record header is 2 bytes long and is located at offset 3
		// as defined in https://www.rfc-editor.org/rfc/rfc8446#section-5.1
		if (!BinaryPrimitives.TryReadUInt16BigEndian(data.Slice(3, 2), out var recordPayloadLength))
		{
			handshakePayload = null;
			return ClientHelloParseErrorCode.DataLengthIsLessThanRequiredByPlaintext;
		}

		// Check that record payload length enough to contain valid Handshake
		if (recordPayloadLength < HandshakeHeaderSize)
		{
			handshakePayload = null;
			return ClientHelloParseErrorCode.RecordPayloadLengthIsLessThanRequiredByHandshake;
		}

		// Check that data length enough to contain the full TLS record with the declared payload length
		if (data.Length < RecordHeaderSize + recordPayloadLength)
		{
			handshakePayload = null;
			return ClientHelloParseErrorCode.DataLengthIsLessThanRequiredToContainPayload;
		}

		handshakePayload = data.Slice(RecordHeaderSize, recordPayloadLength);
		return ClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a TLS handshake message containing a ClientHello,
	/// and extracts the ClientHello bytes if successful.
	/// </summary>
	/// <param name="handshakePayload">The bytes that should represent the <c>Handshake</c> struct.</param>
	/// <param name="clientHello">The bytes that should represent the <c>ClientHello</c> struct.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	private static ClientHelloParseErrorCode TryParseAsHandshakeWithtClientHello
	(
		ReadOnlySpan<Byte> handshakePayload,
		out ReadOnlySpan<Byte> clientHello
	)
	{
		// The first byte of a Handshake struct indicates the content type
		// as defined in https://www.rfc-editor.org/rfc/rfc8446#section-4
		if (handshakePayload[0] != HandshakeType_ClientHello)
		{
			clientHello = null;
			return ClientHelloParseErrorCode.HandshakeTypeIsNotClientHello;
		}

		// The length field of the Handshake struct is 3 bytes long
		// as defined in https://www.rfc-editor.org/rfc/rfc8446#section-4
		var clientHelloLength = ReadUInt24BigEndian(handshakePayload.Slice(1, 3));

		// Check that data length enough to contains the full ClientHello body
		if (handshakePayload.Length < HandshakeHeaderSize + clientHelloLength)
		{
			clientHello = null;
			return ClientHelloParseErrorCode.HandshakeLengthIsLessThanRequiredToContainClientHello;
		}

		clientHello = handshakePayload.Slice(HandshakeHeaderSize, clientHelloLength);
		return ClientHelloParseErrorCode.None;
	}

	private static Boolean TryGetCipherSuites
	(
		ReadOnlySpan<Byte> clientHello,
		out IReadOnlyCollection<TlsCipherSuite> cipherSuites
	)
	{
		cipherSuites = [];

		var offset = ProtocolVersionSize + RandomSize;
		if (clientHello.Length <= offset)
		{
			return false;
		}

		var sessionIdLength = clientHello[offset];
		offset += 1 + sessionIdLength;

		if (clientHello.Length < offset + sizeof(UInt16))
		{
			return false;
		}

		var cipherSuitesLength = BinaryPrimitives.ReadUInt16BigEndian(clientHello.Slice(offset, sizeof(UInt16)));
		offset += sizeof(UInt16);

		if (cipherSuitesLength == 0 || (cipherSuitesLength % 2) != 0)
		{
			return false;
		}

		if (clientHello.Length < offset + cipherSuitesLength)
		{
			return false;
		}

		var suites = new List<TlsCipherSuite>(cipherSuitesLength / 2);
		var suitesBuffer = clientHello.Slice(offset, cipherSuitesLength);

		for (var i = 0; i < suitesBuffer.Length; i += 2)
		{
			var suite = BinaryPrimitives.ReadUInt16BigEndian(suitesBuffer.Slice(i, 2));
			suites.Add((TlsCipherSuite) suite);
		}

		cipherSuites = suites;
		return true;
	}

	/// <summary>
	/// Reads a UInt24 from the beginning of a read-only span of bytes, as big endian and returns it as <see cref="UInt32"/>.
	/// </summary>
	/// <remarks>
	/// Reads exactly 3 bytes from the beginning of the span.
	/// </remarks>
	/// <param name="source">The read-only span to read.</param>
	/// <returns>The big endian value.</returns>
	/// <exception cref="ArgumentOutOfRangeException">Thrown when the source span is too small to contain a UInt24 value.</exception>
	private static Int32 ReadUInt24BigEndian
	(
		ReadOnlySpan<Byte> source
	)
	{
		if (source.Length < 3)
		{
			throw new ArgumentOutOfRangeException(nameof(source), "is too small to contain a UInt24 value.");
		}

		return (source[0] << 16) | (source[1] << 8) | source[2];
	}
}