using System.Buffers;
using System.Net.Security;
using System.Runtime.CompilerServices;

static class CipherSuiteParser
{
	#region Constants

	/// <summary>
	/// Computed length of <c>Handshake</c> message header in bytes.
	/// </summary>
	/// <remarks>
	/// Computed from <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see> as: <c>msg_type(1) + length(3) = 4</c>.
	/// </remarks>
	private const Int32 HandshakeHeaderSize = 4;

	/// <summary>
	/// Computed length of <c>TLSPlaintext</c> record header in bytes.
	/// </summary>
	/// <remarks>
	/// Computed from <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see> as: <c>type(1) + legacy_record_version(2) + length(2) = 5</c>.
	/// </remarks>
	private const Int32 RecordHeaderSize = 5;

	/// <summary>
	/// <c>ContentType.handshake</c> enum value as defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see>.
	/// </summary>
	private const Byte ContentTypeHandshake = 22;

	/// <summary>
	/// <c>HandshakeType.client_hello</c> enum value as defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.
	/// </summary>
	private const Byte HandshakeTypeClientHello = 1;

	/// <summary>
	/// TLS <c>ProtocolVersion</c> field length in bytes.
	/// </summary>
	private const Int32 ProtocolVersionSize = 2;

	/// <summary>
	/// ClientHello <c>Random</c> field length in bytes.
	/// </summary>
	private const Int32 RandomSize = 32;

	/// <summary>
	/// Minimum possible ClientHello body size for the fields parsed by this parser.
	/// </summary>
	private const Int32 ClientHelloHeaderSize = ProtocolVersionSize + RandomSize + 1 + sizeof(UInt16) + sizeof(UInt16);

	#endregion

	#region Public Methods

	/// <summary>
	/// Tries to parse the given bytes as a TLS ClientHello message,
	/// to extract the supported cipher suites and store them in the connection context for later use during the TLS handshake.
	/// </summary>
	/// <param name="data">The bytes that should represent the TLS ClientHello message, starting from the beginning of the TLS record.</param>
	/// <param name="cipherSuites">The output collection of cipher suites extracted from the ClientHello message, if parsing is successful; otherwise, an empty collection.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ClientHelloParseErrorCode TryParse
	(
		ReadOnlySequence<Byte> data,
		out IReadOnlyCollection<TlsCipherSuite> cipherSuites
	)
	{
		if (data.IsEmpty)
		{
			cipherSuites = [];
			return ClientHelloParseErrorCode.DataIsEmpty;
		}

		// Check length before creating Reader
		if (data.Length < RecordHeaderSize)
		{
			cipherSuites = [];
			return ClientHelloParseErrorCode.DataLengthIsLessThanRequiredByRecord;
		}

		// Create Reader
		var reader = new SequenceReader<Byte>(data);

		var result = TryParseAsRecordWithHandshake(ref reader, out var handshakeLength);

		if (result != ClientHelloParseErrorCode.None)
		{
			cipherSuites = [];
			return result;
		}

		result = TryParseAsHandshakeWithClientHello(ref reader, handshakeLength, out var clientHelloLength);

		if (result != ClientHelloParseErrorCode.None)
		{
			cipherSuites = [];
			return result;
		}

		result = TryParseAsClientHelloAndGetCipherSuites(ref reader, clientHelloLength, out cipherSuites);

		return result;
	}

	#endregion

	#region Private Methods

	/// <summary>
	/// Tries to parse the given bytes as a TLS record containing a handshake message,
	/// and extract the Handshake bytes if successful.
	/// </summary>
	/// <param name="reader">The byte sequence reader instance from which the Handshake bytes are to be read.</param>
	/// <param name="handshakeLength">The output length of the Handshake message payload as declared in the TLS record header, if parsing is successful; otherwise, zero.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryParseAsRecordWithHandshake
	(
		ref SequenceReader<Byte> reader,
		out UInt16 handshakeLength
	)
	{
		if (!reader.TryRead(out var recordContentType))
		{
			handshakeLength = 0;
			return ClientHelloParseErrorCode.RecordContentTypeReadError;
		}

		if (recordContentType != ContentTypeHandshake)
		{
			handshakeLength = 0;
			return ClientHelloParseErrorCode.RecordContentTypeIsNotHandshake;
		}

		// Skip TLSPlaintext.legacy_record_version(2)
		reader.Advance(2);

		if (!reader.TryReadBigEndian(out handshakeLength))
		{
			return ClientHelloParseErrorCode.DataLengthIsLessThanRequiredByRecord;
		}

		// Handshake length must be at least as Handshake header size to be able to contain a valid Handshake message
		if (handshakeLength < HandshakeHeaderSize)
		{
			return ClientHelloParseErrorCode.RecordPayloadLengthIsLessThanRequiredByHandshake;
		}

		// Ensure that the reader contains at least the declared payload length to be able to read the full Handshake message
		if (handshakeLength > reader.Remaining)
		{
			return ClientHelloParseErrorCode.DataLengthIsLessThanRequiredToContainPayload;
		}

		return ClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a TLS handshake message containing a ClientHello,
	/// and extract the ClientHello bytes if successful.
	/// </summary>
	/// <param name="reader">The byte sequence reader instance from which the Handshake bytes are to be read.</param>
	/// <param name="handshakeLength">The output length of the Handshake message payload as declared in the TLS record header, if parsing is successful; otherwise, zero.</param>
	/// <param name="clientHelloLength">The output length of the ClientHello message body as declared in the Handshake message header, if parsing is successful; otherwise, zero.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryParseAsHandshakeWithClientHello
	(
		ref SequenceReader<Byte> reader,
		UInt32 handshakeLength,
		out UInt32 clientHelloLength
	)
	{
		if (!reader.TryRead(out var handshakeType))
		{
			clientHelloLength = default;
			return ClientHelloParseErrorCode.HandshakeMessageTypeReadError;
		}

		if (handshakeType != HandshakeTypeClientHello)
		{
			clientHelloLength = default;
			return ClientHelloParseErrorCode.HandshakeMessageTypeIsNotClientHello;
		}

		if (!reader.TryReadBigEndian24(out clientHelloLength))
		{
			return ClientHelloParseErrorCode.HandshakeMessageLengthReadError;
		}

		if (clientHelloLength < ClientHelloHeaderSize)
		{
			return ClientHelloParseErrorCode.ClientHelloLengthIsLessThanRequired;
		}

		if (clientHelloLength > handshakeLength - HandshakeHeaderSize)
		{
			return ClientHelloParseErrorCode.HandshakeMessageLengthIsLessThanRequiredToContainClientHello;
		}

		return ClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a TLS ClientHello message,
	/// and extract the supported cipher suites if successful.
	/// </summary>
	/// <param name="reader">The byte sequence reader instance from which the Handshake bytes are to be read.</param>
	/// <param name="cipherSuites">The output collection of cipher suites extracted from the ClientHello message, if parsing is successful; otherwise, an empty collection.</param>
	/// <param name="clientHelloLength"></param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryParseAsClientHelloAndGetCipherSuites
	(
		ref SequenceReader<Byte> reader,
		UInt32 clientHelloLength,
		out IReadOnlyCollection<TlsCipherSuite> cipherSuites
	)
	{
		cipherSuites = [];
		if (reader.Remaining < (ProtocolVersionSize + RandomSize))
		{
			return ClientHelloParseErrorCode.InvalidClientHelloBody;
		}

		reader.Advance(ProtocolVersionSize + RandomSize);

		if (!reader.TryRead(out var sessionIdLength))
		{
			return ClientHelloParseErrorCode.InvalidClientHelloBody;
		}

		if (reader.Remaining < sessionIdLength)
		{
			return ClientHelloParseErrorCode.InvalidClientHelloBody;
		}

		reader.Advance(sessionIdLength);
		if (!reader.TryReadBigEndian(out UInt16 cipherSuitesLength))
		{
			return ClientHelloParseErrorCode.InvalidClientHelloBody;
		}

		if (cipherSuitesLength == 0 || (cipherSuitesLength % 2) != 0)
		{
			return ClientHelloParseErrorCode.InvalidCipherSuitesLength;
		}

		if (cipherSuitesLength > clientHelloLength - (ProtocolVersionSize + RandomSize + 1 + sessionIdLength + sizeof(UInt16)))
		{
			return ClientHelloParseErrorCode.InvalidCipherSuitesLength;
		}

		var suites = new TlsCipherSuite[cipherSuitesLength / 2];
		for (var suiteIndex = 0; suiteIndex < suites.Length; suiteIndex++)
		{
			if (!reader.TryReadBigEndian(out UInt16 suite))
			{
				return ClientHelloParseErrorCode.InvalidCipherSuitesLength;
			}

			suites[suiteIndex] = (TlsCipherSuite) suite;
		}

		cipherSuites = suites;
		return ClientHelloParseErrorCode.None;
	}

	#endregion
}