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

		var result = TryParseAsRecordWithHandshake(ref reader);

		if (result != ClientHelloParseErrorCode.None)
		{
			cipherSuites = [];
			return result;
		}

		result = TryParseAsHandshakeWithClientHello(ref reader);

		if (result != ClientHelloParseErrorCode.None)
		{
			cipherSuites = [];
			return result;
		}

		result = TryParseAsClientHelloAndGetCipherSuites(ref reader, out cipherSuites);

		return result;
	}

	#endregion

	#region Private Methods

	/// <summary>
	/// Tries to parse the given bytes as a TLS record containing a handshake message,
	/// and extract the Handshake bytes if successful.
	/// </summary>
	/// <param name="reader">The byte sequence reader instance from which the Handshake bytes are to be read.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryParseAsRecordWithHandshake
	(
		ref SequenceReader<Byte> reader
	)
	{
		if (!reader.TryRead(out var recordContentType))
		{
			return ClientHelloParseErrorCode.RecordContentTypeReadError;
		}

		if (recordContentType != ContentTypeHandshake)
		{
			return ClientHelloParseErrorCode.RecordContentTypeIsNotHandshake;
		}

		// Skip TLSPlaintext.legacy_record_version(2)
		reader.Advance(2);

		if (!reader.TryReadBigEndian(out UInt16 recordPayloadLength))
		{
			return ClientHelloParseErrorCode.DataLengthIsLessThanRequiredByRecord;
		}

		if (reader.Remaining < recordPayloadLength)
		{
			return ClientHelloParseErrorCode.DataLengthIsLessThanRequiredToContainPayload;
		}

		// Payload length must be at least as Handshake header size to be able to contain a valid Handshake message
		if (recordPayloadLength < HandshakeHeaderSize)
		{
			return ClientHelloParseErrorCode.RecordPayloadLengthIsLessThanRequiredByHandshake;
		}

		return ClientHelloParseErrorCode.None;
	}

	/// <summary>
	/// Tries to parse the given bytes as a TLS handshake message containing a ClientHello,
	/// and extract the ClientHello bytes if successful.
	/// </summary>
	/// <param name="reader">The byte sequence reader instance from which the Handshake bytes are to be read.</param>
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryParseAsHandshakeWithClientHello
	(
		ref SequenceReader<Byte> reader
	)
	{
		if (!reader.TryRead(out var handshakeType))
		{
			return ClientHelloParseErrorCode.HandshakeMessageTypeReadError;
		}

		if (handshakeType != HandshakeTypeClientHello)
		{
			return ClientHelloParseErrorCode.HandshakeMessageTypeIsNotClientHello;
		}

		if (!reader.TryReadBigEndian24(out var clientHelloLength))
		{
			return ClientHelloParseErrorCode.HandshakeMessageLengthReadError;
		}

		if (reader.Remaining < clientHelloLength)
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
	/// <returns>A <see cref="ClientHelloParseErrorCode"/> indicating the result of the operation.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ClientHelloParseErrorCode TryParseAsClientHelloAndGetCipherSuites
	(
		ref SequenceReader<Byte> reader,
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

		if (reader.Remaining < cipherSuitesLength)
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