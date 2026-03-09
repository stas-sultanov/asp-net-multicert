enum ClientHelloParseErrorCode
{
	None = 0,
	/// <summary>
	/// Received data is empty, no TLS record to parse.
	/// </summary>
	DataIsEmpty,
	/// <summary>
	/// Received data length is less than required by the TLSPlaintext struct.
	/// </summary>
	DataLengthIsLessThanRequiredByRecord,
	/// <summary>
	/// Received data length is less than required by the TLSPlaintext struct to contain the payload.
	/// </summary>
	DataLengthIsLessThanRequiredToContainPayload,
	/// <summary>
	/// TLS record content type is not handshake.
	/// </summary>
	RecordContentTypeIsNotHandshake,
	/// <summary>
	/// Error occurred while reading the TLS record content type.
	/// </summary>
	RecordContentTypeReadError,
	/// <summary>
	/// TLS record payload length is less than required by the Handshake struct.
	/// </summary>
	RecordPayloadLengthIsLessThanRequiredByHandshake,
	/// <summary>
	/// Error occurred while reading the Handshake message type.
	/// </summary>
	HandshakeMessageTypeReadError,
	/// <summary>
	/// Handshake message type is not ClientHello.
	/// </summary>
	HandshakeMessageTypeIsNotClientHello,
	/// <summary>
	/// Error occurred while reading the Handshake message length.
	/// </summary>
	HandshakeMessageLengthReadError,
	/// <summary>
	/// Handshake message length is less than required to contain the ClientHello struct.
	/// </summary>
	HandshakeMessageLengthIsLessThanRequiredToContainClientHello,
	/// <summary>
	/// ClientHello length is less than required to contain the cipher suites.
	/// </summary>
	ClientHelloLengthIsLessThanRequired,
	/// <summary>
	/// ClientHello body does not contain required fields at expected offsets.
	/// </summary>
	InvalidClientHelloBody,
	/// <summary>
	/// Cipher suites vector length is invalid.
	/// </summary>
	InvalidCipherSuitesLength
}
