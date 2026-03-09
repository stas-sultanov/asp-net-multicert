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
	DataLengthIsLessThanRequiredByPlaintext,
	/// <summary>
	/// Received data length is less than required by the TLSPlaintext struct to contain the payload.
	/// </summary>
	DataLengthIsLessThanRequiredToContainPayload,
	/// <summary>
	/// TLS record content type is not handshake.
	/// </summary>
	RecordContentTypeIsNotHandshake,
	/// <summary>
	/// TLS record payload length is less than required by the Handshake struct.
	/// </summary>
	RecordPayloadLengthIsLessThanRequiredByHandshake,
	/// <summary>
	/// Handshake message length is less than the minimum required.
	/// </summary>
	HandshakeLengthIsLessThanMinimum,
	HandshakeTypeIsNotClientHello,
	/// <summary>
	/// Handshake message length is less than required to contain the ClientHello struct.
	/// </summary>
	HandshakeLengthIsLessThanRequiredToContainClientHello,
	InvalidClientHelloBody,
	InvalidCipherSuitesLength
}
