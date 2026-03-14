// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

/// <summary>
/// Defines error codes for the <see cref="CipherSuitesParser.TryParse"/> method.
/// </summary>
public enum CipherSuitesParseErrorCode
{
	/// <summary>
	/// No error occurred, and the cipher suites were successfully parsed from the input data.
	/// </summary>
	None = 0x0000,

	/// <summary>
	/// The input data is empty, so there is no TLS record to parse.
	/// </summary>
	DataIsEmpty = 0x0001,

	/// <summary>
	/// The input data length is invalid.
	/// </summary>
	DataLengthIsInvalid = 0x0002,

	/// <summary>
	/// An error occurred while reading the input data.
	/// </summary>
	DataReadError = 0x0003,

	/// <summary>
	/// The TLSPlaintext.length field value is invalid.
	/// </summary>
	RecordField_Length_ValueIsInvalid = 0x0111,

	/// <summary>
	/// The TLSPlaintext.type field value is not ContentType.handshake.
	/// </summary>
	RecordField_Type_ValueIsNotHandshake = 0x0122,

	/// <summary>
	/// The Handshake.msg_type field value is not HandshakeType.client_hello.
	/// </summary>
	HandshakeField_MessageType_ValueIsNotClientHello = 0x0212,

	/// <summary>
	/// The Handshake.length field value is invalid.
	/// </summary>
	HandshakeField_Length_ValueIsInvalid = 0x0221,

	/// <summary>
	/// The ClientHello.legacy_session_id.length field value is invalid.
	/// </summary>
	ClientHelloField_LegacySessionIdLength_ValueIsInvalid = 0x0311,

	/// <summary>
	/// The ClientHello.cipher_suites.length field value is invalid.
	/// </summary>
	ClientHelloField_CipherSuitesLength_ValueIsInvalid = 0x0321
}
