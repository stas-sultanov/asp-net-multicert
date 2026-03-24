// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

/// <summary>
/// Defines error code groups for the <see cref="TlsClientHelloParseErrorCode"/> enum.
/// </summary>
file static class ErrorCodeGroup
{
	public const Int32 Data               = 0x0100;
	public const Int32 Record             = 0x0200;
	public const Int32 Handshake          = 0x0300;
	public const Int32 ClientHello        = 0x0400;
	public const Int32 Extension          = 0x0500;
	public const Int32 SignatureAlgorithm = 0x0600;
}

/// <summary>
/// Defines error codes for the <see cref="TlsClientHelloParser.TryParse"/> method.
/// </summary>
public enum TlsClientHelloParseErrorCode
{
	/// <summary>
	/// No error occurred.
	/// </summary>
	None = 0x0000,

	/// <summary>
	/// An error occurred while reading the data.
	/// </summary>
	ReadError = 0x0001,

	/// <summary>
	/// The input data is empty, so there is no TLS record to parse.
	/// </summary>
	Data_IsEmpty = ErrorCodeGroup.Data | 0x01,

	/// <summary>
	/// The input data length is invalid.
	/// </summary>
	Data_LengthIsInvalid = ErrorCodeGroup.Data | 0x02,

	/// <summary>
	/// The TLSPlaintext.length field value is invalid.
	/// </summary>
	TLSPlaintextField_Length_ValueIsInvalid = ErrorCodeGroup.Record | 0x01,

	/// <summary>
	/// The TLSPlaintext.type field value is not ContentType.handshake.
	/// </summary>
	TLSPlaintextField_Type_ValueIsNotHandshake = ErrorCodeGroup.Record | 0x02,

	/// <summary>
	/// The Handshake.msg_type field value is not HandshakeType.client_hello.
	/// </summary>
	Handshake_MessageType_ValueIsNotClientHello = ErrorCodeGroup.Handshake | 0x01,

	/// <summary>
	/// The Handshake.length field value is invalid.
	/// </summary>
	Handshake_Length_ValueIsInvalid = ErrorCodeGroup.Handshake | 0x02,

	/// <summary>
	/// The ClientHello.legacy_session_id.length field value is invalid.
	/// </summary>
	ClientHello_LegacySessionIdLength_ValueIsInvalid = ErrorCodeGroup.ClientHello | 0x01,

	/// <summary>
	/// The ClientHello.cipher_suites.length field value is invalid.
	/// </summary>
	ClientHello_CipherSuitesLength_ValueIsInvalid = ErrorCodeGroup.ClientHello | 0x02,

	/// <summary>
	/// The ClientHello.legacy_compression_methods.length field value is invalid.
	/// </summary>
	ClientHello_LegacyCompressionMethodsLength_ValueIsInvalid = ErrorCodeGroup.ClientHello | 0x03,

	/// <summary>
	/// The ClientHello.extensions.length field value is invalid.
	/// </summary>
	ClientHello_ExtensionsLength_ValueIsInvalid = ErrorCodeGroup.ClientHello | 0x04,

	/// <summary>
	/// The Extension.extension_data.length field value is invalid.
	/// </summary>
	Extension_ExtensionDataLength_ValueIsInvalid = ErrorCodeGroup.Extension | 0x01,

	/// <summary>
	/// The SignatureSchemeList.supported_signature_algorithms.length field value is invalid.
	/// </summary>
	SignatureSchemeList_SupportedSignatureAlgorithmsLength_ValueIsInvalid = ErrorCodeGroup.SignatureAlgorithm | 0x01
}
