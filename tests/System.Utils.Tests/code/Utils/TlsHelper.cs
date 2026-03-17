// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Utils.UnitTests;

using System.Net.Security;
using System.Security.Cryptography;

internal static class TlsHelper
{
	/// <summary>
	/// Builds TLS 1.2 ClientHello structure as bytes.
	/// </summary>
	public static Byte[] BuildClientHelloTls12
	(
		TlsCipherSuite[] cipherSuites
	)
	{
		var cipherSuitesAsBytes = new Byte[cipherSuites.Length * 2];

		for (var index = 0; index < cipherSuites.Length; index++)
		{
			var offset = index * 2;
			var suite = (UInt16) cipherSuites[index];
			cipherSuitesAsBytes[offset] = (Byte) (suite >> 8);
			cipherSuitesAsBytes[offset + 1] = (Byte) suite;
		}

		return BuildClientHelloTls12(0x0303, 0, [], (UInt16) cipherSuitesAsBytes.Length, cipherSuitesAsBytes, 1, [0]);
	}

	/// <summary>
	/// Builds TLS 1.2 ClientHello structure as bytes.
	/// </summary>
	public static Byte[] BuildClientHelloTls12
	(
		UInt16 legacy_version,
		Byte legacy_session_id_length,
		Byte[] legacy_session_id_data,
		UInt16 cipher_suites_length,
		Byte[] cipher_suites_data,
		Byte legacy_compression_methods_length,
		Byte[] legacy_compression_methods_data
	)
	{
		// Allocate enough for declared lengths, with minimum valid TLS12 ClientHello body size.
		var clientHelloLength = 2 + 32 + 1 + legacy_session_id_data.Length + 2 + cipher_suites_data.Length + 1 + legacy_compression_methods_data.Length;
		var result = new Byte[clientHelloLength];

		_ = FillClientHello(ref result, legacy_version, legacy_session_id_length, legacy_session_id_data, cipher_suites_length, cipher_suites_data, legacy_compression_methods_length, legacy_compression_methods_data);

		return result;
	}

	/// <summary>
	/// Builds TLS 1.3 ClientHello structure as bytes.
	/// </summary>
	public static Byte[] BuildClientHelloTls13
	(
		Byte[] extensions
	)
	{
		return BuildClientHelloTls13(0x0303, 0, [], 2, [0, 0], 1, [0], (UInt16) extensions.Length, extensions);
	}

	/// <summary>
	/// Builds TLS 1.3 ClientHello structure as bytes.
	/// </summary>
	public static Byte[] BuildClientHelloTls13
	(
		UInt16 legacy_version,
		Byte legacy_session_id_length,
		Byte[] legacy_session_id_data,
		UInt16 cipher_suites_length,
		Byte[] cipher_suites_data,
		Byte legacy_compression_methods_length,
		Byte[] legacy_compression_methods_data,
		UInt16 extensions_length,
		Byte[] extensions_data
	)
	{
		// Allocate enough for declared lengths, with minimum valid TLS13 ClientHello body size.
		var clientHelloLength = 2 + 32 + 1 + legacy_session_id_data.Length + 2 + cipher_suites_data.Length + 1 + legacy_compression_methods_data.Length + 2 + extensions_data.Length;
		var result = new Byte[clientHelloLength];

		var position = FillClientHello(ref result, legacy_version, legacy_session_id_length, legacy_session_id_data, cipher_suites_length, cipher_suites_data, legacy_compression_methods_length, legacy_compression_methods_data);

		// ClientHello.extensions.length
		result[position++] = (Byte) (extensions_length >> 8);
		result[position++] = (Byte) extensions_length;

		// ClientHello.extensions.data
		Buffer.BlockCopy(extensions_data, 0, result, position, extensions_data.Length);

		return result;
	}

	/// <summary>
	/// Builds extension.
	/// </summary>
	/// <param name="extensionType">Extension.extension_type field value.</param>
	/// <param name="extensionDataLength">Extension.extension_data.length field value.</param>
	/// <param name="extensionData">Bytes to place in the Extension.extension_data.</param>
	/// <returns>Complete extension bytes ready for inclusion in ClientHello.Extensions.</returns>
	public static Byte[] BuildExtension
	(
		UInt16 extensionType,
		UInt16 extensionDataLength,
		Byte[] extensionData
	)
	{
		// extension_type(2) + extension_data_length(2) + extension_data.data
		var resultLength = 4 + extensionData.Length;

		// Allocate exact extension byte array
		var result = new Byte[resultLength];

		var position = 0;

		// Extension.extension_type
		result[position++] = (Byte) (extensionType >> 8);
		result[position++] = (Byte) extensionType;

		// Extension.extension_data.length
		result[position++] = (Byte) (extensionDataLength >> 8);
		result[position++] = (Byte) extensionDataLength;

		// Extension.extension_data.data
		Buffer.BlockCopy(extensionData, 0, result, position, extensionData.Length);

		return result;
	}

	/// <summary>
	/// Builds signature_algorithms extension as bytes.
	/// </summary>
	/// <remarks>Signature Algorithms defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3">RFC 8446 Section 4.2.3</see>.</remarks>
	/// <param name="signatureSchemes">Array of SignatureScheme values to include in the extension.</param>
	/// <returns>Complete signature_algorithms extension bytes ready for inclusion in ClientHello extensions.</returns>
	public static Byte[] BuildExtensionSignatureAlgorithms
	(
		UInt16[] signatureSchemes
	)
	{
		// supported_signature_algorithms.length
		var supportedSignatureAlgorithmsLength = (UInt16) (signatureSchemes.Length * 2);

		// Extension.extension_data.length
		var extensionDataLength = 2 + supportedSignatureAlgorithmsLength;

		// extension_type(2) + extension_data_length(2) + supported_signature_algorithms_length(2) + schemes
		var resultLength = 4 + extensionDataLength;

		// Allocate exact extension byte array
		var result = new Byte[resultLength];

		var position = 0;

		// Extension.extension_type (signature_algorithms = 13)
		result[position++] = 0x00;
		result[position++] = 0x0D;

		// Extension.extension_data.length
		result[position++] = (Byte) (extensionDataLength >> 8);
		result[position++] = (Byte) extensionDataLength;

		// SignatureSchemeList.supported_signature_algorithms.length
		result[position++] = (Byte) (supportedSignatureAlgorithmsLength >> 8);
		result[position++] = (Byte) supportedSignatureAlgorithmsLength;

		// SignatureSchemeList.supported_signature_algorithms.data
		foreach (var scheme in signatureSchemes)
		{
			result[position++] = (Byte) (scheme >> 8);
			result[position++] = (Byte) scheme;
		}

		return result;
	}

	/// <summary>
	/// Builds Handshake structure as bytes.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.</remarks>
	/// <param name="msg_type">Handshake.msg_type field value.</param>
	/// <param name="length">Handshake.length field value.</param>
	/// <param name="message">Bytes to place in the Handshake message body.</param>
	/// <returns>Complete Handshake bytes ready for wrapping into a TLS record.</returns>
	public static Byte[] BuildHandshake
	(
		Byte msg_type,
		UInt32 length,
		Byte[] message
	)
	{
		// 1 byte for msg_type + 3 bytes for length + message body
		var resultLength = 4 + message.Length;

		// Allocate exact header + payload size.
		var result = new Byte[resultLength];

		// Handshake.msg_type
		result[0] = msg_type;

		// Handshake.length as 3-byte big-endian.
		result[1] = (Byte) (length >> 16);
		result[2] = (Byte) (length >> 8);
		result[3] = (Byte) length;

		// Copy message after the 4-byte handshake header.
		Buffer.BlockCopy(message, 0, result, 4, message.Length);

		// Return complete handshake bytes.
		return result;
	}

	/// <summary>
	/// Builds Handshake structure bytes with controllable ClientHello body length.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.1">RFC 8446 Section 4.1</see>.</remarks>
	/// <param name="clientHello">The ClientHello body bytes to place in the Handshake message body.</param>
	/// <returns>Complete Handshake bytes with ClientHello as the message body.</returns>
	public static Byte[] BuildHandshakeWithClientHello
	(
		Byte[] clientHello
	)
	{
		// Return complete handshake bytes.
		return BuildHandshake(0x01, (UInt32) clientHello.Length, clientHello);
	}

	/// <summary>
	/// Builds TLSPlaintext record as bytes.
	/// </summary>
	/// <remarks>TLSPlaintext struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see>.</remarks>
	/// <param name="type">TLSPlaintext.type field value.</param>
	/// <param name="legacy_record_version">TLSPlaintext.legacy_record_version field value.</param>
	/// <param name="length">TLSPlaintext.length field value.</param>
	/// <param name="payload">Bytes to place in the TLSPlaintext fragment/payload.</param>
	/// <returns>Complete TLSPlaintext record bytes ready for parsing.</returns>
	public static Byte[] BuildTLSPlaintext
	(
		Byte type,
		UInt16 legacy_record_version,
		UInt16 length,
		Byte[] payload
	)
	{
		// 1 byte for type + 2 bytes for legacy_record_version + 2 bytes for length + payload
		var resultLength = 5 + payload.Length;

		// Allocate exact TLS record byte array
		var result = new Byte[resultLength];

		// TLSPlaintext.type
		result[0] = type;

		// TLSPlaintext.legacy_record_version
		result[1] = (Byte) (legacy_record_version >> 8);
		result[2] = (Byte) legacy_record_version;

		// TLSPlaintext.length as big-endian UInt16
		result[3] = (Byte) (length >> 8);
		result[4] = (Byte) length;

		// Copy handshake payload after 5-byte record header
		Buffer.BlockCopy(payload, 0, result, 5, payload.Length);

		// Return complete TLSPlaintext record
		return result;
	}

	/// <summary>
	/// Builds TLSPlaintext record with Handshake payload record.
	/// </summary>
	/// <remarks>TLSPlaintext struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see>.</remarks>
	/// <param name="handshake">Handshake bytes to place in the record payload.</param>
	/// <param name="overrideLength">If specified, overrides the TLSPlaintext.length field with this value instead of the actual handshake length.</param>
	/// <param name="overrideType">If specified, overrides the TLSPlaintext.type field with this value instead of the default handshake type (0x16).</param>
	/// <returns>Complete TLSPlaintext record bytes ready for parsing.</returns>
	public static Byte[] BuildTlsPlaintextWithHandshake
	(
		Byte[] handshake,
		UInt16? overrideLength = null,
		Byte? overrideType = null
	)
	{
		var type = overrideType ?? 0x16; // Default to handshake content type
		var length = overrideLength ?? (UInt16) handshake.Length;

		// Return complete TLSPlaintext record
		return BuildTLSPlaintext(type, 0x0303, length, handshake);
	}

	public static Int32 FillClientHello
	(
		ref Byte[] buffer,
		UInt16 legacy_version,
		Byte legacy_session_id_length,
		Byte[] legacy_session_id_data,
		UInt16 cipher_suites_length,
		Byte[] cipher_suites_data,
		Byte legacy_compression_methods_length,
		Byte[] legacy_compression_methods_data
	)
	{
		var position = 0;

		// ClientHello.legacy_version
		buffer[position++] = (Byte) (legacy_version >> 8);
		buffer[position++] = (Byte) legacy_version;

		// ClientHello.random
		var random = RandomNumberGenerator.GetBytes(32);
		Buffer.BlockCopy(random, 0, buffer, position, random.Length);
		position += random.Length;

		// ClientHello.legacy_session_id.length
		buffer[position++] = legacy_session_id_length;

		// ClientHello.legacy_session_id.data
		Buffer.BlockCopy(legacy_session_id_data, 0, buffer, position, legacy_session_id_data.Length);
		position += legacy_session_id_data.Length;

		// ClientHello.cipher_suites.length
		buffer[position++] = (Byte) (cipher_suites_length >> 8);
		buffer[position++] = (Byte) cipher_suites_length;

		// ClientHello.cipher_suites.data
		Buffer.BlockCopy(cipher_suites_data, 0, buffer, position, cipher_suites_data.Length);
		position += cipher_suites_data.Length;

		// ClientHello.legacy_compression_methods.length
		buffer[position++] = legacy_compression_methods_length;

		// ClientHello.legacy_compression_methods.data
		Buffer.BlockCopy(legacy_compression_methods_data, 0, buffer, position, legacy_compression_methods_data.Length);
		position += legacy_compression_methods_data.Length;

		return position;
	}
}
