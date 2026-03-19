// Authored by Stas Sultanov
// Copyright © Stas Sultanov

using System.Net.Security;
using System.Security.Cryptography;

internal static class TlsHelper
{
	#region Methods: Public

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
	/// Builds instance of generic Extension.
	/// </summary>
	/// <param name="extension_type">Extension.extension_type field value.</param>
	/// <param name="extension_data_length">Extension.extension_data.length field value.</param>
	/// <param name="extension_data">Extension.extension_data field value.</param>
	/// <returns>Generic Extension.</returns>
	public static Byte[] BuildExtension
	(
		UInt16 extension_type,
		UInt16 extension_data_length,
		Byte[] extension_data
	)
	{
		// extension_type(2) + extension_data_length(2) + extension_data.data
		var resultLength = 4 + extension_data.Length;

		// Allocate exact extension byte array
		var result = new Byte[resultLength];

		var position = 0;

		// Extension.extension_type
		result[position++] = (Byte) (extension_type >> 8);
		result[position++] = (Byte) extension_type;

		// Extension.extension_data.length
		result[position++] = (Byte) (extension_data_length >> 8);
		result[position++] = (Byte) extension_data_length;

		// Extension.extension_data.data
		Buffer.BlockCopy(extension_data, 0, result, position, extension_data.Length);

		return result;
	}

	/// <summary>
	/// Builds instance of Handshake struct as bytes.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.</remarks>
	/// <param name="msg_type">Handshake.msg_type field value.</param>
	/// <param name="length">Handshake.length field value.</param>
	/// <param name="message">Bytes to place in the Handshake message body.</param>
	/// <returns>Handshake struct.</returns>
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
	/// Builds instance of SignatureSchemeList struct as bytes.
	/// </summary>
	/// <remarks>SignatureSchemeList struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3">RFC 8446 Section 4.2.3</see>.</remarks>
	/// <param name="supported_signature_algorithms_length">supported_signature_algorithms.length field value.</param>
	/// <param name="supported_signature_algorithms">supported_signature_algorithms.data field value.</param>
	/// <returns>SignatureSchemeList struct.</returns>
	public static Byte[] BuildSignatureSchemeList
	(
		UInt16 supported_signature_algorithms_length,
		UInt16[] supported_signature_algorithms
	)
	{
		// Actual byte size of the scheme data.
		var length = (UInt16) (supported_signature_algorithms.Length * 2);

		// Total result size: 2-byte length field + scheme data.
		var extensionDataLength = (UInt16) (2 + length);
		var result = new Byte[extensionDataLength];

		var position = 0;

		// SignatureSchemeList.supported_signature_algorithms.length
		result[position++] = (Byte) (supported_signature_algorithms_length >> 8);
		result[position++] = (Byte) supported_signature_algorithms_length;

		// SignatureSchemeList.supported_signature_algorithms.data
		foreach (var scheme in supported_signature_algorithms)
		{
			result[position++] = (Byte) (scheme >> 8);
			result[position++] = (Byte) scheme;
		}

		return result;
	}

	/// <summary>
	/// Builds instance of TLSPlaintext struct as bytes.
	/// </summary>
	/// <remarks>TLSPlaintext struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see>.</remarks>
	/// <param name="type">TLSPlaintext.type field value.</param>
	/// <param name="length">TLSPlaintext.length field value.</param>
	/// <param name="fragment">TLSPlaintext.fragment field value.</param>
	/// <returns>TLSPlaintext struct.</returns>
	public static Byte[] BuildTLSPlaintext
	(
		Byte type,
		UInt16 length,
		Byte[] fragment
	)
	{
		// 1 byte for type + 2 bytes for legacy_record_version + 2 bytes for length + payload
		var resultLength = 5 + fragment.Length;

		// Allocate exact TLS record byte array
		var result = new Byte[resultLength];

		// TLSPlaintext.type
		result[0] = type;

		// TLSPlaintext.legacy_record_version
		result[1] = 0x03;
		result[2] = 0x03;

		// TLSPlaintext.length as big-endian UInt16
		result[3] = (Byte) (length >> 8);
		result[4] = (Byte) length;

		// Copy fragment after 5-byte record header
		Buffer.BlockCopy(fragment, 0, result, 5, fragment.Length);

		// Return complete TLSPlaintext record
		return result;
	}

	#endregion

	#region Methods: Private

	private static Int32 FillClientHello
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

	#endregion
}
