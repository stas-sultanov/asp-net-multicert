// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Utils.UnitTests;

using System.Buffers;
using System.Net.Security;
using System.Security.Cryptography;

// Contains tests for parsing TLS ClientHello signature algorithms from raw record bytes.

[TestClass]
public sealed class CipherSuitesParserTests
{
	#region Test Methods: Data Layer

	[TestMethod]
	public void TryParse_Fail_If_Data_IsEmpty()
	{
		var data = ReadOnlySequence<Byte>.Empty;

		var result = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		Assert.AreEqual(ClientHelloParseErrorCode.DataIsEmpty, result);
		Assert.AreEqual(TlsSignatureAlgorithms.None, signatureAlgorithms);
	}

	[TestMethod]
	public void TryParse_Fail_If_Data_LengthIsInvalid()
	{
		var data = new ReadOnlySequence<Byte>(new Byte[4]);

		var result = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		Assert.AreEqual(ClientHelloParseErrorCode.DataLengthIsInvalid, result);
		Assert.AreEqual(TlsSignatureAlgorithms.None, signatureAlgorithms);
	}

	#endregion

	#region Test Methods: Record Layer

	[TestMethod]
	public void TryParse_Fail_If_RecordField_Type_ValueIsNotHandshake()
	{
		var record = BuildTLSPlaintext(0, 0x0303, 0, []);

		var data = new ReadOnlySequence<Byte>(record);

		var result = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		Assert.AreEqual(ClientHelloParseErrorCode.RecordField_Type_ValueIsNotHandshake, result);
		Assert.AreEqual(TlsSignatureAlgorithms.None, signatureAlgorithms);
	}

	[TestMethod]
	public void TryParse_Fail_If_RecordField_Length_ValueIsLess()
	{
		// Minimum valid handshake length is 4 bytes for the handshake header, so declare less than that.
		var record = BuildTLSPlaintext(0x16, 0x0303, 3, []);

		var data = new ReadOnlySequence<Byte>(record);

		var result = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		Assert.AreEqual(ClientHelloParseErrorCode.RecordField_Length_ValueIsInvalid, result);
		Assert.AreEqual(TlsSignatureAlgorithms.None, signatureAlgorithms);
	}

	[TestMethod]
	public void TryParse_Fail_If_RecordField_Length_ValueIsGreater()
	{
		// Handshake header is 4 bytes, so declare length greater than actual payload to trigger length validation failure.
		var record = BuildTLSPlaintext(0x16, 0x0303, 5, new Byte[4]);

		var data = new ReadOnlySequence<Byte>(record);

		var result = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		Assert.AreEqual(ClientHelloParseErrorCode.RecordField_Length_ValueIsInvalid, result);
		Assert.AreEqual(TlsSignatureAlgorithms.None, signatureAlgorithms);
	}

	#endregion

	#region Test Methods: Handshake Layer

	[TestMethod]
	public void TryParse_Fail_If_HandshakeField_MessageType_ValueIsNotClientHello()
	{
		// Build a handshake with msg_type set to 0x02 (server_hello) instead of 0x01 (client_hello).
		var handshake = BuildHandshake(0x02, 0, []);
		var record = BuildTlsPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		Assert.AreEqual(ClientHelloParseErrorCode.HandshakeField_MessageType_ValueIsNotClientHello, result);
		Assert.AreEqual(TlsSignatureAlgorithms.None, signatureAlgorithms);
	}

	[TestMethod]
	public void TryParse_Fail_If_HandshakeField_Length_ValueIsLessThanMinimumClientHello()
	{
		// Minimum valid ClientHello length is 41 bytes
		var handshake = BuildHandshake(0x01, 40, []);
		var record = BuildTlsPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		Assert.AreEqual(ClientHelloParseErrorCode.HandshakeField_Length_ValueIsInvalid, result);
		Assert.AreEqual(TlsSignatureAlgorithms.None, signatureAlgorithms);
	}

	[TestMethod]
	public void TryParse_Fail_If_HandshakeField_Length_ValueExceedsHandshakePayload()
	{
		var handshake = BuildHandshake(0x01, 50, []);
		var record = BuildTlsPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		Assert.AreEqual(ClientHelloParseErrorCode.HandshakeField_Length_ValueIsInvalid, result);
		Assert.AreEqual(TlsSignatureAlgorithms.None, signatureAlgorithms);
	}

	#endregion

	#region Test Methods: ClientHello Layer

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_LegacySessionIdLength_ValueIsGreaterThan32()
	{
		var clientHello = BuildClientHelloTls12(0x0303, 33, [], 2, [0, 0], 1, [0]);

		TryParse_ClientHelloField(clientHello, ClientHelloParseErrorCode.ClientHelloField_LegacySessionIdLength_ValueIsInvalid);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_CipherSuitesLength_ValueIsZero()
	{
		var clientHello = BuildClientHelloTls12(0x0303, 0, [], 0, [], 10, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

		TryParse_ClientHelloField(clientHello, ClientHelloParseErrorCode.ClientHelloField_CipherSuitesLength_ValueIsInvalid);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_CipherSuitesLength_ValueIsOdd()
	{
		var clientHello = BuildClientHelloTls12(0x0303, 0, [], 3, [1, 2, 3], 1, [0]);

		TryParse_ClientHelloField(clientHello, ClientHelloParseErrorCode.ClientHelloField_CipherSuitesLength_ValueIsInvalid);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_LegacyCompressionMethodsLength_ValueIsLessThan1()
	{
		var clientHello = BuildClientHelloTls12(0x0303, 0, [], 2, [0, 0], 0, [0]);

		TryParse_ClientHelloField(clientHello, ClientHelloParseErrorCode.ClientHelloField_LegacyCompressionMethodsLength_ValueIsInvalid);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_LegacyCompressionMethodsLength_ValueIsInvalid()
	{
		var clientHello = BuildClientHelloTls12(0x0303, 0, [], 2, [0, 0], 2, [0]);

		TryParse_ClientHelloField(clientHello, ClientHelloParseErrorCode.ClientHelloField_LegacyCompressionMethodsLength_ValueIsInvalid);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_ExtensionsLength_ValueIsLessThan8()
	{
		var clientHello = BuildClientHelloTls13(0x0303, 0, [], 2, [0, 0], 2, [0], 7, [0, 1, 2, 3, 4, 5, 6, 7]);

		TryParse_ClientHelloField(clientHello, ClientHelloParseErrorCode.ClientHelloField_ExtensionsLength_ValueIsInvalid);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_ExtensionsLength_ValueIsInvalid()
	{
		var clientHello = BuildClientHelloTls13(0x0303, 0, [], 2, [0, 0], 2, [0], 9, [0, 1, 2, 3, 4, 5, 6, 7]);

		TryParse_ClientHelloField(clientHello, ClientHelloParseErrorCode.ClientHelloField_ExtensionsLength_ValueIsInvalid);
	}

	[TestMethod]
	public void TryParse_Succeed_If_ClientHello_IsValidWithoutAlgorithm()
	{
		var expectedSignatureAlgorithms = TlsSignatureAlgorithms.None;

		var expectedCipherSuites = new TlsCipherSuite []
		{
			TlsCipherSuite.TLS_AES_128_GCM_SHA256
		};

		var clientHello = BuildClientHelloTls12(expectedCipherSuites);

		TryParse_ClientHelloField(clientHello, ClientHelloParseErrorCode.None, expectedSignatureAlgorithms);
	}

	#endregion

	#region Helper Methods

	/// <summary>
	/// A helper method to build TLS record bytes with controllable ClientHello body and invoke the parser, asserting expected results.
	/// </summary>
	/// <param name="clientHello">The ClientHello bytes to parse.</param>
	/// <param name="expectedErrorCode">The expected error code from the parser.</param>
	/// <param name="expectedSignatureAlgorithms">The expected signature algorithms from the parser.</param>
	private static void TryParse_ClientHelloField
	(
		Byte[] clientHello,
		ClientHelloParseErrorCode expectedErrorCode = ClientHelloParseErrorCode.None,
		TlsSignatureAlgorithms expectedSignatureAlgorithms = TlsSignatureAlgorithms.None
	)
	{
		var handshake = BuildHandshakeWithClientHelo(clientHello);
		var record = BuildTlsPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = ClientHelloParser.TryParse(data, out var signatureAlgorithms);

		Assert.AreEqual(expectedErrorCode, result);
		Assert.AreEqual(expectedSignatureAlgorithms, signatureAlgorithms);
	}

	private static Byte[] BuildClientHelloTls12
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
	/// Builds TLS12 ClientHello structure as bytes.
	/// </summary>
	private static Byte[] BuildClientHelloTls12
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
	/// Builds TLS13 ClientHello structure as bytes.
	/// </summary>
	private static Byte[] BuildClientHelloTls13
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

	/// <summary>
	/// Builds Handshake structure bytes with controllable ClientHello body length.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.1">RFC 8446 Section 4.1</see>.</remarks>
	/// <param name="clientHello">The ClientHello body bytes to place in the Handshake message body.</param>
	/// <returns>Complete Handshake bytes with ClientHello as the message body.</returns>
	private static Byte[] BuildHandshakeWithClientHelo
	(
		Byte[] clientHello
	)
	{
		// Return complete handshake bytes.
		return BuildHandshake(0x01, (UInt32) clientHello.Length, clientHello);
	}

	/// <summary>
	/// Builds Handshake structure as bytes.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.</remarks>
	/// <param name="msg_type">Handshake.msg_type field value.</param>
	/// <param name="length">Handshake.length field value.</param>
	/// <param name="message">Bytes to place in the Handshake message body.</param>
	/// <returns>Complete Handshake bytes ready for wrapping into a TLS record.</returns>
	private static Byte[] BuildHandshake
	(
		Byte msg_type,
		UInt32 length,
		Byte[] message
	)
	{
		// Allocate exact header + payload size.
		var result = new Byte[4 + message.Length];

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
	/// Builds TLSPlaintext record as bytes.
	/// </summary>
	/// <remarks>TLSPlaintext struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see>.</remarks>
	/// <param name="type">TLSPlaintext.type field value.</param>
	/// <param name="legacy_record_version">TLSPlaintext.legacy_record_version field value.</param>
	/// <param name="length">TLSPlaintext.length field value.</param>
	/// <param name="payload">Bytes to place in the TLSPlaintext fragment/payload.</param>
	/// <returns>Complete TLSPlaintext record bytes ready for parsing.</returns>
	private static Byte[] BuildTLSPlaintext
	(
		Byte type,
		UInt16 legacy_record_version,
		UInt16 length,
		Byte[] payload
	)
	{
		// Allocate exact TLS record byte array
		var result = new Byte[5 + payload.Length];

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
	private static Byte[] BuildTlsPlaintextWithHandshake
	(
		Byte[] handshake,
		UInt16? overrideLength = null,
		Byte? overrideType = null
	)
	{
		var type = overrideType ?? 0x16; // Default to handshake content type
		var length = overrideLength ?? (UInt16)handshake.Length;

		// Return complete TLSPlaintext record
		return BuildTLSPlaintext(type, 0x0303, length, handshake);
	}

	#endregion
}
