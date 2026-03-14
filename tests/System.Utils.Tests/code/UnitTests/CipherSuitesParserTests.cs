// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Utils.UnitTests;

using System.Buffers;
using System.Net.Security;
using System.Security.Cryptography;

// Contains tests for parsing TLS ClientHello cipher suites from raw record bytes.

[TestClass]
public sealed class CipherSuitesParserTests
{
	#region Test Methods: Data Layer

	[TestMethod]
	public void TryParse_Fail_If_Data_IsEmpty()
	{
		var data = ReadOnlySequence<Byte>.Empty;

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.DataIsEmpty, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_Fail_If_Data_LengthIsInvalid()
	{
		var data = new ReadOnlySequence<Byte>(new Byte[4]);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.DataLengthIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	#endregion

	#region Test Methods: Record Layer

	[TestMethod]
	public void TryParse_Fail_If_RecordField_Type_ValueIsNotHandshake()
	{
		var record = CreateTLSPlaintext(0, 0x0303, 0, []);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.RecordField_Type_ValueIsNotHandshake, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_Fail_If_RecordField_Length_ValueIsLess()
	{
		// Minimum valid handshake length is 4 bytes for the handshake header, so declare less than that.
		var record = CreateTLSPlaintext(0x16, 0x0303, 3, []);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.RecordField_Length_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_Fail_If_RecordField_Length_ValueIsGreater()
	{
		// Handshake header is 4 bytes, so declare length greater than actual payload to trigger length validation failure.
		var record = CreateTLSPlaintext(0x16, 0x0303, 5, new Byte[4]);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.RecordField_Length_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	#endregion

	#region Test Methods: Handshake Layer

	[TestMethod]
	public void TryParse_Fail_If_HandshakeField_MessageType_ValueIsNotClientHello()
	{
		// Create a handshake with msg_type set to 0x02 (server_hello) instead of 0x01 (client_hello).
		var handshake = CreateHandshake(0x02, 0, []);
		var record = CreateTLSPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.HandshakeField_MessageType_ValueIsNotClientHello, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_Fail_If_HandshakeField_Length_ValueIsLessThanMinimumClientHello()
	{
		// Minimum valid ClientHello length is 49 bytes
		var handshake = CreateHandshake(0x01, 48, []);
		var record = CreateTLSPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.HandshakeField_Length_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_Fail_If_HandshakeField_Length_ValueExceedsHandshakePayload()
	{
		var handshake = CreateHandshake(0x01, 50, []);
		var record = CreateTLSPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.HandshakeField_Length_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	#endregion

	#region Test Methods: ClientHello Layer

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_LegacySessionIdLength_ValueIsGreaterThan32()
	{
		var clientHello = CreateClientHello(0x0303, 33, [], 0, []);
		var handshake = CreateHandshakeWithClientHelo(clientHello);
		var record = CreateTLSPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.ClientHelloField_LegacySessionIdLength_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_CipherSuitesLength_ValueIsZero()
	{
		var clientHello = CreateClientHello(0x0303, 0, [], 0, []);
		var handshake = CreateHandshakeWithClientHelo(clientHello);
		var record = CreateTLSPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.ClientHelloField_CipherSuitesLength_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_CipherSuitesLength_ValueIsOdd()
	{
		var clientHello = CreateClientHello(0x0303, 0, [], 3, []);
		var handshake = CreateHandshakeWithClientHelo(clientHello);
		var record = CreateTLSPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.ClientHelloField_CipherSuitesLength_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_Succeed_If_ClientHello_IsValid()
	{
		var expectedCipherSuites = new TlsCipherSuite []
		{
			TlsCipherSuite.TLS_AES_128_GCM_SHA256,
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
		};

		var clientHello = CreateClientHello(expectedCipherSuites);
		var handshake = CreateHandshakeWithClientHelo(clientHello);
		var record = CreateTLSPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var actualCipherSuites);

		CollectionAssert.AreEqual(expectedCipherSuites, actualCipherSuites.ToArray());
		Assert.AreEqual(CipherSuitesParseErrorCode.None, result);
	}

	#endregion

	#region Helper Methods

	private static Byte[] CreateClientHello
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

		return CreateClientHello(0x0303, 0, [], (UInt16) cipherSuitesAsBytes.Length, cipherSuitesAsBytes);
	}

	/// <summary>
	/// Builds ClientHello structure as bytes.
	/// </summary>
	/// <remarks>ClientHello struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2">RFC 8446 Section 4.1.2</see>.</remarks>

	private static Byte[] CreateClientHello
	(
		UInt16 legacy_version,
		Byte legacy_session_id_length,
		Byte[] legacy_session_id_data,
		UInt16 cipher_suites_length,
		Byte[] cipher_suites
	)
	{
		// Allocate enough for declared lengths, with minimum valid ClientHello body size.
		var clientHelloLength = Math.Max(49, 2 + 32 + 1 + legacy_session_id_data.Length + 2 + cipher_suites.Length);
		var result = new Byte[clientHelloLength];

		var position = 0;

		// ClientHello.legacy_version
		result[position++] = (Byte) (legacy_version >> 8);
		result[position++] = (Byte) legacy_version;

		// ClientHello.random
		var random = RandomNumberGenerator.GetBytes(32);
		Buffer.BlockCopy(random, 0, result, position, random.Length);
		position += random.Length;

		// ClientHello.legacy_session_id.length
		result[position++] = legacy_session_id_length;

		// ClientHello.legacy_session_id.data
		Buffer.BlockCopy(legacy_session_id_data, 0, result, position, legacy_session_id_data.Length);
		position += legacy_session_id_data.Length;

		// ClientHello.cipher_suites.length
		result[position++] = (Byte) (cipher_suites_length >> 8);
		result[position++] = (Byte) cipher_suites_length;

		// ClientHello.cipher_suites.data
		Buffer.BlockCopy(cipher_suites, 0, result, position, cipher_suites.Length);

		return result;
	}

	/// <summary>
	/// Builds Handshake structure bytes with controllable ClientHello body length.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4.1">RFC 8446 Section 4.1</see>.</remarks>
	/// <param name="clientHello">The ClientHello body bytes to place in the Handshake message body.</param>
	/// <returns>Complete Handshake bytes with ClientHello as the message body.</returns>
	private static Byte[] CreateHandshakeWithClientHelo
	(
		Byte[] clientHello
	)
	{
		// Return complete handshake bytes.
		return CreateHandshake(0x01, (UInt32) clientHello.Length, clientHello);
	}

	/// <summary>
	/// Builds Handshake structure as bytes.
	/// </summary>
	/// <remarks>Handshake struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-4">RFC 8446 Section 4</see>.</remarks>
	/// <param name="msg_type">Handshake.msg_type field value.</param>
	/// <param name="length">Handshake.length field value.</param>
	/// <param name="message">Bytes to place in the Handshake message body.</param>
	/// <returns>Complete Handshake bytes ready for wrapping into a TLS record.</returns>
	private static Byte[] CreateHandshake
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
	/// Builds TLSPlaintext record with Handshake payload record.
	/// </summary>
	/// <remarks>TLSPlaintext struct defined in <see href="https://www.rfc-editor.org/rfc/rfc8446#section-5.1">RFC 8446 Section 5.1</see>.</remarks>
	/// <param name="handshake">Handshake bytes to place in the record payload.</param>
	/// <param name="overrideLength">If specified, overrides the TLSPlaintext.length field with this value instead of the actual handshake length.</param>
	/// <param name="overrideType">If specified, overrides the TLSPlaintext.type field with this value instead of the default handshake type (0x16).</param>
	/// <returns>Complete TLSPlaintext record bytes ready for parsing.</returns>
	private static Byte[] CreateTLSPlaintextWithHandshake
	(
		Byte[] handshake,
		UInt16? overrideLength = null,
		Byte? overrideType = null
	)
	{
		var type = overrideType ?? 0x16; // Default to handshake content type
		var length = overrideLength ?? (UInt16)handshake.Length;

		// Return complete TLSPlaintext record
		return CreateTLSPlaintext(type, 0x0303, length, handshake);
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
	private static Byte[] CreateTLSPlaintext
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

	#endregion
}
