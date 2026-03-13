using System.Buffers;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Security;

namespace System.Utils.UnitTests;

// Contains tests for parsing TLS ClientHello cipher suites from raw record bytes.
[TestClass]
public sealed class CipherSuitesParserTests
{
	#region Test Methods: Data Layer

	[TestMethod]
	public void TryParse_ShouldFail_If_Data_IsEmpty()
	{
		var data = ReadOnlySequence<Byte>.Empty;

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.DataIsEmpty, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_ShouldFail_If_Data_LengthIsInvalid()
	{
		var data = new ReadOnlySequence<Byte>(new Byte[4]);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.DataLengthIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	#endregion

	#region Test Methods: Record Layer

	[TestMethod]
	public void TryParse_ShouldFail_If_RecordField_Type_ValueIsNotHandshake()
	{
		var record = CreateTLSPlaintext(0, 0x0303, 0, []);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.RecordField_Type_ValueIsNotHandshake, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_ShouldFail_If_RecordField_Length_ValueIsLess()
	{
		// Minimum valid handshake length is 4 bytes for the handshake header, so declare less than that.
		var record = CreateTLSPlaintextWithHandshake(new Byte[10], 3);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.RecordField_Length_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	[TestMethod]
	public void TryParse_ShouldFail_If_RecordField_Length_ValueIsGreater()
	{
		// Handshake header is 4 bytes, so declare length greater than actual payload to trigger length validation failure.
		var record = CreateTLSPlaintextWithHandshake(new Byte[4], 5);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.RecordField_Length_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	#endregion

	#region Test Methods: Handshake Layer

	[TestMethod]
	public void TryParse_ShouldFail_If_HandshakeField_MessageType_ValueIsNotClientHello()
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
	public void TryParse_ShouldFail_If_HandshakeField_Length_ValueIsLessThanMinimumClientHello()
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
	public void TryParse_ShouldFail_If_HandshakeField_Length_ValueExceedsHandshakePayload()
	{
		var handshake = CreateHandshake(0x01, 50, []);
		var record = CreateTLSPlaintextWithHandshake(handshake);

		var data = new ReadOnlySequence<Byte>(record);

		var result = CipherSuitesParser.TryParse(data, out var cipherSuites);

		Assert.AreEqual(CipherSuitesParseErrorCode.HandshakeField_Length_ValueIsInvalid, result);
		Assert.IsEmpty(cipherSuites);
	}

	#endregion

	#region Helper Methods

	private static Byte[] CreateMinimumValidClientHello()
	{
		var clientHello = new Byte[49];

		for (var index = 0; index < 34; index++)
		{
			clientHello[index] = 0xAA;
		}

		clientHello[34] = 0x00;
		clientHello[35] = 0x00;
		clientHello[36] = 0x02;
		clientHello[37] = 0x13;
		clientHello[38] = 0x01;

		return clientHello;
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
	/// <param name="msgType">Handshake.msg_type field value.</param>
	/// <param name="length">Handshake.length field value.</param>
	/// <param name="message">Bytes to place in the Handshake message body.</param>
	/// <returns>Complete Handshake bytes ready for wrapping into a TLS record.</returns>
	private static Byte[] CreateHandshake
	(
		Byte msgType,
		UInt32 length,
		Byte[] message
	)
	{
		// Allocate exact header + payload size.
		var handshake = new Byte[4 + message.Length];

		// Handshake.msg_type
		handshake[0] = msgType;

		// Handshake.length as 3-byte big-endian.
		handshake[1] = (Byte) (length >> 16);
		handshake[2] = (Byte) (length >> 8);
		handshake[3] = (Byte) length;

		// Copy message after the 4-byte handshake header.
		Buffer.BlockCopy(message, 0, handshake, 4, message.Length);

		// Return complete handshake bytes.
		return handshake;
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
	/// <param name="reader">The byte sequence reader containing the Handshake payload to place in the record fragment.</param>	/// <param name="type">TLSPlaintext.type field value.</param>
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
		var record = new Byte[5 + payload.Length];

		// TLSPlaintext.type
		record[0] = type;

		// TLSPlaintext.legacy_record_version
		record[1] = (Byte) (legacy_record_version >> 8);
		record[2] = (Byte) legacy_record_version;

		// TLSPlaintext.length as big-endian UInt16
		record[3] = (Byte) (length >> 8);
		record[4] = (Byte) length;

		// Copy handshake payload after 5-byte record header
		Buffer.BlockCopy(payload, 0, record, 5, payload.Length);

		// Return complete TLSPlaintext record
		return record;
	}

	#endregion
}
