using System.Buffers;
using System.Net.Security;

using Xunit;

public sealed class CipherSuiteParserBoundaryTests
{
	[Fact]
	public void TryParse_CurrentImplementation_AllowsReadingPastDeclaredClientHelloLength_WithinOneRecord()
	{
		// Declared ClientHello length is exactly the parser's minimum accepted length (39).
		const UInt32 declaredClientHelloLength = 39;

		// Actual bytes contain a cipher_suites_length (64) that cannot fit in 39 bytes.
		// Extra suites bytes are appended after byte 39 in the same TLS record.
		var clientHello = CreateClientHelloWithDeclaredLengthOverflow();
		var handshake = CreateHandshake(clientHello, declaredClientHelloLength);
		var record = CreateTLSPlainText(handshake);

		var result = CipherSuiteParser.TryParse(new ReadOnlySequence<Byte>(record), out var cipherSuites);

		Assert.Equal(ClientHelloParseErrorCode.InvalidCipherSuitesLength, result);
		Assert.Empty(cipherSuites);
	}

	[Fact]
	public void TryParse_ShouldFail_WhenDeclaredClientHelloLengthIsTooSmallEvenIfRecordContainsEnoughBytes()
	{
		var clientHello = CreateClientHello();

		// BUG INJECTION: declared ClientHello length is 0, while body bytes still follow.
		var handshake = CreateHandshake(clientHello, declaredClientHelloLength: 0);

		var record = CreateTLSPlainText(handshake);

		var result = CipherSuiteParser.TryParse(new ReadOnlySequence<Byte>(record), out _);

		Assert.Equal(ClientHelloParseErrorCode.ClientHelloLengthIsLessThanRequired, result);
	}

	private static Byte[] CreateClientHello()
	{
		var clientHelloBody = new Byte[39];
		for (var index = 0; index < 34; index++)
		{
			clientHelloBody[index] = 0xAA;
		}

		clientHelloBody[34] = 0x00; // session_id length
		clientHelloBody[35] = 0x00; // cipher_suites length hi
		clientHelloBody[36] = 0x02; // cipher_suites length lo
		clientHelloBody[37] = 0x13; // TLS_AES_128_GCM_SHA256 hi
		clientHelloBody[38] = 0x01; // TLS_AES_128_GCM_SHA256 lo

		return clientHelloBody;
	}

	private static Byte[] CreateClientHelloWithDeclaredLengthOverflow()
	{
		var clientHelloBody = new Byte[101];

		for (var index = 0; index < 34; index++)
		{
			clientHelloBody[index] = 0xAA;
		}

		clientHelloBody[34] = 0x00; // session_id length
		clientHelloBody[35] = 0x00; // cipher_suites length hi
		clientHelloBody[36] = 0x40; // cipher_suites length lo (64)

		for (var index = 37; index < clientHelloBody.Length; index += 2)
		{
			clientHelloBody[index] = 0x13;
			clientHelloBody[index + 1] = 0x01;
		}

		return clientHelloBody;
	}

	private static Byte[] CreateHandshake(Byte[] clientHello, UInt32 declaredClientHelloLength)
	{
		var handshake = new Byte[4 + clientHello.Length];
		handshake[0] = 0x01; // handshake type client_hello
		handshake[1] = (Byte) (declaredClientHelloLength >> 16);
		handshake[2] = (Byte) (declaredClientHelloLength >> 8);
		handshake[3] = (Byte) declaredClientHelloLength;
		Buffer.BlockCopy(clientHello, 0, handshake, 4, clientHello.Length);
		return handshake;
	}

	private static Byte[] CreateTLSPlainText(Byte[] payload)
	{
		var record = new Byte[5 + payload.Length];
		record[0] = 0x16; // handshake
		record[1] = 0x03; // legacy_record_version hi
		record[2] = 0x03; // legacy_record_version lo
		record[3] = (Byte) (payload.Length >> 8);
		record[4] = (Byte) (payload.Length & 0xFF);
		Buffer.BlockCopy(payload, 0, record, 5, payload.Length);
		return record;
	}
}
