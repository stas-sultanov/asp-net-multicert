// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Utils.UnitTests;

using System.Buffers;
using System.Net.Security;

/// <summary>
/// Unit tests for <see cref="TlsClientHelloParser"/> class.
/// </summary>
[TestClass]
public sealed class TlsClientHelloParserTests
{
	#region Test Methods: Fail on Data

	[TestMethod]
	public void TryParse_Fail_If_Data_IsEmpty()
	{
		// Data is empty to trigger validation failure.
		var data = ReadOnlySequence<Byte>.Empty;
		var expectedErrorCode = TlsClientHelloParseErrorCode.Data_IsEmpty;

		TestTryParseData(data, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_Data_LengthIsInvalid()
	{
		// Data length must be at least 5 bytes to contain a valid TLS record, so use 4 bytes.
		var data = new ReadOnlySequence<Byte>(new Byte[4]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Data_LengthIsInvalid;

		TestTryParseData(data, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on TLSPlaintext

	[TestMethod]
	public void TryParse_Fail_If_TLSPlaintextField_Type_ValueIsNotHandshake()
	{
		// Content type must be 0x16 (handshake), so use 0 to trigger validation failure.
		var record = TlsHelper.BuildTLSPlaintext(0, 0, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.TLSPlaintextField_Type_ValueIsNotHandshake;

		TestTryParseRecord(record, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_TLSPlaintextField_Length_ValueIsLess()
	{
		// Minimum valid handshake length is 4 bytes for the handshake header, so declare less than that.
		var record = TlsHelper.BuildTLSPlaintext(0x16, 3, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.TLSPlaintextField_Length_ValueIsInvalid;

		TestTryParseRecord(record, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_TLSPlaintextField_Length_ValueIsGreater()
	{
		// Handshake header is 4 bytes, so declare length greater than actual payload to trigger length validation failure.
		var record = TlsHelper.BuildTLSPlaintext(0x16, 5, new Byte[4]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.TLSPlaintextField_Length_ValueIsInvalid;

		TestTryParseRecord(record, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on Handshake

	[TestMethod]
	public void TryParse_Fail_If_HandshakeField_MessageType_ValueIsNotClientHello()
	{
		// Build a handshake with msg_type set to 0x02 (server_hello) instead of 0x01 (client_hello).
		var handshake = TlsHelper.BuildHandshake(0x02, 0, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Handshake_MessageType_ValueIsNotClientHello;

		TestTryParseHandshake(handshake, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_HandshakeField_Length_ValueIsLessThanMinimumClientHello()
	{
		// Minimum valid ClientHello length is 41 bytes, so use 40 to trigger validation failure.
		var handshake = TlsHelper.BuildHandshake(0x01, 40, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Handshake_Length_ValueIsInvalid;

		TestTryParseHandshake(handshake, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_HandshakeField_Length_ValueExceedsHandshakePayload()
	{
		// Declare length of 50 bytes with empty payload to trigger length validation failure.
		var handshake = TlsHelper.BuildHandshake(0x01, 50, []);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Handshake_Length_ValueIsInvalid;

		TestTryParseHandshake(handshake, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on ClientHello

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_LegacySessionIdLength_ValueIsGreaterThan32()
	{
		// Maximum valid session ID length is 32 bytes, so use 33 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 33, [], 2, [0, 0], 1, [0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_LegacySessionIdLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_CipherSuitesLength_ValueIsZero()
	{
		// Cipher suites length must be greater than zero, so use 0 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 0, [], 0, [], 10, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_CipherSuitesLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_CipherSuitesLength_ValueIsOdd()
	{
		// Cipher suites length must be even (each suite is 2 bytes), so use 3 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 0, [], 3, [1, 2, 3], 1, [0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_CipherSuitesLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_LegacyCompressionMethodsLength_ValueIsLessThan1()
	{
		// Compression methods length must be at least 1, so use 0 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 0, [], 2, [0, 0], 0, [0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_LegacyCompressionMethodsLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_LegacyCompressionMethodsLength_ValueIsInvalid()
	{
		// Declare compression methods length of 2 with only 1 byte payload to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls12(0x0303, 0, [], 2, [0, 0], 2, [0]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_LegacyCompressionMethodsLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_ExtensionsLength_ValueIsLessThan8()
	{
		// Minimum valid extensions length is 8 bytes, so use 7 to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls13(0x0303, 0, [], 2, [0, 0], 2, [0], 7, [0, 1, 2, 3, 4, 5, 6, 7]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_ExtensionsLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloField_ExtensionsLength_ValueIsGreaterThanData()
	{
		// Declare extensions length of 9 bytes with only 8 bytes payload to trigger validation failure.
		var clientHello = TlsHelper.BuildClientHelloTls13(0x0303, 0, [], 2, [0, 0], 2, [0], 9, [0, 1, 2, 3, 4, 5, 6, 7]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.ClientHello_ExtensionsLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_ClientHelloExtensionDataLengthField_ValueIsInvalid()
	{
		// Declare extensions length of 5 bytes with only 4 bytes payload to trigger validation failure.
		var extension = TlsHelper.BuildExtension(1, 5, [0, 1, 2, 3]);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.Extension_ExtensionDataLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Fail on Signature Algorithms Extension

	[TestMethod]
	public void TryParse_Fail_If_SignatureAlgorithms_SupportedSignatureAlgorithmsLength_ValueIsZero()
	{
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(0, []);
		var extension0 = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var extension1 = TlsHelper.BuildExtension(1, 4, [0, 1, 2, 3]);
		// Include 2nd extension to overcome < 8 bytes length check
		var clientHello = TlsHelper.BuildClientHelloTls13([..extension0, ..extension1]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SignatureSchemeList_SupportedSignatureAlgorithmsLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_SignatureAlgorithms_SupportedSignatureAlgorithmsLength_ValueIsOdd()
	{
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(3, [0x0401, 0x0501]);
		var extension = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SignatureSchemeList_SupportedSignatureAlgorithmsLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_SignatureAlgorithms_SupportedSignatureAlgorithmsLength_ValueIsGreaterThanData()
	{
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(4, [0x0401]);
		var extension = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SignatureSchemeList_SupportedSignatureAlgorithmsLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	[TestMethod]
	public void TryParse_Fail_If_SignatureAlgorithms_SupportedSignatureAlgorithmsLength_ValueIsGreaterThanExtensionData_WhenFollowedByAnotherExtension()
	{
		var signatureScheme = TlsHelper.BuildSignatureSchemeList(6, [0x0401]); // declares 6 bytes, only 2 bytes of scheme data follow
		var extension0 = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var extension1 = TlsHelper.BuildExtension(0x0002, 4, [0x00, 0x00, 0x00, 0x00]);
		var clientHello = TlsHelper.BuildClientHelloTls13([..extension0, ..extension1]);
		var expectedErrorCode = TlsClientHelloParseErrorCode.SignatureSchemeList_SupportedSignatureAlgorithmsLength_ValueIsInvalid;

		TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
	}

	#endregion

	#region Test Methods: Succeed

	[TestMethod]
	public void TryParse_Succeed_If_ClientHelloTls12_IsValidWithAlgorithm()
	{
		var expectedCipherSuites = new TlsCipherSuite []
		{
			TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256
		};

		var clientHello = TlsHelper.BuildClientHelloTls12(expectedCipherSuites);

		var expectedErrorCode = TlsClientHelloParseErrorCode.None;
		TestTryParseClientHello(clientHello, expectedErrorCode, info =>
		{
			var cipherSuites = new TlsCipherSuite[info.CipherSuitesCount];
			var copyResult = info.TryCopyCipherSuites(cipherSuites);
			return cipherSuites.SequenceEqual(expectedCipherSuites);
		});
	}

	[TestMethod]
	public void TryParse_Succeed_If_ClientHelloTls13_IsValidWithSignatureAlgorithms()
	{
		var expectedAuthenticationAlgorithms = new TlsSignatureScheme[]
		{
			TlsSignatureScheme.rsa_pkcs1_sha256,
			TlsSignatureScheme.ecdsa_secp521r1_sha512
		};

		var signatureScheme = TlsHelper.BuildSignatureSchemeList(4, Array.ConvertAll(expectedAuthenticationAlgorithms, value => (UInt16) value));
		var extension = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.None;

		TestTryParseClientHello(clientHello, expectedErrorCode, info =>
		{
			var signatureSchemes = new TlsSignatureScheme[info.SignatureAlgorithmsCount];
			var copyResult = info.TryCopySignatureAlgorithms(signatureSchemes);
			return signatureSchemes.SequenceEqual(expectedAuthenticationAlgorithms);
		});
	}

	[TestMethod]
	public void TryParse_Succeed_If_ClientHelloTls13_IsValidWithSignatureAlgorithmsCert()
	{
		var expectedAuthenticationAlgorithms = new TlsSignatureScheme[]
		{
			TlsSignatureScheme.ed25519, TlsSignatureScheme.rsa_pkcs1_sha384
		};

		var signatureScheme = TlsHelper.BuildSignatureSchemeList(4, Array.ConvertAll(expectedAuthenticationAlgorithms, value => (UInt16) value));
		var extension = TlsHelper.BuildExtension(50, (UInt16) signatureScheme.Length, signatureScheme);
		var clientHello = TlsHelper.BuildClientHelloTls13(extension);
		var expectedErrorCode = TlsClientHelloParseErrorCode.None;

		TestTryParseClientHello(clientHello, expectedErrorCode, info =>
		{
			var signatureSchemesCert = new TlsSignatureScheme[info.SignatureAlgorithmsCertCount];
			var copyResult = info.TryCopySignatureAlgorithmsCert(signatureSchemesCert);
			return signatureSchemesCert.SequenceEqual(expectedAuthenticationAlgorithms);
		});
	}

	/*
			[TestMethod]
			public void TryParse_Succeed_If_ClientHelloTls13_IsValidWithAlgorithmEcdsa()
			{
				// ecdsa_secp521r1_sha512
				var signatureScheme = TlsHelper.BuildSignatureSchemeList(2, [0x0603]);

				var extension0 = TlsHelper.BuildExtension(1, 4, [0, 1, 2, 3]);

				var extension1 = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);

				// Add another extension to cover the case where signature_algorithms extension is not the first extension.
				var clientHello = TlsHelper.BuildClientHelloTls13([..extension0, ..extension1]);

				var expectedErrorCode = TlsClientHelloParseErrorCode.None;
				var expectedAuthenticationAlgorithms = TlsCertificateAuthenticationAlgorithms.ECDSA;
				TestTryParseClientHello(clientHello, expectedErrorCode, _ => true);
			}

			[TestMethod]
			public void TryParse_Succeed_If_ClientHelloTls13_IsValidWithAlgorithmEdDsa()
			{
				var expectedAuthenticationAlgorithms = TlsCertificateAuthenticationAlgorithms.EdDSA;

				// ed25519
				var signatureScheme = TlsHelper.BuildSignatureSchemeList(2, [0x0807]);

				var extension = TlsHelper.BuildExtension(0x000d, (UInt16) signatureScheme.Length, signatureScheme);

				var clientHello = TlsHelper.BuildClientHelloTls13(extension);

				TestTryParseClientHello(clientHello, TlsClientHelloParseErrorCode.None, expectedAuthenticationAlgorithms);
			}
		*/
	#endregion

	#region Helper Methods

	/// <summary>
	/// A helper method to parse ClientHello bytes.
	/// </summary>
	/// <param name="clientHello">The ClientHello bytes to parse.</param>
	/// <param name="expectedErrorCode">The expected error code from the parser.</param>
	/// <param name="isAsExpected">A function that validates the parsed TLS client hello info.</param>
	private static void TestTryParseClientHello
	(
		Byte[] clientHello,
		TlsClientHelloParseErrorCode expectedErrorCode,
		Func<TlsClientHelloInfo, Boolean> isAsExpected
	)
	{
		// 0x01 is HandshakeType.client_hello.
		var handshake = TlsHelper.BuildHandshake(0x01, (UInt32) clientHello.Length, clientHello);

		TestTryParseHandshake(handshake, expectedErrorCode, isAsExpected);
	}

	/// <summary>
	/// A helper method to parse Handshake bytes.
	/// </summary>
	/// <param name="handshake">The TLS handshake bytes to parse.</param>
	/// <param name="expectedErrorCode">The expected error code from the parser.</param>
	/// <param name="isAsExpected">A function that validates the parsed TLS client hello info.</param>
	private static void TestTryParseHandshake
	(
		Byte[] handshake,
		TlsClientHelloParseErrorCode expectedErrorCode,
		Func<TlsClientHelloInfo, Boolean> isAsExpected
	)
	{
		// 0x16 is ContentType.handshake, 0x0303 is legacy_record_version for TLS 1.2 and TLS 1.3.
		var record = TlsHelper.BuildTLSPlaintext(0x16, (UInt16) handshake.Length, handshake);

		TestTryParseRecord(record, expectedErrorCode, isAsExpected);
	}

	/// <summary>
	/// A helper method to parse TLS record bytes.
	/// </summary>
	/// <param name="record">The TLS record bytes to parse.</param>
	/// <param name="expectedErrorCode">The expected error code from the parser.</param>
	/// <param name="isAsExpected">A function that validates the parsed TLS client hello info.</param>
	private static void TestTryParseRecord
	(
		Byte[] record,
		TlsClientHelloParseErrorCode expectedErrorCode,
		Func<TlsClientHelloInfo, Boolean> isAsExpected
	)
	{
		var data = new ReadOnlySequence<Byte>(record);

		TestTryParseData(data, expectedErrorCode, isAsExpected);
	}

	/// <summary>
	/// A helper method to parse data bytes as a TLS record.
	/// </summary>
	/// <param name="data">The TLS record bytes to parse.</param>
	/// <param name="expectedErrorCode">The expected error code from the parser.</param>
	/// <param name="isAsExpected">A function that validates the parsed TLS client hello info.</param>
	private static void TestTryParseData
	(
		ReadOnlySequence<Byte> data,
		TlsClientHelloParseErrorCode expectedErrorCode,
		Func<TlsClientHelloInfo, Boolean> isAsExpected
	)
	{
		var result = TlsClientHelloParser.TryParse(data, out var info);

		Assert.AreEqual(expectedErrorCode, result);

		var asExpected = isAsExpected(info);

		Assert.IsTrue(asExpected);
	}

	#endregion
}
