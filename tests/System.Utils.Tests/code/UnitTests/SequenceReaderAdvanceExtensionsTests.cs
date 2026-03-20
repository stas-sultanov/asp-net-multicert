// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Utils.UnitTests;

using System.Buffers;

/// <summary>
/// Unit tests for <see cref="SequenceReaderExtensions"/> methods that read unsigned integers.
/// </summary>
[TestClass]
public sealed class SequenceReaderAdvanceExtensionsTests
{
	#region Test Methods: TryReadBigEndian

	[TestMethod]
	public void TryReadBigEndian_ShouldNotLoseData_WhenSignedValueIsConvertedToUInt16()
	{
		// 0x8001 is negative as Int16, so this verifies the extension does not lose bits when converting to UInt16.
		var data = new ReadOnlySequence<Byte>([0x80, 0x01]);
		var reader = new SequenceReader<Byte>(data);

		var result = reader.TryReadBigEndian(out UInt16 value);

		Assert.IsTrue(result);
		Assert.AreEqual((UInt16) 0x8001, value);
		Assert.AreEqual(0, reader.Remaining);
	}

	#endregion

	#region Test Methods: TryReadBigEndian24

	[TestMethod]
	public void TryReadBigEndian24_Fail_IfDataLengthIs0()
	{
		var data = new ReadOnlySequence<Byte>([]);
		var reader = new SequenceReader<Byte>(data);

		var result = reader.TryReadBigEndian24(out var _);

		Assert.IsFalse(result);
		Assert.AreEqual(0, reader.Remaining);
	}

	[TestMethod]
	public void TryReadBigEndian24_Fail_IfDataLengthIs1()
	{
		var data = new ReadOnlySequence<Byte>([1]);
		var reader = new SequenceReader<Byte>(data);

		var result = reader.TryReadBigEndian24(out var _);

		Assert.IsFalse(result);
		Assert.AreEqual(0, reader.Remaining);
	}

	[TestMethod]
	public void TryReadBigEndian24_Fail_IfDataLengthIs2()
	{
		var data = new ReadOnlySequence<Byte>([1, 2]);
		var reader = new SequenceReader<Byte>(data);

		var result = reader.TryReadBigEndian24(out var _);

		Assert.IsFalse(result);
		Assert.AreEqual(0, reader.Remaining);
	}

	[TestMethod]
	public void TryReadBigEndian24_Succeed_WhenEnoughData()
	{
		var expectedValue = 0x123456;

		var data = new ReadOnlySequence<Byte>
		(
			[
				(Byte) (expectedValue >> 16),
				(Byte) ((expectedValue >> 8) & 0xFF),
				(Byte) (expectedValue & 0xFF),
				0x00FF
			]
		);
		var reader = new SequenceReader<Byte>(data);

		var result = reader.TryReadBigEndian24(out var actualValue);

		Assert.IsTrue(result);
		Assert.AreEqual(expectedValue, actualValue);
		Assert.AreEqual(1, reader.Remaining);
	}

	#endregion
}
