// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Buffers;

using System.Runtime.CompilerServices;

/// <summary>
/// Provides extended functionality for the <see cref="SequenceReader{T}"/> class
/// that allows reading endian-specific numeric values from binary data.
/// </summary>
internal static class SequenceReaderAdvanceExtensions
{
	/// <summary>
	/// Tries to read an <see cref="UInt16"/> as big endian.
	/// </summary>
	/// <param name="reader">The byte sequence reader instance from which the value is to be read.</param>
	/// <param name="value">When the method returns, the value read out of the byte sequence reader, as big endian.</param>
	/// <returns><c>true</c> if the read operation is successful; <c>false</c> if there isn't enough data for an <see cref="UInt16"/>.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Boolean TryReadBigEndian
	(
		ref this SequenceReader<Byte> reader,
		out UInt16 value
	)
	{
		var result = SequenceReaderExtensions.TryReadBigEndian(ref reader, out Int16 signedValue);

		value = (UInt16) signedValue;

		return result;
	}

	/// <summary>
	/// Tries to read a 24-bit unsigned integer as big-endian.
	/// </summary>
	/// <param name="reader">The byte sequence reader instance from which the value is to be read.</param>
	/// <param name="value">When the method returns, the value read out of the byte sequence reader, as big endian.</param>
	/// <returns><c>true</c> if the read operation is successful; <c>false</c> if there is not enough data for a 24-bit unsigned integer.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Boolean TryReadBigEndian24
	(
		ref this SequenceReader<Byte> reader,
		out Int32 value
	)
	{
		if (reader.TryRead(out var b0) && reader.TryRead(out var b1) && reader.TryRead(out var b2))
		{
			value = (b0 << 16) | (b1 << 8) | b2;
			return true;
		}

		value = default;
		return false;
	}
}
