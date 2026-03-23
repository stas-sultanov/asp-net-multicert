// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

/// <summary>
/// Information about the ClientHello message, passed to the certificate selection callback.
/// </summary>
public readonly ref struct TlsClientHelloInfo
{
	#region Fields

	private readonly ReadOnlySequence<Byte> cipherSuites;
	private readonly ReadOnlySequence<Byte> signatureAlgorithms;
	private readonly ReadOnlySequence<Byte> signatureAlgorithmsCert;

	#endregion

	#region Properties

	/// <summary>
	/// The number of cipher suites offered by the client in the ClientHello message.
	/// </summary>
	public Int32 CipherSuitesCount { get; }

	/// <summary>
	/// The number of signature algorithms offered by the client in the ClientHello message.
	/// </summary>
	public Int32 SignatureAlgorithmsCount { get; }

	/// <summary>
	/// The number of signature algorithms for certificates offered by the client in the ClientHello message.
	/// </summary>
	public Int32 SignatureAlgorithmsCertCount { get; }

	#endregion

	#region Constructors

	/// <summary>
	/// Initializes a new instance of the <see cref="TlsClientHelloInfo"/> struct.
	/// </summary>
	/// <param name="cipherSuites">The cipher suites offered by the client.</param>
	/// <param name="signatureAlgorithms">The signature algorithms offered by the client.</param>
	/// <param name="signatureAlgorithmsCert">The signature algorithms for certificates offered by the client.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal TlsClientHelloInfo
	(
		ReadOnlySequence<Byte> cipherSuites,
		ReadOnlySequence<Byte> signatureAlgorithms,
		ReadOnlySequence<Byte> signatureAlgorithmsCert
	)
	{
		this.cipherSuites = cipherSuites;
		this.signatureAlgorithms = signatureAlgorithms;
		this.signatureAlgorithmsCert = signatureAlgorithmsCert;

		CipherSuitesCount = (Int32) (cipherSuites.Length / 2);
		SignatureAlgorithmsCount = (Int32) (signatureAlgorithms.Length / 2);
		SignatureAlgorithmsCertCount = (Int32) (signatureAlgorithmsCert.Length / 2);
	}

	#endregion

	#region Methods

	/// <summary>
	/// The cipher suites.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Boolean TryCopyCipherSuites(Span<TlsCipherSuite> destination)
	{
		return TryCopy(cipherSuites, CipherSuitesCount, destination);
	}

	/// <summary>
	/// The signature algorithms, from the supported_signature_algorithms extension.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Boolean TryCopySignatureAlgorithms(Span<TlsSignatureScheme> destination)
	{
		return TryCopy(signatureAlgorithms, SignatureAlgorithmsCount, destination);
	}

	/// <summary>
	/// The signature algorithms, from the signature_algorithms_cert extension.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Boolean TryCopySignatureAlgorithmsCert(Span<TlsSignatureScheme> destination)
	{
		return TryCopy(signatureAlgorithmsCert, SignatureAlgorithmsCertCount, destination);
	}

	#endregion

	#region Methods : Helpers

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Boolean TryCopy<T>
	(
		in ReadOnlySequence<Byte> source,
		in Int32 sourceCount,
		Span<T> destination
	)
	where T : struct, Enum
	{
		if (destination.Length != sourceCount)
		{
			return false;
		}

		if (source.IsSingleSegment)
		{
			for (var index = 0; index < sourceCount; index++)
			{
				var sourceSlice = source.FirstSpan.Slice(index * 2, 2);

				var value = BinaryPrimitives.ReadUInt16BigEndian(sourceSlice);

				destination[index] = Unsafe.As<UInt16, T>(ref value);
			}

			return true;
		}

		var reader = new SequenceReader<Byte>(source);

		for (var index = 0; index < sourceCount; index++)
		{
			// Read each signature algorithm, 2 bytes
			if (!reader.TryReadBigEndian(out UInt16 value))
			{
				return false;
			}

			destination[index] = Unsafe.As<UInt16, T>(ref value);
		}

		return true;
	}

	#endregion
}
