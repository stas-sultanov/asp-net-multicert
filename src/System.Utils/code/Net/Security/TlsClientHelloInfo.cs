// Authored by Stas Sultanov
// Copyright © Stas Sultanov

namespace System.Net.Security;

using System.Buffers;

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
	public Int64 CipherSuitesCount { get; }

	/// <summary>
	/// The number of signature algorithms offered by the client in the ClientHello message.
	/// </summary>
	public Int64 SignatureAlgorithmsCount { get; }

	/// <summary>
	/// The number of signature algorithms for certificates offered by the client in the ClientHello message.
	/// </summary>
	public Int64 SignatureAlgorithmsCertCount { get; }

	#endregion

	#region Constructors

	/// <summary>
	/// Initializes a new instance of the <see cref="TlsClientHelloInfo"/> struct.
	/// </summary>
	/// <param name="cipherSuites">The cipher suites offered by the client.</param>
	/// <param name="signatureAlgorithms">The signature algorithms offered by the client.</param>
	/// <param name="signatureAlgorithmsCert">The signature algorithms for certificates offered by the client.</param>
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

		CipherSuitesCount = cipherSuites.Length / 2;
		SignatureAlgorithmsCount = signatureAlgorithms.Length / 2;
		SignatureAlgorithmsCertCount = signatureAlgorithmsCert.Length / 2;
	}

	#endregion

	#region Methods

	/// <summary>
	/// The cipher suites offered by the client in the ClientHello message.
	/// </summary>
	public Boolean TryCopyCipherSuites(Span<TlsCipherSuite> destination)
	{
		if (destination.Length != CipherSuitesCount)
		{
			return false;
		}

		var reader = new SequenceReader<Byte>(cipherSuites);

		for (var index = 0; index < CipherSuitesCount; index++)
		{
			// Read each cipher suite, 2 bytes
			if (!reader.TryReadBigEndian(out UInt16 cipherSuite))
			{
				return false;
			}

			destination[index] = (TlsCipherSuite) cipherSuite;
		}

		return true;
	}

	/// <summary>
	/// The signature algorithms offered by the client in the ClientHello message, from the supported_signature_algorithms extension.
	/// </summary>
	public Boolean TryCopySignatureAlgorithms(Span<TlsSignatureScheme> destination)
	{
		if (destination.Length != SignatureAlgorithmsCount)
		{
			return false;
		}

		var reader = new SequenceReader<Byte>(signatureAlgorithms);

		for (var index = 0; index < SignatureAlgorithmsCount; index++)
		{
			// Read each signature algorithm, 2 bytes
			if (!reader.TryReadBigEndian(out UInt16 signatureAlgorithm))
			{
				return false;
			}

			destination[index] = (TlsSignatureScheme) signatureAlgorithm;
		}

		return true;
	}

	/// <summary>
	/// The signature algorithms offered by the client in the ClientHello message, from the signature_algorithms_cert extension.
	/// </summary>
	public Boolean TryCopySignatureAlgorithmsCert(Span<TlsSignatureScheme> destination)
	{
		if (destination.Length != SignatureAlgorithmsCertCount)
		{
			return false;
		}

		var reader = new SequenceReader<Byte>(signatureAlgorithmsCert);

		for (var index = 0; index < SignatureAlgorithmsCertCount; index++)
		{
			// Read each signature algorithm, 2 bytes
			if (!reader.TryReadBigEndian(out UInt16 signatureAlgorithm))
			{
				return false;
			}

			destination[index] = (TlsSignatureScheme) signatureAlgorithm;
		}

		return true;
	}

	#endregion
}
