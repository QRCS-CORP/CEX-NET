#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// An MPKCS One Time Sign (OTS) message sign and verify implementation.
    /// <para>Sign: uses the specified digest to hash a message; the hash value is then encrypted with a McEliece public key.
    /// Verify: decrypts the McEliece cipher text, and then compares the value to a hash of the message.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of using the signing and verifying an array:</description>
    /// <code>
    /// MPKCParameters ps = MPKCParamSets.MPKCFM11T40S256;
    /// MPKCKeyGenerator gen = new MPKCKeyGenerator(ps);
    /// IAsymmetricKeyPair kp = gen.GenerateKeyPair();
    /// byte[] code;
    /// byte[] data = new byte[100];
    ///
    /// // get the message code for an array of bytes
    /// using (MPKCSign sgn = new MPKCSign(ps))
    /// {
    ///     sgn.Initialize(kp.PublicKey);
    ///     code = sgn.Sign(data, 0, data.Length);
    /// }
    ///
    /// // test the message for validity
    /// using (MPKCSign sgn = new MPKCSign(ps))
    /// {
    ///     sgn.Initialize(kp.PrivateKey);
    ///     bool valid = sgn.Verify(data, 0, data.Length, code);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.AsymmetricEngines">VTDev.Libraries.CEXEngine.Crypto AsymmetricEngines Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCPublicKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece MPKCPublicKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCPrivateKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece MPKCPrivateKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKeyPair Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKey Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Signing is intended as a one time only key implementation (OTS); keys should never be re-used.</description></item>
    /// <item><description>Uses the McEliece CCA2 variants; Fujisaki, KobriImai, or PointCheval ciphers.</description></item>
    /// <item><description>Digests can be any of the implemented digests; Blake, Keccak, SHA-2 or Skein.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MPKCSign : IAsymmetricSign
    {
        #region Constants
        private const string ALG_NAME = "MPKCSign";
        #endregion

        #region Fields
        private IAsymmetricKey _asmKey;
        private IMPKCCiphers _asyCipher;
        private IDigest _dgtEngine;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The cipher has been initialized with a key
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
        }

        /// <summary>
        /// Get: This class is initialized for Signing with the Public key
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if cipher has not been initialized</exception>
        public bool IsSigner
        {
            get
            {
                if (!_isInitialized)
                    throw new CryptoAsymmetricException("MPKCSign:IsSigner", "The signer has not been initialized!", new InvalidOperationException());

                return (_asmKey is MPKCPublicKey);
            }
        }

        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized</exception>
        public int MaxPlainText
        {
            get 
            { 
                if (!_isInitialized)
                    throw new CryptoAsymmetricException("MPKCSign:MaxPlainText", "The signer has not been initialized!", new InvalidOperationException());

                if (_asmKey is MPKCPublicKey)
                    return ((MPKCPublicKey)_asmKey).K >> 3; 
                else
                    return ((MPKCPrivateKey)_asmKey).K >> 3; 
            }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CipherParams">The McEliece cipher used to encrypt the hash</param>
        /// <param name="Digest">The type of digest engine used</param>
        public MPKCSign(MPKCParameters CipherParams, Digests Digest = Digests.SHA512)
        {
            _dgtEngine = GetDigest(CipherParams.Digest);
            _asyCipher = GetEngine(CipherParams);
        }

        private MPKCSign()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCSign()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the cipher
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the McEliece Public (Sign) or Private (Verify) key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid keypair is used</exception>
        public void Initialize(IAsymmetricKey AsmKey)
        {
            if (!(AsmKey is MPKCPublicKey) && !(AsmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricException("MPKCSign:Initialize", "The key is not a valid RNBW key!", new InvalidDataException());

            Reset();
            _asmKey = AsmKey;
            _isInitialized = true;
        }

        /// <summary>
        /// Reset the underlying digest engine
        /// </summary>
        public void Reset()
        {
            _dgtEngine.Reset();
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized or the key is invalid</exception>
        public byte[] Sign(Stream InputStream)
        {
            if (!_isInitialized)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (_asmKey == null)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The public key is invalid!", new InvalidDataException());
            if (!(_asmKey is MPKCPublicKey))
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The public key is invalid!", new InvalidDataException());

            _asyCipher.Initialize(_asmKey);

            if (_asyCipher.MaxPlainText < _dgtEngine.DigestSize)
                throw new CryptoAsymmetricException("MPKCSign:Sign", string.Format("The key size is too small; key supports encrypting up to {0} bytes!", _asyCipher.MaxPlainText), new ArgumentOutOfRangeException());

            byte[] hash = Compute(InputStream);

            return _asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="Input">The byte array contining the data</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized, the length is out of range, or the key is invalid</exception>
        public byte[] Sign(byte[] Input, int Offset, int Length)
        {
            if (Input.Length - Offset < Length)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The input array is too short!", new ArgumentOutOfRangeException());
            if (!_isInitialized)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (_asmKey == null)
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The public key is invalid!", new InvalidDataException());
            if (!(_asmKey is MPKCPublicKey))
                throw new CryptoAsymmetricException("MPKCSign:Sign", "The public key is invalid!", new InvalidDataException());

            _asyCipher.Initialize(_asmKey);

            if (_asyCipher.MaxPlainText < _dgtEngine.DigestSize)
                throw new CryptoAsymmetricException("MPKCSign:Sign", string.Format("The key size is too small; key supports encrypting up to {0} bytes!", _asyCipher.MaxPlainText), new ArgumentException());

            byte[] hash = Compute(Input, Offset, Length);

            return _asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data to test</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized, or the key is invalid</exception>
        public bool Verify(Stream InputStream, byte[] Code)
        {
            if (!_isInitialized)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (_asmKey == null)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The private key is invalid!", new InvalidDataException());
            if (!(_asmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The private key is invalid!", new InvalidDataException());

            _asyCipher.Initialize(_asmKey);
            byte[] chksum = _asyCipher.Decrypt(Code);
            byte[] hash = Compute(InputStream);

            return Compare.IsEqual(hash, chksum);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="Input">The stream containing the data to test</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the signer is not initialized, or the key is invalid</exception>
        public bool Verify(byte[] Input, int Offset, int Length, byte[] Code)
        {
            if (Input.Length - Offset < Length)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The input array is too short!", new ArgumentOutOfRangeException());
            if (!_isInitialized)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (_asmKey == null)
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The private key is invalid!", new InvalidDataException());
            if (!(_asmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricException("MPKCSign:Verify", "The private key is invalid!", new InvalidDataException());

            _asyCipher.Initialize(_asmKey);
            byte[] chksum = _asyCipher.Decrypt(Code);
            byte[] hash = Compute(Input, Offset, Length);

            return Compare.IsEqual(hash, chksum);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Compute the hash from a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The input stream</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(Stream InputStream)
        {
            int length = (int)(InputStream.Length - InputStream.Position);
            int blockSize = _dgtEngine.BlockSize < length ? length : _dgtEngine.BlockSize;
            int bytesRead = 0;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                bytesRead = InputStream.Read(buffer, 0, blockSize);
                _dgtEngine.BlockUpdate(buffer, 0, bytesRead);
                bytesTotal += bytesRead;
            }

            // last block
            if (bytesTotal < length)
            {
                buffer = new byte[length - bytesTotal];
                bytesRead = InputStream.Read(buffer, 0, buffer.Length);
                _dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
                bytesTotal += buffer.Length;
            }

            byte[] hash = new byte[_dgtEngine.DigestSize];
            _dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Compute the hash from a byte array
        /// </summary>
        /// 
        /// <param name="Input">The data byte array</param>
        /// <param name="Offset">The starting offset within the array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(byte[] Input, int Offset, int Length)
        {
            if (Length < Input.Length - Offset)
                throw new ArgumentOutOfRangeException();

            int blockSize = _dgtEngine.BlockSize < Length ? Length : _dgtEngine.BlockSize;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = Length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, blockSize);
                _dgtEngine.BlockUpdate(buffer, 0, blockSize);
                bytesTotal += blockSize;
            }

            // last block
            if (bytesTotal < Length)
            {
                buffer = new byte[Length - bytesTotal];
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, Math.Min(buffer.Length, Input.Length - bytesTotal));
                _dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
            }

            byte[] hash = new byte[_dgtEngine.DigestSize];
            _dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="DigestType">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the digest is unrecognized or unsupported</exception>
        private IDigest GetDigest(Digests DigestType)
        {
            try
            {
                return DigestFromName.GetInstance(DigestType);
            }
            catch
            {
                throw new CryptoAsymmetricException("MPKCSign:GetDigest", "The digest is unrecognized or unsupported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="CipherParams">The engine type</param>
        /// 
        /// <returns>An initialized cipher</returns>
        private IMPKCCiphers GetEngine(MPKCParameters CipherParams)
        {
            switch (CipherParams.CCA2Engine)
            {
                case CCA2Ciphers.KobaraImai:
                    return new KobaraImaiCipher(CipherParams);
                case CCA2Ciphers.Pointcheval:
                    return new PointchevalCipher(CipherParams);
                default:
                    return new FujisakiCipher(CipherParams);
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_dgtEngine != null)
                    {
                        _dgtEngine.Dispose();
                        _dgtEngine = null;
                    }
                    if (_asyCipher != null)
                    {
                        _asyCipher.Dispose();
                        _asyCipher = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
