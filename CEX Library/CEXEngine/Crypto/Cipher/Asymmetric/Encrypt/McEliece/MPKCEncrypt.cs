#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// A McEliece CCA2 Secure asymmetric cipher implementation
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of encrypting and decrypting an array:</description>
    /// <code>
    /// MPKCParameters ps = MPKCParamSets.MPKCFM11T40S256;
    /// MPKCKeyGenerator gen = new MPKCKeyGenerator(ps);
    /// IAsymmetricKeyPair kp = gen.GenerateKeyPair();
    /// 
    /// byte[] data = new byte[48];
    /// byte[] enc, dec;
    /// 
    /// // encrypt an array
    /// using (MPKCEncrypt cipher = new MPKCEncrypt(ps))
    /// {
    ///     cipher.Initialize(kp.PublicKey);
    ///     enc = cipher.Encrypt(data);
    /// }
    /// 
    /// // decrypt the cipher text
    /// using (MPKCEncrypt cipher = new MPKCEncrypt(ps))
    /// {
    ///     cipher.Initialize(kp.PrivateKey);
    ///     dec = cipher.Decrypt(enc);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.AsymmetricEngines">VTDev.Libraries.CEXEngine.Crypto.Enumeration AsymmetricEngines Enumeration</seealso>
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
    /// <item><description>Uses the McEliece CCA2 variants; Fujisaki, KobriImai, or PointCheval ciphers.</description></item>
    /// <item><description>Use the MaxPlainText property to get max input size post initialization.</description></item>
    /// <item><description>The MaxCipherText property gives the max allowable ciphertext size post initialization.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>McEliece Handbook of Applied Cryptography: Chapter 8<cite>McEliece Handbook of Applied Cryptography</cite>.</description></item>
    /// <item><description>Selecting Parameters for Secure McEliece-based Cryptosystems<cite>McEliece Parameters</cite>.</description></item>
    /// <item><description>Weak keys in the McEliece public-key cryptosystem<cite>McEliece Weak keys</cite>.</description></item>
    /// <item><description>McBits: fast constant-time code-based cryptography<cite>McEliece McBits</cite>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> versions McEliece implementation.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MPKCEncrypt : IAsymmetricCipher
    {
        #region Constants
        private const string ALG_NAME = "MPKCEncrypt";
        #endregion

        #region Fields
        private IMPKCCiphers _encEngine;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isInitialized = false;
        private int _maxPlainText;
        private int _maxCipherText;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The cipher is initialized for encryption
        /// </summary>
        public bool IsEncryption
        {
            get 
            {
                if (!_isInitialized)
                    throw new CryptoAsymmetricException("MPKCEncrypt:IsEncryption", "The cipher must be initialized before state can be determined!", new InvalidOperationException());

                return _isEncryption; 
            }
        }

        /// <summary>
        /// Get: The cipher has been initialized with a key
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
        }

        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized</exception>
        public int MaxCipherText
        {
            get
            {
                if (_maxCipherText == 0 || !_isInitialized)
                    throw new CryptoAsymmetricException("MPKCEncrypt:MaxCipherText", "The cipher must be initialized before size can be calculated!", new InvalidOperationException());

                return _maxCipherText; 
            }
        }

        /// <summary>
        /// Get: The maximum number of bytes the cipher can encrypt
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized</exception>
        public int MaxPlainText
        {
            get 
            {
                if (_maxPlainText == 0 || !_isInitialized)
                    throw new CryptoAsymmetricException("MPKCEncrypt:MaxPlainText", "The cipher must be initialized before size can be calculated!", new InvalidOperationException());

                return _maxPlainText; 
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
        /// <param name="CipherParams">The cipher engine</param>
        public MPKCEncrypt(MPKCParameters CipherParams)
        {
            _encEngine = GetEngine(CipherParams);
        }

        private MPKCEncrypt()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCEncrypt()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a cipher text
        /// </summary>
        /// 
        /// <param name="Input">The cipher text</param>
        /// 
        /// <returns>The plain text</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized</exception>
        public byte[] Decrypt(byte[] Input)
        {
            if (!_isInitialized)
                throw new CryptoAsymmetricException("MPKCEncrypt:Decrypt", "The cipher has not been initialized!", new InvalidOperationException());
            if (_isEncryption)
                throw new CryptoAsymmetricSignException("MPKCEncrypt:Decrypt", "The cipher is not initialized for decryption!", new ArgumentException());

            return _encEngine.Decrypt(Input);
        }

        /// <summary>
        /// Encrypt a plain text message
        /// </summary>
        /// 
        /// <param name="Input">The plain text</param>
        /// 
        /// <returns>The cipher text</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized, or the input text is invalid</exception>
        public byte[] Encrypt(byte[] Input)
        {
            if (!_isInitialized)
                throw new CryptoAsymmetricException("MPKCEncrypt:Encrypt", "The cipher has not been initialized!", new InvalidOperationException());
            if (Input.Length > _maxPlainText)
                throw new CryptoAsymmetricException("MPKCEncrypt:Encrypt", "The input text is too long!", new ArgumentException());
            if (!_isEncryption)
                throw new CryptoAsymmetricSignException("MPKCEncrypt:Encrypt", "The cipher is not initialized for encryption!", new ArgumentException());

            return _encEngine.Encrypt(Input);
        }

        /// <summary>
        /// Return the key size of the working key
        /// </summary>
        /// 
        /// <param name="Key">The key</param>
        /// 
        /// <returns>The size of the key</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized</exception>
        public int GetKeySize(IAsymmetricKey Key)
        {
            if (!_isInitialized)
                throw new CryptoAsymmetricException("MPKCEncrypt:GetKeySize", "The cipher has not been initialized!", new InvalidOperationException());

            if (Key is MPKCPublicKey)
                return ((MPKCPublicKey)Key).N;
            if (Key is MPKCPrivateKey)
                return ((MPKCPrivateKey)Key).N;

            throw new CryptoAsymmetricException("MPKCEncrypt:GetKeySize", "Unsupported key type!", new ArgumentException());
        }

        /// <summary>
        /// Initialize the cipher.
        /// <para>Requires a <see cref="MPKCPublicKey"/> for encryption, or a <see cref="MPKCPrivateKey"/> for decryption</para>
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the McEliece public or private key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the cipher is not initialized or the key is invalid</exception>
        public void Initialize(IAsymmetricKey AsmKey)
        {
            if (!(AsmKey is MPKCPublicKey) && !(AsmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricSignException("MPKCEncrypt:Initialize", "The key is not a valid Ring-KWE key!", new InvalidDataException());

            _isEncryption = (AsmKey is MPKCPublicKey);

            // init implementation engine
            _encEngine.Initialize(AsmKey);

            // get the sizes
            if (_isEncryption)
            {
                if (AsmKey == null)
                    throw new CryptoAsymmetricException("MPKCEncrypt:Initialize", "Encryption requires a public key!", new InvalidOperationException());
                if (!(AsmKey is MPKCPublicKey))
                    throw new CryptoAsymmetricException("MPKCEncrypt:Initialize", "The public key is invalid!", new ArgumentException());

                _maxCipherText = ((MPKCPublicKey)AsmKey).N >> 3;
                _maxPlainText = ((MPKCPublicKey)AsmKey).K >> 3;
            }
            else
            {
                if (AsmKey == null)
                    throw new CryptoAsymmetricException("MPKCEncrypt:Initialize", "Decryption requires a private key!", new InvalidOperationException());
                if (!(AsmKey is MPKCPrivateKey))
                    throw new CryptoAsymmetricException("MPKCEncrypt:Initialize", "The private key is invalid!", new ArgumentException());

                _maxPlainText = ((MPKCPrivateKey)AsmKey).K >> 3;
                _maxCipherText = ((MPKCPrivateKey)AsmKey).N>> 3;
            }

            _isInitialized = true;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="CipherParams">The cipher parameters</param>
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
                    if (_encEngine != null)
                    {
                        _encEngine.Dispose();
                        _encEngine = null;
                    }
                    _maxPlainText = 0;
                    _maxCipherText = 0;
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
