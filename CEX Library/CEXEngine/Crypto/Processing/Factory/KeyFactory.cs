#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Factory
{
    /// <summary>
    /// <h3>A helper class used to create or extract a CipherKey file.</h3>
    /// 
    /// <list type="bullet">
    /// <item><description>Constructors may use a fully qualified path to a key file, or the keys file stream.</description></item>
    /// <item><description>The <see cref="Create(CipherDescription, KeyParams)"/> method requires a populated KeyParams class.</description></item>
    /// <item><description>The <see cref="Create(CipherDescription, Prngs, Digests)"/> method auto-generate keying material.</description></item>
    /// <item><description>The Extract() method retrieves a populated cipher key (CipherKey), and key material (KeyParams), from the key file.</description></item>
    /// </list>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using the <see cref="Create(CipherDescription, Prngs, Digests)"/> overload:</description>
    /// <code>
    /// // create the key file
    /// new KeyFactory(KeyPath).Create(description);
    /// </code>
    /// 
    /// <description>Example using the <see cref="Extract(out CipherKey, out KeyParams)"/> method:</description>
    /// <code>
    /// // local vars
    /// keyparam KeyParams;
    /// CipherKey header;
    /// 
    /// new KeyFactory(KeyPath).Extract(out header, out keyparam);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.CipherKey">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherKey Structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherDescription Structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyGenerator">VTDev.Libraries.CEXEngine.Crypto.Processing.Factory KeyGenerator class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams">VTDev.Libraries.CEXEngine.Crypto.Processing.Structure KeyParams class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.StreamCipher">VTDev.Libraries.CEXEngine.Crypto.Processing StreamCipher class</seealso>
    public sealed class KeyFactory : IDisposable
    {
        #region Fields
        private bool _isDisposed = false;
        private string _keyPath;
        private Stream _keyStream;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class with a key file path; key will be written to the path
        /// </summary>
        /// 
        /// <param name="KeyPath">The fully qualified path to the key file to be read or created</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the key path is invalid, a key file exists at the path specified, or file path is read only</exception>
        public KeyFactory(string KeyPath)
        {
            if (string.IsNullOrEmpty(KeyPath) || Path.GetExtension(KeyPath).Length < 1 || Path.GetFileNameWithoutExtension(KeyPath).Length < 1 || !Path.IsPathRooted(KeyPath))
                throw new CryptoProcessingException("KeyFactory:Ctor", "The key path must contain a valid directory and file name!", new ArgumentException());
            if (File.Exists(KeyPath))
                throw new CryptoProcessingException("KeyFactory:Ctor", "The key file exists! Can not overwrite an existing key file, choose a different path.", new FileLoadException());
            if (!DirectoryTools.IsWritable(Path.GetDirectoryName(KeyPath)))
                throw new CryptoProcessingException("KeyFactory:Ctor", "The selected directory is read only! Choose a different path.", new UnauthorizedAccessException());

            _keyPath = KeyPath;
        }

        /// <summary>
        /// Initialize this class with a stream; key will be written to the stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The fully qualified path to the key file to be read or created</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a null stream is passed</exception>
        public KeyFactory(Stream KeyStream)
        {
            if (KeyStream == null)
                throw new CryptoProcessingException("KeyFactory:Ctor", "The key stream can not be null!", new ArgumentException());

            _keyStream = KeyStream;
        }

        private KeyFactory()
        {
        }

        /// <summary>
        /// Finalizer: ensure resources are destroyed
        /// </summary>
        ~KeyFactory()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a single use key file using automatic key material generation.
        /// <para>The Key, and optional IV and IKM are generated automatically using the cipher description contained in the <see cref="CipherDescription"/>.
        /// This overload creates keying material using the seed and digest engines specified with the <see cref="KeyGenerator"/> class</para>
        /// </summary>
        /// 
        /// <param name="Description">The <see cref="CipherDescription">Cipher Description</see> containing the cipher implementation details</param>
        /// <param name="SeedEngine">The <see cref="Prngs">Random Generator</see> used to create the stage I seed material during key generation.</param>
        /// <param name="HashEngine">The <see cref="Digests">Digest Engine</see> used in the stage II phase of key generation.</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a KeyParams member is null, but specified in the Header</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if a Header parameter does not match a KeyParams value</exception>
        public void Create(CipherDescription Description, Prngs SeedEngine = Prngs.CSPRng, Digests HashEngine = VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests.SHA512)
        {
            KeyParams keyParam;

            using (KeyGenerator keyGen = new KeyGenerator(SeedEngine, HashEngine))
                keyParam = keyGen.GetKeyParams(Description.KeySize, Description.IvSize, Description.MacSize);

            Create(Description, keyParam);
        }

        /// <summary>
        /// Create a single use key file using a <see cref="KeyParams"/> containing the key material, and a <see cref="CipherDescription"/> containing the cipher implementation details
        /// </summary>
        /// 
        /// <param name="Description">The <see cref="CipherDescription">Cipher Description</see> containing the cipher details</param>
        /// <param name="KeyParam">An initialized and populated key material container</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a KeyParams member is null, but specified in the Header or a Header parameter does not match a KeyParams value</exception>
        public void Create(CipherDescription Description, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoProcessingException("KeyFactory:Create", "The key can not be null!", new ArgumentNullException());
            if (KeyParam.Key.Length != Description.KeySize)
                throw new CryptoProcessingException("KeyFactory:Create", "The key parameter does not match the key size specified in the Header!", new ArgumentOutOfRangeException());

            if (Description.IvSize > 0 && KeyParam.IV != null)
            {
                if (KeyParam.IV.Length != Description.IvSize)
                    throw new CryptoProcessingException("KeyFactory:Create", "The KeyParam IV size does not align with the IVSize setting in the Header!", new ArgumentOutOfRangeException());
            }
            if (Description.MacSize > 0)
            {
                if (KeyParam.IKM == null)
                    throw new CryptoProcessingException("KeyFactory:Create", "Digest key is specified in the header MacSize, but is null in KeyParam!", new ArgumentNullException());
                if (KeyParam.IKM.Length != Description.MacSize)
                    throw new CryptoProcessingException("KeyFactory:Create", "Header MacSize does not align with the size of the KeyParam IKM!", new ArgumentOutOfRangeException());
            }

            if (_keyStream == null)
                _keyStream = new FileStream(_keyPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);

            byte[] hdr = new CipherKey(Description).ToBytes();
            _keyStream.Write(hdr, 0, hdr.Length);
            byte[] key = ((MemoryStream)KeyParams.Serialize(KeyParam)).ToArray();
            _keyStream.Write(key, 0, key.Length);
        }

        /// <summary>
        /// Create a single use Key file using a manual description of the cipher parameters.
        /// </summary>
        /// 
        /// <param name="KeyParam">An initialized and populated key material container</param>
        /// <param name="EngineType">The Cryptographic <see cref="SymmetricEngines">Engine</see> type</param>
        /// <param name="KeySize">The cipher Key Size in bytes</param>
        /// <param name="IvSize">Size of the cipher <see cref="IVSizes">Initialization Vector</see></param>
        /// <param name="CipherType">The type of <see cref="CipherModes">Cipher Mode</see></param>
        /// <param name="PaddingType">The type of cipher <see cref="PaddingModes">Padding Mode</see></param>
        /// <param name="BlockSize">The cipher <see cref="BlockSizes">Block Size</see></param>
        /// <param name="Rounds">The number of diffusion <see cref="RoundCounts">Rounds</see></param>
        /// <param name="KdfEngine">The <see cref="Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
        /// <param name="MacSize">The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key</param>
        /// <param name="MacEngine">The HMAC <see cref="Digests">Digest</see> engine used to authenticate a message file encrypted with this key</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a KeyParams member is null, but specified in the Header</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if a Header parameter does not match a KeyParams value</exception>
        public void Create(KeyParams KeyParam, SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType,
            PaddingModes PaddingType, BlockSizes BlockSize, RoundCounts Rounds, Digests KdfEngine, int MacSize, Digests MacEngine)
        {
            CipherDescription dsc = new CipherDescription()
            {
                EngineType = (int)EngineType,
                KeySize = KeySize,
                IvSize = (int)IvSize,
                CipherType = (int)CipherType,
                PaddingType = (int)PaddingType,
                BlockSize = (int)BlockSize,
                RoundCount = (int)Rounds,
                KdfEngine = (int)KdfEngine,
                MacEngine = (int)MacEngine,
                MacSize = MacSize
            };

            Create(dsc, KeyParam);
        }

        /// <summary>
        /// Extract a KeyParams and CipherKey
        /// </summary>
        /// 
        /// <param name="KeyHeader">The <see cref="CipherKey"/> that receives the cipher description, key id, and extension key</param>
        /// <param name="KeyParam">The <see cref="KeyParams"/> container that receives the key material from the file</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the key file could not be found or a Header parameter does not match the keystream length</exception>
        public void Extract(out CipherKey KeyHeader, out KeyParams KeyParam)
        {
            if (!string.IsNullOrEmpty(_keyPath))
            {
                if (!File.Exists(_keyPath))
                    throw new CryptoProcessingException("KeyFactory:Extract", "The key file could not be found! Check the path.", new FileNotFoundException());
            }

            if (_keyStream == null)
                _keyStream = new FileStream(_keyPath, FileMode.Open, FileAccess.Read);

            KeyHeader = new CipherKey(_keyStream);
            CipherDescription dsc = KeyHeader.Description;

            if (_keyStream.Length < dsc.KeySize + dsc.IvSize + dsc.MacSize + CipherKey.GetHeaderSize())
                throw new CryptoProcessingException("KeyFactory:Extract", "The size of the key file does not align with the CipherKey sizes! Key is corrupt.", new ArgumentOutOfRangeException());

            _keyStream.Position = CipherKey.GetHeaderSize();
            KeyParam = KeyParams.DeSerialize(_keyStream);
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
                    if (_keyStream != null)
                    {
                        _keyStream.Dispose();
                        _keyStream = null;
                    }
                    if (_keyPath != null)
                    {
                        _keyPath = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
