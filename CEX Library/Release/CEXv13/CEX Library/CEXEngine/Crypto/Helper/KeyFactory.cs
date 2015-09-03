#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// <h3>A helper class used to create or extract a Key file.</h3>
    /// 
    /// <list type="bullet">
    /// <item><description>Constructors may use a fully qualified path to a key file, or the key file stream.</description></item>
    /// <item><description>The <see cref="Create(KeyParams, KeyHeaderStruct)"/> method requires a populated KeyParams class.</description></item>
    /// <item><description>The <see cref="Create(KeyHeaderStruct)"/> and <see cref="Create(Prngs, Digests, KeyHeaderStruct)"/> methods auto-generate keying material.</description></item>
    /// <item><description>The Extract() method retrieves a populated cipher description (KeyHeaderStruct), and key material (KeyParams), from the key file.</description></item>
    /// </list>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using the <see cref="Create(KeyHeaderStruct)"/> overload:</description>
    /// <code>
    /// // create the key file
    /// new KeyFactory(KeyPath).Create(keyHeaderStruct);
    /// </code>
    /// 
    /// <description>Example using the <see cref="Extract(out KeyParams, out KeyHeaderStruct)"/> method:</description>
    /// <code>
    /// // local vars
    /// keyparam KeyParams;
    /// KeyHeaderStruct header;
    /// 
    /// new KeyFactory(KeyPath).Extract(out keyparam, out header);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    ///     <revision date="2015/01/23" version="1.3.0.0" author="John Underhill">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="KeyHeaderStruct">VTDev.Libraries.CEXEngine.Crypto.Helper.KeyHeaderStruct Struct</seealso>
    /// <seealso cref="KeyHeader">VTDev.Libraries.CEXEngine.Crypto.Helper.KeyHeader Class</seealso>
    /// <seealso cref="Prngs">VTDev.Libraries.CEXEngine.Crypto.Prngs Enumeration</seealso>
    /// <seealso cref="Digests">VTDev.Libraries.CEXEngine.Crypto.Digests Enumeration</seealso>
    /// <seealso cref="KeyGenerator">VTDev.Libraries.CEXEngine.Crypto.Helper.KeyGenerator class</seealso>
    /// <seealso cref="KeyParams">VTDev.Libraries.CEXEngine.Crypto.KeyParams class</seealso>
    public sealed class KeyFactory : IDisposable
    {
        #region Fields
        private bool _isDisposed = false;
        private string _keyPath;
        private Stream _keyStream;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class with a key file path
        /// </summary>
        /// 
        /// <param name="KeyPath">The fully qualified path to the key file to be read or created</param>
        public KeyFactory(string KeyPath)
        {
            _keyPath = KeyPath;
        }

        /// <summary>
        /// Initialize this class with a key file stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The fully qualified path to the key file to be read or created</param>
        public KeyFactory(Stream KeyStream)
        {
            _keyStream = KeyStream;
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
        /// Create a key file using automatic key material generation.
        /// <para>The Key, and optional IV and IKM are generated automatically using the cipher description contained in the Header. 
        /// This overload creates keying material using the <see cref="KeyGenerator"/> default seed and digest engines: 
        /// <see cref="VTDev.Libraries.CEXEngine.Crypto.Prng.CSPRng"/> and 
        /// <see cref="VTDev.Libraries.CEXEngine.Crypto.Digest.SHA512">SHA-2 512</see></para>
        /// </summary>
        /// 
        /// <param name="Header">The <see cref="KeyHeaderStruct">Key Header</see> containing the cipher description</param>
        /// 
        /// <exception cref="System.IO.FileLoadException">A key file exists at the path specified</exception>
        /// <exception cref="System.UnauthorizedAccessException">The key file path is read only</exception>
        /// <exception cref="System.ArgumentNullException">A KeyParams member is null, but specified in the Header</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">A Header parameter does not match a KeyParams value</exception>
        public void Create(KeyHeaderStruct Header)
        {
            KeyParams keyParam;

            using (KeyGenerator keyGen = new KeyGenerator())
                keyParam = keyGen.GetKeyParams(Header.KeySize, Header.IvSize, Header.MacSize);

            Create(keyParam, Header);
        }

        /// <summary>
        /// Create a key file using a <see cref="KeyParams"/> containing the key material, and a <see cref="KeyHeaderStruct"/> containing the cipher description.
        /// </summary>
        /// 
        /// <param name="KeyParam">An initialized and populated key material container</param>
        /// <param name="Header">The <see cref="KeyHeaderStruct">Key Header</see> containing the cipher description</param>
        /// 
        /// <exception cref="System.IO.FileLoadException">A key file exists at the path specified</exception>
        /// <exception cref="System.UnauthorizedAccessException">The key file path is read only</exception>
        /// <exception cref="System.ArgumentNullException">A KeyParams member is null, but specified in the Header</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">A Header parameter does not match a KeyParams value</exception>
        public void Create(KeyParams KeyParam, KeyHeaderStruct Header)
        {
            // if you are getting exceptions.. read the docs!
            if (File.Exists(_keyPath))
                throw new FileLoadException("The key file exists! Can not overwrite an existing key file, choose a different path.");
            if (!Utility.FileUtilities.DirectoryIsWritable(Path.GetDirectoryName(_keyPath)))
                throw new UnauthorizedAccessException("The selected directory is read only! Choose a different path.");
            if (KeyParam.Key == null)
                throw new ArgumentNullException("The key can not be null!");
            if (KeyParam.Key.Length != Header.KeySize)
                throw new ArgumentOutOfRangeException("The key parameter does not match the key size specified in the Header!");

            if (Header.IvSize > 0 && KeyParam.IV != null)
            {
                if (KeyParam.IV.Length != Header.IvSize)
                    throw new ArgumentOutOfRangeException("The KeyParam IV size does not align with the IVSize setting in the Header!");
            }
            if (Header.MacSize > 0)
            {
                if (KeyParam.IKM == null)
                    throw new ArgumentNullException("Digest key is specified in the header MacSize, but is null in KeyParam!");
                if (KeyParam.IKM.Length != Header.MacSize)
                    throw new ArgumentOutOfRangeException("Header MacSize does not align with the size of the KeyParam IKM!");
            }

            using (FileStream outStream = new FileStream(_keyPath, FileMode.Create, FileAccess.Write))
            {
                byte[] hdr = ((MemoryStream)KeyHeader.SerializeHeader(Header)).ToArray();
                outStream.Write(hdr, 0, hdr.Length);

                if (Header.MacSize > 0)
                    outStream.Write(KeyParam.IKM, 0, KeyParam.IKM.Length);

                outStream.Write(KeyParam.Key, 0, KeyParam.Key.Length);

                if (KeyParam.IV != null)
                    outStream.Write(KeyParam.IV, 0, KeyParam.IV.Length);
            }
        }

        /// <summary>
        /// Create a key file using automatic key material generation.
        /// <para>The Key, and optional IV and IKM are generated automatically using the cipher description contained in the <see cref="KeyHeaderStruct"/>.
        /// This overload creates keying material using the seed and digest engines specified with the <see cref="KeyGenerator"/> class</para>
        /// </summary>
        /// 
        /// <param name="SeedEngine">The <see cref="Prngs">Random Generator</see> used to create the stage I seed material during key generation.</param>
        /// <param name="HashEngine">The <see cref="Digests">Digest Engine</see> used in the stage II phase of key generation.</param>
        /// <param name="Header">The <see cref="KeyHeaderStruct">Key Header</see> containing the cipher description</param>
        /// 
        /// <exception cref="System.IO.FileLoadException">A key file exists at the path specified</exception>
        /// <exception cref="System.UnauthorizedAccessException">The key file path is read only</exception>
        /// <exception cref="System.ArgumentNullException">A KeyParams member is null, but specified in the Header</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">A Header parameter does not match a KeyParams value</exception>
        public void Create(Prngs SeedEngine, Digests HashEngine, KeyHeaderStruct Header)
        {
            KeyParams keyParam;

            using (KeyGenerator keyGen = new KeyGenerator(SeedEngine, HashEngine))
                keyParam = keyGen.GetKeyParams(Header.KeySize, Header.IvSize, Header.MacSize);

            Create(keyParam, Header);
        }

        /// <summary>
        /// Create a Key file using a manual description of the cipher parameters.
        /// </summary>
        /// 
        /// <param name="KeyParam">An initialized and populated key material container</param>
        /// <param name="EngineType">The Cryptographic <see cref="Engines">Engine</see> type</param>
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
        /// <exception cref="System.IO.FileLoadException">A key file exists at the path specified</exception>
        /// <exception cref="System.UnauthorizedAccessException">The key file path is read only</exception>
        /// <exception cref="System.ArgumentNullException">A KeyParams member is null, but specified in the Header</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">A Header parameter does not match a KeyParams value</exception>
        public void Create(KeyParams KeyParam, Engines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType, 
            PaddingModes PaddingType, BlockSizes BlockSize, RoundCounts Rounds, Digests KdfEngine, int MacSize, Digests MacEngine)
        {
            
            KeyHeaderStruct header = new KeyHeaderStruct()
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

            Create(KeyParam, header);
        }

        /// <summary>
        /// Extract a key file
        /// </summary>
        /// 
        /// <param name="KeyParam">The <see cref="KeyParams"/> container that receives the key material from the file</param>
        /// <param name="Header">The <see cref="KeyHeaderStruct"/> that receives the cipher description</param>
        public void Extract(out KeyParams KeyParam, out KeyHeaderStruct Header)
        {
            if (!string.IsNullOrEmpty(_keyPath))
            {
                if (!File.Exists(_keyPath))
                    throw new FileNotFoundException("The key file could not be found! Check the path.");
            }
            
            if (_keyStream == null)
                _keyStream = new FileStream(_keyPath, FileMode.Open, FileAccess.Read);

            Header = KeyHeader.DeSerializeHeader(_keyStream);

            if (_keyStream.Length < Header.KeySize + Header.IvSize + KeyHeader.GetHeaderSize)
                throw new ArgumentOutOfRangeException("The size of the key file does not align with the KeyHeaderStruct sizes! Key is corrupt.");

            _keyStream.Position = KeyHeader.GetHeaderSize;

            if (Header.MacSize > 0 && Header.IvSize > 0)
            {
                byte[] ikm = new byte[Header.MacSize];
                byte[] key = new byte[Header.KeySize];
                byte[] iv = new byte[Header.IvSize];
                _keyStream.Read(ikm, 0, ikm.Length);
                _keyStream.Read(key, 0, key.Length);
                _keyStream.Read(iv, 0, iv.Length);
                KeyParam = new KeyParams(key, iv, ikm);
            }
            else if (Header.IvSize > 0)
            {
                byte[] key = new byte[Header.KeySize];
                byte[] iv = new byte[Header.IvSize];
                _keyStream.Read(key, 0, key.Length);
                _keyStream.Read(iv, 0, iv.Length);
                KeyParam = new KeyParams(key, iv);
            }
            else if (Header.MacSize > 0)
            {
                byte[] key = new byte[Header.KeySize];
                byte[] ikm = new byte[Header.MacSize];
                _keyStream.Read(ikm, 0, ikm.Length);
                _keyStream.Read(key, 0, key.Length);
                KeyParam = new KeyParams(key, null, ikm);
            }
            else
            {
                byte[] key = new byte[Header.KeySize];
                _keyStream.Read(key, 0, key.Length);
                KeyParam = new KeyParams(key);
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
