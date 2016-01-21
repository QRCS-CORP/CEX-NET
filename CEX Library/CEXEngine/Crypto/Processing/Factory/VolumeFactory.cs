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
    /// <h3>A helper class used to create and extract a VolumeKey file.</h3>
    /// 
    /// <list type="bullet">
    /// <item><description>Constructors may use a fully qualified path to a key file, or the keys file stream.</description></item>
    /// <item><description>The <see cref="Create(VolumeKey, Prngs, Digests)"/> method auto-generate keying material.</description></item>
    /// </list>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using the <see cref="Create(CipherDescription, int)"/> overload:</description>
    /// <code>
    ///     string[] paths = DirectoryTools.GetFiles(InputDirectory);
    /// 
    ///     // set cipher paramaters
    ///     CipherDescription desc = new CipherDescription(
    ///         Engines.RDX, 32,
    ///         IVSizes.V128,
    ///         CipherModes.CTR,
    ///         PaddingModes.X923,
    ///         BlockSizes.B128,
    ///         RoundCounts.R14,
    ///         Digests.Keccak512,
    ///         64,
    ///         Digests.Keccak512);
    /// 
    ///     // define the volume key
    ///     VolumeKey vkey = new VolumeKey(desc, paths.Length);
    ///     
    ///     // key will be written to this stream
    ///     MemoryStream keyStream = new MemoryStream();
    /// 
    ///     // create the volume key stream
    ///     using (VolumeFactory vf = new VolumeFactory(keyStream))
    ///         vf.Create(vkey);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/05/22" version="1.3.6.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.VolumeKey">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures VolumeKey Structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherDescription Structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyGenerator">VTDev.Libraries.CEXEngine.Crypto.Processing.Factory KeyGenerator class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher">VTDev.Libraries.CEXEngine.Crypto.Processing VolumeCipher class</seealso>
    public sealed class VolumeFactory : IDisposable
    {
        #region Fields
        private bool _isDisposed = false;
        private bool _disposeKey = false;
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
        /// <exception cref="CryptoProcessingException">Thrown if the key path is invalid, the key file exists, or the path is read onle</exception>
        public VolumeFactory(string KeyPath)
        {
            if (string.IsNullOrEmpty(KeyPath) || Path.GetExtension(KeyPath).Length < 1 || Path.GetFileNameWithoutExtension(KeyPath).Length < 1 || !Path.IsPathRooted(KeyPath))
                throw new CryptoProcessingException("VolumeFactory:Ctor", "The key path must contain a valid directory and file name!", new ArgumentException());
            if (File.Exists(KeyPath))
                throw new CryptoProcessingException("VolumeFactory:Ctor", "The key file exists! Can not overwrite an existing key file, choose a different path.", new FileLoadException());
            if (!DirectoryTools.IsWritable(Path.GetDirectoryName(KeyPath)))
                throw new CryptoProcessingException("VolumeFactory:Ctor", "The selected directory is read only! Choose a different path.", new UnauthorizedAccessException());

            _keyPath = KeyPath;
        }

        /// <summary>
        /// Initialize this class with a stream; key will be written to the stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream that receives the key</param>
        /// <param name="DisposeKey">Dispose of the key stream when this class is disposed; default is false</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a null stream is passed</exception>
        public VolumeFactory(Stream KeyStream, bool DisposeKey = false)
        {
            if (KeyStream == null)
                throw new CryptoProcessingException("VolumeFactory:Ctor", "The key stream can not be null!", new ArgumentException());
            _disposeKey = DisposeKey;

            _keyStream = KeyStream;
        }

        private VolumeFactory()
        {
        }

        /// <summary>
        /// Finalizer: ensure resources are destroyed
        /// </summary>
        ~VolumeFactory()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a volume key file using automatic key material generation.
        /// <para>The Key, and IV sets are generated automatically using the cipher description contained in the <see cref="CipherDescription"/>.
        /// This overload creates keying material using the seed and digest engines specified with the <see cref="KeyGenerator"/> class</para>
        /// </summary>
        /// 
        /// <param name="Key">The <see cref="VolumeKey">VolumeKey</see> containing the cipher and key implementation details</param>
        /// <param name="SeedEngine">The <see cref="Prngs">Random Generator</see> used to create the stage I seed material during key generation.</param>
        /// <param name="HashEngine">The <see cref="Digests">Digest Engine</see> used in the stage II phase of key generation.</param>
        /// 
        /// <exception cref="System.IO.FileLoadException">A key file exists at the path specified</exception>
        /// <exception cref="System.UnauthorizedAccessException">The key file path is read only</exception>
        public void Create(VolumeKey Key, SeedGenerators SeedEngine = SeedGenerators.CSPRsg, Digests HashEngine = Digests.SHA512)
        {
            int ksize = Key.Count * (Key.Description.KeySize + Key.Description.IvSize);
            byte[] kdata;

            using (KeyGenerator keyGen = new KeyGenerator(SeedEngine, HashEngine, null))
                kdata = keyGen.GetBytes(ksize);

            if (_keyStream == null)
                _keyStream = new FileStream(_keyPath, FileMode.Create, FileAccess.Write);

            byte[] hdr = Key.ToBytes();
            _keyStream.Write(hdr, 0, hdr.Length);
            _keyStream.Write(kdata, 0, kdata.Length);
        }

        /// <summary>
        /// Create a volume key file using a <see cref="CipherDescription"/> containing the cipher implementation details, and a key count size
        /// </summary>
        /// 
        /// <param name="Description">The <see cref="CipherDescription">Cipher Description</see> containing the cipher details</param>
        /// <param name="KeyCount">The number of key sets associated with this volume key</param>
        /// 
        /// <exception cref="System.IO.FileLoadException">A key file exists at the path specified</exception>
        /// <exception cref="System.UnauthorizedAccessException">The key file path is read only</exception>
        public void Create(CipherDescription Description, int KeyCount)
        {
            this.Create(new VolumeKey(Description, KeyCount));
        }

        /// <summary>
        /// Create a volume key file using a manual description of the cipher parameters.
        /// </summary>
        /// 
        /// <param name="KeyCount">The number of key sets associated with this volume key</param>
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
        /// <exception cref="System.IO.FileLoadException">A key file exists at the path specified</exception>
        /// <exception cref="System.UnauthorizedAccessException">The key file path is read only</exception>
        public void Create(int KeyCount, SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType,
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

            Create(dsc, KeyCount);
        }

        /// <summary>
        /// Extract a KeyParams and CipherDescription
        /// </summary>
        /// 
        /// <param name="Index">The index of the key set to extract</param>
        /// <param name="Description">The <see cref="CipherDescription"/> that receives the cipher description</param>
        /// <param name="KeyParam">The <see cref="KeyParams"/> container that receives the key material from the file</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the key file could not be found</exception>
        public void Extract(int Index, out CipherDescription Description, out KeyParams KeyParam)
        {
            if (!string.IsNullOrEmpty(_keyPath))
            {
                if (!File.Exists(_keyPath))
                    throw new CryptoProcessingException("VolumeFactory:Extract", "The key file could not be found! Check the path.", new FileNotFoundException());
            }

            if (_keyStream == null)
                _keyStream = new FileStream(_keyPath, FileMode.Open, FileAccess.Read);

            VolumeKey vkey = new VolumeKey(_keyStream);
            Description = vkey.Description;
            KeyParam = VolumeKey.AtIndex(_keyStream, Index);
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
                    if (_keyStream != null && _disposeKey)
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
