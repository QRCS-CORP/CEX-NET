#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Written by John Underhill, January 21, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing
{
    /// <summary>
    /// <h5>VolumeCipher: Performs bulk file cryptographic transforms.</h5>
    /// <para>A helper class used to encrypt or decrypt a series of files on a directory or volume.
    /// Note: If the cipher is for encryption, files are encrypted in place.
    /// If the cipher is for decryption, individual files or the entire directory can be decrypted.</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example of encrypting and decrypting a Directory:</description>
    /// <code>
    /// public static void VolumeCipherTest(string InputDirectory)
    /// {
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
    ///     // key will be written to this stream
    ///     MemoryStream keyStream = new MemoryStream();
    /// 
    ///     // create the volume key stream
    ///     using (VolumeFactory vf = new VolumeFactory(keyStream))
    ///         vf.Create(vkey);
    /// 
    ///     // encrypt the files in the directory
    ///     using (VolumeCipher vc = new VolumeCipher(true, keyStream))
    ///         vc.Transform(paths);
    /// 
    ///     // decrypt the files in the directory
    ///     using (VolumeCipher vc = new VolumeCipher(false, keyStream))
    ///         vc.Transform(paths);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/05/22" version="1.3.6.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherDescription Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">VTDev.Libraries.CEXEngine.Crypto.Engines Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Uses any of the implemented <see cref="ICipherMode">Cipher Mode</see> wrapped <see cref="SymmetricEngines">Block Ciphers</see>, or any of the implemented <see cref="IStreamCipher">Stream Ciphers</see>.</description></item>
    /// <item><description>Cipher Engine can be Disposed when this class is Disposed, set the DisposeEngine parameter in the class Constructor to true to dispose automatically.</description></item>
    /// <item><description>Streams can be Disposed when the class is Disposed, set the DisposeStream parameter in the Initialize(Stream, Stream, bool) call to true to dispose automatically.</description></item>
    /// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per either of the 'Transform()' calls.</description></item>
    /// <item><description>Changes to the Cipher or CipherStream ParallelBlockSize must be set after initialization.</description></item>
    /// </list>
    /// </remarks>
    public class VolumeCipher : IDisposable
    {
        #region Enums
        /// <summary>
        /// ParallelBlockProfile enumeration
        /// </summary>
        public enum BlockProfiles : int
        {
            /// <summary>
            /// Set parallel block size as a division of 100 segments
            /// </summary>
            ProgressProfile = 0,
            /// <summary>
            /// Set parallel block size for maximum possible speed
            /// </summary>
            SpeedProfile
        }
        #endregion

        #region Constants
        // Max array size allocation base; multiply by processor count for actual
        // byte/memory allocation during parallel loop execution
        private const int MAXALLOC_MB100 = 100000000;
        // default parallel block size
        private const int PARALLEL_DEFBLOCK = 64000;
        #endregion

        #region Events
        /// <summary>
        /// Progress indicator delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="e">Progress event arguments containing percentage and bytes processed as the UserState param</param>
        public delegate void ProgressDelegate(object sender, System.ComponentModel.ProgressChangedEventArgs e);

        /// <summary>
        /// Error notification delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="message">The bnature of the error</param>
        public delegate void NotificationDelegate(object sender, string message);

        /// <summary>
        /// Progress Percent Event; returns bytes processed as an integer percentage
        /// </summary>
        public event ProgressDelegate ProgressPercent;

        /// <summary>
        /// Error Notification; alerts the caller to an error condition that has not halted processing
        /// </summary>
        public event NotificationDelegate ErrorNotification;
        #endregion

        #region Fields
        private ICipherMode _cipherEngine;
        private IStreamCipher _streamCipher;
        private bool _isEncryption = true;
        private int _blockSize = PARALLEL_DEFBLOCK;
        private IPadding _cipherPadding;
        private bool _disposeEngine = false;
        private bool _isCounterMode = false;
        private bool _isDisposed = false;
        private bool _isParallel = false;
        private bool _isStreamCipher = false;
        private BlockProfiles _parallelBlockProfile = BlockProfiles.ProgressProfile;
        private long _progressTotal = 0;
        private int _processorCount;
        private VolumeKey _volumeKey;
        private Stream _keyStream;
        #endregion
        
        #region Properties
        /// <summary>
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return _isParallel; }
            set { _isParallel = value; }
        }

        /// <summary>
        /// Get/Set: Determines how the size of a parallel block is calculated; using the <see cref="BlockProfiles">Block Profiles</see>
        /// </summary>
        public BlockProfiles ParallelBlockProfile
        {
            get { return _parallelBlockProfile; }
            set { _parallelBlockProfile = value; }
        }

        /// <summary>
        /// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
        /// </summary>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, 
        /// or the size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return _blockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoProcessingException("VolumeCipher:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoProcessingException("VolumeCipher:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

                _blockSize = value;
            }
        }

        /// <summary>
        /// Get: Maximum input size with parallel processing
        /// </summary>
        public int ParallelMaximumSize
        {
            get { return MAXALLOC_MB100; }
        }

        /// <summary>
        /// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
        /// </summary>
        public int ParallelMinimumSize
        {
            get 
            {
                if (_isStreamCipher)
                {
                    if (_streamCipher.GetType().Equals(typeof(ChaCha)))
                        return ((ChaCha)_streamCipher).ParallelMinimumSize;
                    else
                        return ((Salsa20)_streamCipher).ParallelMinimumSize;
                }
                else
                {
                    if (_cipherEngine.GetType().Equals(typeof(CTR)))
                        return ((CTR)_cipherEngine).ParallelMinimumSize;
                    else if (_cipherEngine.GetType().Equals(typeof(CBC)) && !_isEncryption)
                        return ((CBC)_cipherEngine).ParallelMinimumSize;
                    else if (_cipherEngine.GetType().Equals(typeof(CFB)) && !_isEncryption)
                        return ((CFB)_cipherEngine).ParallelMinimumSize;
                    else
                        return 0;
                }
            }
        }

        /// <summary>
        /// Get: The system processor count
        /// </summary>
        public int ProcessorCount 
        { 
            get { return _processorCount; }
            private set { _processorCount = value; }
        }
        #endregion

        #region Constructor 
        /// <summary>
        /// Initialize the class with a CipherDescription Structure; containing the cipher implementation details, and a <see cref="KeyParams"/> class containing the Key material.
        /// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription. 
        /// Cipher modes, padding, and engines are destroyed automatically through this classes Dispose() method.</para>
        /// </summary>
        /// 
        /// <param name="Encryption">Cipher is an encryptor</param>
        /// <param name="KeyStream">A stream containing a <see cref="VolumeKey"/> and the keying material</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if an invalid <see cref="VolumeKey"/> is used</exception>
        public VolumeCipher(bool Encryption, Stream KeyStream)
        {
            _keyStream = KeyStream;
            _volumeKey = new VolumeKey(KeyStream);

            if (!CipherDescription.IsValid(_volumeKey.Description))
                throw new CryptoProcessingException("VolumeCipher:CTor", "The key Header is invalid!", new ArgumentException());

            _disposeEngine = true;
            _isEncryption = Encryption;
            _blockSize = _volumeKey.Description.BlockSize;
            _isParallel = false;
            CipherDescription desc = _volumeKey.Description;

            if (_isStreamCipher = IsStreamCipher((SymmetricEngines)desc.EngineType))
            {
                _streamCipher = GetStreamCipher((StreamCiphers)desc.EngineType, desc.RoundCount);

                if (_streamCipher.GetType().Equals(typeof(ChaCha)))
                {
                    if (_isParallel = ((ChaCha)_streamCipher).IsParallel)
                        _blockSize = ((ChaCha)_streamCipher).ParallelBlockSize;
                }
                else
                {
                    if (_isParallel = ((Salsa20)_streamCipher).IsParallel)
                        _blockSize = ((Salsa20)_streamCipher).ParallelBlockSize;
                }
            }
            else
            {
                _cipherEngine = GetCipherMode((CipherModes)desc.CipherType, (BlockCiphers)desc.EngineType, desc.BlockSize, desc.RoundCount, (Digests)desc.KdfEngine);

                if (_isCounterMode = _cipherEngine.GetType().Equals(typeof(CTR)))
                {
                    if (_isParallel = ((CTR)_cipherEngine).IsParallel)
                        _blockSize = ((CTR)_cipherEngine).ParallelBlockSize;
                }
                else
                {
                    if (_cipherEngine.GetType().Equals(typeof(CBC)))
                    {
                        if (_isParallel = ((CBC)_cipherEngine).IsParallel && !((CBC)_cipherEngine).IsEncryption)
                            _blockSize = ((CBC)_cipherEngine).ParallelBlockSize;
                    }
                    else if (_cipherEngine.GetType().Equals(typeof(CFB)))
                    {
                        if (_isParallel = ((CFB)_cipherEngine).IsParallel && !((CFB)_cipherEngine).IsEncryption)
                            _blockSize = ((CFB)_cipherEngine).ParallelBlockSize;
                    }
                    _cipherPadding = GetPaddingMode((PaddingModes)_volumeKey.Description.PaddingType);
                }
            }
        }

        private VolumeCipher()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~VolumeCipher()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Encrypt or Decrypt the files in the specified directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">The directory containing the files to be processed</param>
        public void Transform(string DirectoryPath)
        {
            string[] filePaths = DirectoryTools.GetFiles(DirectoryPath);
            Transform(filePaths);
        }

        /// <summary>
        /// Encrypt or Decrypt the files in the specified directory
        /// </summary>
        /// 
        /// <param name="FilePaths">A list of the files to be processed</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the VolumeKey does not contain enough keys to encrypt all the files in the directory</exception>
        public void Transform(string[] FilePaths)
        {
            if (_isEncryption && _volumeKey.KeyCount() < FilePaths.Length)
                throw new CryptoProcessingException("VolumeCipher:Transform", "Not enough keys in the volume key to encrypt this directory!", new ArgumentException());
            
            Initialize(FilePaths);

            for (int i = 0; i < FilePaths.Length; i++)
            {
                // next key
                int index = -1;
                FileStream wrkStream;
                KeyParams key;
                int hash = FilePaths[i].GetHashCode();
                wrkStream = GetStream(FilePaths[i]);

                // should notify or log
                if (wrkStream == null)
                {
                    if (ErrorNotification != null)
                        ErrorNotification(this, String.Format("The file {0}; could not be written to", FilePaths[i]));

                    continue;
                }
                if (_isEncryption)
                {
                    // get an unused key
                    index = _volumeKey.NextSubKey();
                    key = VolumeKey.AtIndex(_keyStream, index);
                    // update header
                    _volumeKey.FileId[index] = hash;
                    _volumeKey.State[index] = (byte)VolumeKeyStates.Encrypted;
                }
                else
                {
                    // get key associated with file
                    key = VolumeKey.FromId(_keyStream, hash);

                    // user dropped a file in, notify or log
                    if (key == null)
                    {
                        if (ErrorNotification != null)
                            ErrorNotification(this, String.Format("The file {0}; has no key assigned", FilePaths[i]));

                        continue;
                    }
                    _volumeKey.State[_volumeKey.GetIndex(hash)] = (byte)VolumeKeyStates.Decrypted;
                }

                // process file
                if (!_isStreamCipher)
                {
                    _cipherEngine.Initialize(_isEncryption, key);

                    if (_isParallel)
                    {
                        ProcessParallel(wrkStream);
                    }
                    else
                    {
                        if (_isEncryption)
                            Encrypt(wrkStream);
                        else
                            Decrypt(wrkStream);
                    }
                }
                else
                {
                    _streamCipher.Initialize(key);
                    ProcessStream(wrkStream);
                }

                wrkStream.Close();
                wrkStream.Dispose();
            }

            // update the key header
            _keyStream.Seek(0, SeekOrigin.Begin);
            byte[] ks = _volumeKey.ToBytes();
            _keyStream.Write(ks, 0, ks.Length);
        }
        #endregion

        #region Crypto
        private void Decrypt(FileStream WorkStream)
        {
            byte[] inputBuffer = new byte[_blockSize];
            byte[] outputBuffer = new byte[_blockSize];
            int bytesRead = 0;
            long bytesTotal = 0;
            long lastBlock = WorkStream.Length;

            while ((bytesRead = WorkStream.Read(inputBuffer, 0, _blockSize)) == _blockSize)
            {
                _cipherEngine.Transform(inputBuffer, outputBuffer);
                bytesTotal += bytesRead;
                WorkStream.Position -= bytesRead;

                if (bytesTotal < lastBlock)
                {
                    WorkStream.Write(outputBuffer, 0, _blockSize);
                    CalculateProgress(bytesTotal);
                }
                else
                {
                    int fnlSize = _cipherEngine.BlockSize - _cipherPadding.GetPaddingLength(outputBuffer);
                    WorkStream.Write(outputBuffer, 0, fnlSize);
                    bytesTotal += fnlSize;
                }
            }

            CalculateProgress(bytesTotal);
        }

        private void Encrypt(FileStream WorkStream)
        {
            byte[] inputBuffer = new byte[_blockSize];
            byte[] outputBuffer = new byte[_blockSize];
            int bytesRead = 0;
            long bytesTotal = 0;

            while ((bytesRead = WorkStream.Read(inputBuffer, 0, _blockSize)) == _blockSize)
            {
                _cipherEngine.Transform(inputBuffer, outputBuffer);
                WorkStream.Position -= bytesRead;
                WorkStream.Write(outputBuffer, 0, bytesRead);
                bytesTotal += bytesRead;
                CalculateProgress(bytesTotal);
            }

            if (bytesRead > 0)
            {
                if (bytesRead < _blockSize)
                    _cipherPadding.AddPadding(inputBuffer, (int)bytesRead);

                _cipherEngine.Transform(inputBuffer, outputBuffer);
                WorkStream.Position -= bytesRead;
                WorkStream.Write(outputBuffer, 0, _blockSize);
                bytesTotal += bytesRead;
            }

            CalculateProgress(bytesTotal);
        }

        private IBlockCipher GetBlockCipher(BlockCiphers EngineType, int BlockSize, int RoundCount, Digests KdfEngine)
        {
            try
            {
                return BlockCipherFromName.GetInstance(EngineType, BlockSize, RoundCount, KdfEngine);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("CipherStream:GetBlockEngine", ex);
            }
        }

        private ICipherMode GetCipherMode(CipherModes CipherType, BlockCiphers EngineType, int BlockSize, int RoundCount, Digests KdfEngine)
        {
            IBlockCipher engine = GetBlockCipher(EngineType, BlockSize, RoundCount, KdfEngine);

            try
            {
                return CipherModeFromName.GetInstance(CipherType, engine);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("CipherStream:GetCipherMode", ex);
            }
        }

        private IPadding GetPaddingMode(PaddingModes PaddingType)
        {
            try
            {
                return PaddingFromName.GetInstance(PaddingType);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("CipherStream:GetPaddingMode", ex);
            }
        }

        private IStreamCipher GetStreamCipher(StreamCiphers EngineType, int RoundCount)
        {
            try
            {
                return StreamCipherFromName.GetInstance(EngineType, RoundCount);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("CipherStream:GetStreamEngine", ex);
            }
        }

        private bool IsStreamCipher(SymmetricEngines EngineType)
        {
            return EngineType == SymmetricEngines.ChaCha ||
                EngineType == SymmetricEngines.Salsa;
        }

        private void ProcessParallel(FileStream WorkStream)
        {
            long bytesTotal = 0;
            int bytesRead = 0;
            byte[] inputBuffer = new byte[_blockSize];
            byte[] outputBuffer = new byte[_blockSize];

            // loop through file
            while ((bytesRead = WorkStream.Read(inputBuffer, 0, _blockSize)) == _blockSize)
            {
                bytesTotal += bytesRead;
                _cipherEngine.Transform(inputBuffer, outputBuffer);
                WorkStream.Position -= bytesRead;
                WorkStream.Write(outputBuffer, 0, bytesRead);
                CalculateProgress(bytesTotal);
            }

            // last block
            if (bytesRead > 0)
            {
                outputBuffer = new byte[bytesRead];
                // parallel modes handle alignment
                _cipherEngine.Transform(inputBuffer, outputBuffer);

                if (_isCounterMode)
                {
                    WorkStream.Position -= bytesRead;
                    WorkStream.Write(outputBuffer, 0, bytesRead);
                    bytesTotal += bytesRead;
                }
                else
                {
                    // decrypt cbc/cfb
                    int fnlSize = bytesRead - _cipherPadding.GetPaddingLength(outputBuffer);
                    WorkStream.Position -= bytesRead;
                    WorkStream.Write(outputBuffer, 0, fnlSize);
                    bytesTotal += fnlSize;
                }
            }

            CalculateProgress(bytesTotal);
        }

        private void ProcessStream(FileStream WorkStream)
        {
            int bytesRead = 0;
            long bytesTotal = 0;
            byte[] inputBuffer = new byte[_blockSize];
            byte[] outputBuffer = new byte[_blockSize];

            // loop through file
            while ((bytesRead = WorkStream.Read(inputBuffer, 0, _blockSize)) == _blockSize)
            {
                _streamCipher.Transform(inputBuffer, outputBuffer);
                WorkStream.Position -= bytesRead;
                WorkStream.Write(outputBuffer, 0, bytesRead);
                bytesTotal += bytesRead;
                CalculateProgress(bytesTotal);
            }

            // last block
            if (bytesRead > 0)
            {
                outputBuffer = new byte[bytesRead];
                _streamCipher.Transform(inputBuffer, outputBuffer);
                WorkStream.Position -= bytesRead;
                WorkStream.Write(outputBuffer, 0, bytesRead);
                bytesTotal += bytesRead;
            }

            CalculateProgress(bytesTotal);
        }
        #endregion

        #region Helpers
        private void CalculateProgress(long Size)
        {
            if (ProgressPercent != null)
            {
                double progress = 100.0 * (double)Size / _progressTotal;
                ProgressPercent(this, new System.ComponentModel.ProgressChangedEventArgs((int)progress, (object)Size));
            }
        }

        private FileStream GetStream(string FilePath)
        {
            try
            {
                return new FileStream(FilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read, 64000, FileOptions.WriteThrough);
            }
            catch
            {
                return null;
            }
        }

        private void Initialize(string[] FilePaths)
        {
            for (int i = 0; i < FilePaths.Length; i++)
                _progressTotal += FileTools.GetSize(FilePaths[i]);

            if (!_isParallel)
                _blockSize = _volumeKey.Description.BlockSize;
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
                    if (_disposeEngine)
                    {
                        if (_cipherEngine != null)
                        {
                            _cipherEngine.Dispose();
                            _cipherEngine = null;
                        }
                        if (_cipherPadding != null)
                        {
                            _cipherPadding = null;
                        }
                        if (_streamCipher != null)
                        {
                            _streamCipher.Dispose();
                            _streamCipher = null;
                        }
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
