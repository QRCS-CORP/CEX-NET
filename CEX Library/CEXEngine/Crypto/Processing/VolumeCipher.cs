#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Tools;
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
    /// VolumeCipher: Performs bulk file cryptographic transforms.
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
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
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
        private bool _isEncryption = true;
        private long _progressTotal = 0;
        private bool _isDisposed = false;
        private VolumeKey _volumeKey;
        private Stream _keyStream;
        private CipherStream _cipherStream;
        #endregion
        
        #region Properties
        /// <summary>
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return _cipherStream.IsParallel; }
            set { _cipherStream.IsParallel = value; }
        }

        /// <summary>
        /// Get/Set: Determines how the size of a parallel block is calculated
        /// </summary>
        public CipherStream.BlockProfiles ParallelBlockProfile
        {
            get { return _cipherStream.ParallelBlockProfile; }
            set { _cipherStream.ParallelBlockProfile = value; }
        }

        /// <summary>
        /// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
        /// </summary>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, 
        /// or the size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return _cipherStream.ParallelBlockSize; }
            set
            {
                try
                {
                    _cipherStream.ParallelBlockSize = value;
                }
                catch (Exception ex)
                {
                    throw new CryptoProcessingException("VolumeCipher:ParallelBlockSize", "The block size is invalid!", ex);
                }
            }
        }

        /// <summary>
        /// Get: Maximum input size with parallel processing
        /// </summary>
        public int ParallelMaximumSize
        {
            get { return _cipherStream.ParallelMaximumSize; }
        }

        /// <summary>
        /// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
        /// </summary>
        public int ParallelMinimumSize
        {
            get { return _cipherStream.ParallelMinimumSize; }
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

            _isEncryption = Encryption;
            CipherDescription desc = _volumeKey.Description;

            try
            {
                _cipherStream = new CipherStream(desc);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("VolumeCipher:CTor", "The cipher could not be initialized!", ex);
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
            if (FilePaths.Length < 1)
                throw new CryptoProcessingException("VolumeCipher:Transform", "The file paths list is empty!", new ArgumentException());
            if (_isEncryption && _volumeKey.KeyCount() < FilePaths.Length)
                throw new CryptoProcessingException("VolumeCipher:Transform", "Not enough keys in the volume key to encrypt this directory!", new ArgumentException());
            
            Initialize(FilePaths);

            if (_progressTotal < 1)
                throw new CryptoProcessingException("VolumeCipher:Initialize", "The files are all zero bytes!", new ArgumentException());

            long prgCtr = 0;

            for (int i = 0; i < FilePaths.Length; i++)
            {
                // next key
                int index = -1;
                FileStream inpStream;
                FileStream outStream;
                KeyParams key;
                int hash = GetFileNameHash(FilePaths[i]);//TODO: check this..
                inpStream = GetStream(FilePaths[i]);
                outStream = GetStream(FilePaths[i]);

                // should notify or log
                if (inpStream == null || outStream == null)
                {
                    if (ErrorNotification != null)
                        ErrorNotification(this, String.Format("The file {0}; could not be written to", FilePaths[i]));
                }
                else
                {
                    if (_isEncryption)
                    {
                        // get an unused key
                        index = _volumeKey.NextSubKey();
                        key = VolumeKey.AtIndex(_keyStream, index);
                        if (key == null)
                        {
                            if (ErrorNotification != null)
                                ErrorNotification(this, String.Format("The file {0}; has no key assigned", FilePaths[i]));
                        }
                        else
                        {
                            // update header
                            _volumeKey.FileId[index] = hash;
                            _volumeKey.State[index] = (byte)VolumeKeyStates.Encrypted;
                            _cipherStream.Initialize(_isEncryption, key);
                            _cipherStream.Write(inpStream, outStream);
                        }
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
                        }
                        else
                        {
                            _volumeKey.State[_volumeKey.GetIndex(hash)] = (byte)VolumeKeyStates.Decrypted;
                            _cipherStream.Initialize(_isEncryption, key);
                            _cipherStream.Write(inpStream, outStream);
                        }
                    }
                }

                prgCtr += inpStream.Position;
                CalculateProgress(prgCtr);

                inpStream.Close();
                inpStream.Dispose();
                outStream.Close();
                outStream.Dispose();
            }

            // update the key header
            if (_isEncryption)
            {
                byte[] ks = _volumeKey.ToBytes();
                _keyStream.Seek(0, SeekOrigin.Begin);
                _keyStream.Write(ks, 0, ks.Length);
            }
        }
        #endregion

        #region Helpers
        private void CalculateProgress(long Size)
        {
            if (ProgressPercent != null && Size > 0)
            {
                double progress = 100.0 * (double)Size / _progressTotal;
                ProgressPercent(this, new System.ComponentModel.ProgressChangedEventArgs((int)progress, (object)Size));
            }
        }
        private int GetFileNameHash(string FileName)
        {
            // remove root for portable drives
            string trnName = FileName.Substring(0, FileName.Length - Path.GetPathRoot(FileName).Length);
            byte[] hash;
            using (Digest.SHA256 eng = new Digest.SHA256())
                hash = eng.ComputeHash(System.Text.Encoding.Unicode.GetBytes(trnName));

            while (hash.Length > 4)
                hash = Reduce(hash);

            int[] ret = new int[1];
            Buffer.BlockCopy(hash, 0, ret, 0, 4);
            return ret[0];
        }

        private FileStream GetStream(string FilePath)
        {
            try
            {
                return new FileStream(FilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, 64000, FileOptions.WriteThrough);
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
        }

        private byte[] Reduce(byte[] Seed)
        {
            int len = Seed.Length / 2;
            byte[] data = new byte[len];

            for (int i = 0; i < len; i++)
                data[i] = (byte)(Seed[i] ^ Seed[len + i]);

            return data;
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
                    _isEncryption = false;
                    _progressTotal = 0;
                    _volumeKey.Reset();
                    if (_cipherStream != null)
                        _cipherStream.Dispose();
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
