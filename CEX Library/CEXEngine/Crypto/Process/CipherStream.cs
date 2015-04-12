#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Structures;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
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

namespace VTDev.Libraries.CEXEngine.Crypto.Process
{
    /// <summary>
    /// <h3>Cipher stream helper class.</h3>
    /// <para>Wraps encryption stream functions in an easy to use interface.</para>
    /// 
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example of encrypting a Stream:</description>
    /// <code>
    /// using (ICipherMode cipher = new CTR(new RDX()))
    /// {
    ///     // initialize the cipher
    ///     cipher.Initialize(true, new KeyParams(Key, Iv));
    ///     
    ///     using (CipherStream cstrm = new CipherStream(cipher, [false]))
    ///     {
    ///         // assign the input and output streams
    ///         cstrm.Initialize(InputStream, OutputStream, [true]);
    ///         // encrypt/decrypt write to the output stream
    ///         cstrm.Write([InOffset], [OutOffset]);
    ///     }
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Mode.ICipherMode">VTDev.Libraries.CEXEngine.Crypto.Mode.ICipherMode Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Engines">VTDev.Libraries.CEXEngine.Crypto.Engines Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Uses any of the implemented <see cref="ICipherMode">Cipher Mode</see> wrapped <see cref="Engines">Block Ciphers</see>, or any of the implemented <see cref="IStreamCipher">Stream Ciphers</see>.</description></item>
    /// <item><description>Cipher Engine can be Disposed when this class is <see cref="Dispose()">Disposed</see>, set the DisposeEngine parameter in the class Constructor to true to dispose automatically.</description></item>
    /// <item><description>Streams can be Disposed when the class is <see cref="Dispose()">Disposed</see>, set the DisposeStream parameter in the <see cref="Initialize(Stream, Stream, bool)"/> call to true to dispose automatically.</description></item>
    /// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per any of the <see cref="Write()">Write()</see> calls.</description></item>
    /// <item><description>Changes to the Cipher or StreamCipher <see cref="ParallelBlockSize">ParallelBlockSize</see> must be set after initialization.</description></item>
    /// </list>
    /// </remarks>
    public sealed class CipherStream : IDisposable
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
        /// Progress Percent Event; returns bytes processed as an integer percentage
        /// </summary>
        public event ProgressDelegate ProgressPercent;
        #endregion

        #region Fields
        private int _blockSize = PARALLEL_DEFBLOCK;
        private ICipherMode _cipherEngine;
        private IPadding _cipherPadding;
        private bool _disposeEngine = false;
        private bool _disposeStream = false;
        private Stream _inStream;
        private bool _isCounterMode = false;
        private bool _isDisposed = false;
        private bool _isEncryption = true;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private bool _isStreamCipher = false;
        private BlockProfiles _parallelBlockProfile = BlockProfiles.ProgressProfile;
        private long _progressInterval = 1024;
        private int _processorCount;
        private Stream _outStream;
        private IStreamCipher _streamCipher;
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
        /// <exception cref="System.ArgumentException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if parallel block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return _blockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new ArgumentException(String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize));
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new ArgumentOutOfRangeException(String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize));

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
                    if (_streamCipher.GetType().Equals(typeof(Fusion)))
                        return ((Fusion)_streamCipher).ParallelMinimumSize;
                    else
                        return 0;
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
        /// Initialize the class with a KeyHeader Structure; containing the cipher description, and a <see cref="KeyParams"/> class containing the Key material.
        /// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription. 
        /// Cipher modes, padding, and engines are destroyed automatically through this classes Dispose() method.</para>
        /// </summary>
        /// 
        /// <param name="Encryption">Cipher is an encryptor</param>
        /// <param name="Header">A <see cref="CipherDescription"/> containing the cipher description</param>
        /// <param name="KeyParam">A <see cref="KeyParams"/> class containing the encryption Key material</param>
        /// 
        /// <exception cref="System.ArgumentException">Thrown if an invalid <see cref="CipherDescription">CipherDescription</see> is used</exception>
        /// <exception cref="System.ArgumentNullException">Thrown if a null <see cref="KeyParams">KeyParams</see> is used</exception>
        public CipherStream(bool Encryption, CipherDescription Header, KeyParams KeyParam)
        {
            if (!CipherDescription.IsValid(Header))
                throw new ArgumentException("The key Header is invalid!");
            if (KeyParam == null)
                throw new ArgumentNullException("KeyParam can not be null!");

            _disposeEngine = true;
            _isEncryption = Encryption;
            _blockSize = Header.BlockSize;
            _isParallel = false;

            if (_isStreamCipher = IsStreamCipher((Engines)Header.EngineType))
            {
                _streamCipher = GetStreamEngine((Engines)Header.EngineType, Header.RoundCount, (Digests)Header.KdfEngine);
                _streamCipher.Initialize(KeyParam);

                if (_streamCipher.GetType().Equals(typeof(Fusion)))
                {
                    if (_isParallel = ((Fusion)_streamCipher).IsParallel)
                        _blockSize = ((Fusion)_streamCipher).ParallelBlockSize;
                }
            }
            else
            {
                _cipherEngine = GetCipher((CipherModes)Header.CipherType, (Engines)Header.EngineType, Header.RoundCount, Header.BlockSize, (Digests)Header.KdfEngine);
                _cipherEngine.Initialize(_isEncryption, KeyParam);
                
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
                    _cipherPadding = GetPadding((PaddingModes)Header.PaddingType);
                }
            }
        }

        /// <summary>
        /// Initialize the class with a Block <see cref="ICipherMode">Cipher</see> and optional <see cref="IPadding">Padding</see> instances.
        /// <para>This constructor requires a fully initialized <see cref="CipherModes">CipherMode</see> instance.
        /// If the <see cref="PaddingModes">PaddingMode</see> parameter is null, X9.23 padding will be used if required.</para>
        /// </summary>
        /// 
        /// <param name="Cipher">The <see cref="Engines">Block Cipher</see> wrapped in a <see cref="ICipherMode">Cipher</see> mode</param>
        /// <param name="Padding">The <see cref="IPadding">Padding</see> instance</param>
        /// <param name="DisposeEngine">Dispose of cipher engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null <see cref="ICipherMode">Cipher</see> is used</exception>
        /// <exception cref="System.ArgumentException">Thrown if an uninitialized Cipher is used</exception>
        public CipherStream(ICipherMode Cipher, IPadding Padding = null, bool DisposeEngine = false)
        {
            if (Cipher == null)
                throw new ArgumentNullException("The Cipher can not be null!");
            if (!Cipher.IsInitialized)
                throw new ArgumentException("The Cipher has not been initialized!");

            _disposeEngine = DisposeEngine;
            _cipherEngine = Cipher;
            _isStreamCipher = false;
            _blockSize = _cipherEngine.BlockSize;
            _isEncryption = _cipherEngine.IsEncryption;
            _isParallel = false;

            if (_isCounterMode = _cipherEngine.GetType().Equals(typeof(CTR)))
            {
                if (_isParallel = ((CTR)_cipherEngine).IsParallel)
                    _blockSize = ((CTR)_cipherEngine).ParallelBlockSize;
            }
            else 
            {
                if (_cipherEngine.GetType().Equals(typeof(CBC)))
                    _isParallel = ((CBC)_cipherEngine).IsParallel && !((CBC)_cipherEngine).IsEncryption;

                // default padding
                if (Padding == null)
                    _cipherPadding = new X923();
            }
        }

        /// <summary>
        /// Initialize the class with a <see cref="IStreamCipher">Stream Cipher</see> instance.
        /// <para>This constructor requires a fully initialized <see cref="Engines">StreamCipher</see> instance.</para>
        /// </summary>
        /// 
        /// <param name="Cipher">The initialized <see cref="IStreamCipher">Stream Cipher</see> instance</param>
        /// <param name="DisposeEngine">Dispose of cipher engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null <see cref="IStreamCipher">Stream Cipher</see> is used</exception>
        /// <exception cref="System.ArgumentException">Thrown if an uninitialized Cipher is used</exception>
        public CipherStream(IStreamCipher Cipher, bool DisposeEngine = true)
        {
            if (Cipher == null)
                throw new ArgumentNullException("The Cipher can not be null!");
            if (!Cipher.IsInitialized)
                throw new ArgumentException("The Cipher has not been initialized!");

            _disposeEngine = DisposeEngine;
            _streamCipher = Cipher;
            _isStreamCipher = true;
            _blockSize = 1024;
            _isCounterMode = false;

            // set defaults
            if (_streamCipher.GetType().Equals(typeof(Fusion)))
            {
                if (_isParallel = ((Fusion)_streamCipher).IsParallel)
                    _blockSize = ((Fusion)_streamCipher).ParallelBlockSize;
            }
            else
            {
                _isParallel = false;
            }
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CipherStream()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize internal state
        /// </summary>
        /// 
        /// <param name="InStream">The Source stream to be transformed</param>
        /// <param name="OutStream">The transformed Output stream</param>
        /// <param name="DisposeStream">Dispose of streams when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Input or Output stream is used</exception>
        public void Initialize(Stream InStream, Stream OutStream, bool DisposeStream = false)
        {
            if (InStream == null)
                throw new ArgumentNullException("The Input stream can not be null!");
            if (OutStream == null)
                throw new ArgumentNullException("The Output stream can not be null!");

            _disposeStream = DisposeStream;
            _inStream = InStream;
            _outStream = OutStream;

            // pre allocate size for less fragmentation
            if (_isEncryption)
            {
                _outStream.SetLength(_inStream.Length + _outStream.Position);
            }
            else
            {
                long len = _inStream.Length - _inStream.Position;
                if (!_isStreamCipher)
                    len -= _cipherEngine.BlockSize;

                _outStream.SetLength(len);
            }

            if (_isParallel)
            {
                CalculateBlockSize();
                _progressInterval = InStream.Length / _blockSize;
            }
            else
            {
                _progressInterval = InStream.Length / _blockSize;
            }

            CalculateInterval(0);
            _isInitialized = true;
        }

        /// <summary>
        /// Process the entire length of the Input Stream (fastest)
        /// </summary>
        /// 
        /// <exception cref="System.InvalidOperationException">Thrown if Write is called before Initialize()</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if Size + Offset is longer than Input stream</exception>
        public void Write()
        {
            if (!_isInitialized)
                throw new InvalidOperationException("Initialize() must be called before a write operation can be performed!");
            if (_inStream.Length < 1)
                throw new ArgumentOutOfRangeException("The Input stream is too short!");

            if (!_isStreamCipher)
            {
                if (_isParallel)
                {
                    ProcessParallel();
                }
                else
                {
                    if (_isEncryption)
                        Encrypt();
                    else
                        Decrypt();
                }
            }
            else
            {
                ProcessStream();
            }
        }

        /// <summary>
        /// Process a length within the Input stream using Offsets
        /// </summary>
        /// 
        /// <param name="InOffset">The Input Stream positional offset</param>
        /// <param name="OutOffset">The Output Stream positional offset</param>
        /// 
        /// <exception cref="System.InvalidOperationException">Thrown if Write is called before Initialize()</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if Size + Offset is longer than Input stream</exception>
        public void Write(long InOffset = 0, long OutOffset = 0)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("Initialize() must be called before a write operation can be performed!");
            if (_inStream.Length - InOffset < 1)
                throw new ArgumentOutOfRangeException("The Input stream is too short!");

            _inStream.Position = InOffset;
            _outStream.Position = OutOffset;

            if (InOffset > 0)
                CalculateInterval(InOffset);

            if (!_isStreamCipher)
            {
                if (_isParallel)
                {
                    ProcessParallel();
                }
                else
                {
                    if (_isEncryption)
                        Encrypt();
                    else
                        Decrypt();
                }
            }
            else
            {
                ProcessStream();
            }
        }
        #endregion

        #region Crypto
        private void Decrypt()
        {
            byte[] inputBuffer = new byte[_blockSize];
            byte[] outputBuffer = new byte[_blockSize];
            int bytesRead = 0;
            long bytesTotal = 0;
            long lastBlock = _inStream.Length - _inStream.Position;

            while ((bytesRead = _inStream.Read(inputBuffer, 0, _blockSize)) == _blockSize)
            {
                _cipherEngine.Transform(inputBuffer, outputBuffer);
                bytesTotal += bytesRead;

                if (bytesTotal < lastBlock)
                {
                    _outStream.Write(outputBuffer, 0, _blockSize);
                    CalculateProgress(bytesTotal);
                }
                else
                {
                    int fnlSize = _cipherEngine.BlockSize - _cipherPadding.GetPaddingLength(outputBuffer);
                    _outStream.Write(outputBuffer, 0, fnlSize);
                    bytesTotal += fnlSize;
                }
            }

            CalculateProgress(bytesTotal, true);
        }

        private void Encrypt()
        {
            byte[] inputBuffer = new byte[_blockSize];
            byte[] outputBuffer = new byte[_blockSize];
            int bytesRead = 0;
            long bytesTotal = 0;

            while ((bytesRead = _inStream.Read(inputBuffer, 0, _blockSize)) == _blockSize)
            {
                _cipherEngine.Transform(inputBuffer, outputBuffer);
                _outStream.Write(outputBuffer, 0, bytesRead);
                bytesTotal += bytesRead;
                CalculateProgress(bytesTotal);
            }

            if (bytesRead > 0)
            {
                if (bytesRead < _blockSize)
                    _cipherPadding.AddPadding(inputBuffer, (int)bytesRead);

                _cipherEngine.Transform(inputBuffer, outputBuffer);
                _outStream.Write(outputBuffer, 0, _blockSize);
                bytesTotal += bytesRead;
            }

            CalculateProgress(bytesTotal, true);
        }

        private IBlockCipher GetBlockEngine(Engines EngineType, int RoundCount, int BlockSize, Digests KdfEngine)
        {
            if (EngineType == Engines.RDX)
                return new RDX(BlockSize);
            else if (EngineType == Engines.RHX)
                return new RHX(RoundCount, BlockSize, KdfEngine);
            else if (EngineType == Engines.RSM)
                return new RSM(RoundCount, BlockSize, KdfEngine);
            else if (EngineType == Engines.SHX)
                return new SHX(RoundCount, KdfEngine);
            else if (EngineType == Engines.SPX)
                return new SPX(RoundCount);
            else if (EngineType == Engines.TFX)
                return new TFX(RoundCount);
            else if (EngineType == Engines.THX)
                return new THX(RoundCount, KdfEngine);
            else if (EngineType == Engines.TSM)
                return new TSM(RoundCount, KdfEngine);
            else
                return new RHX(RoundCount, BlockSize, KdfEngine);
        }

        private ICipherMode GetCipher(CipherModes CipherType, Engines EngineType, int RoundCount, int BlockSize, Digests KdfEngine)
        {
            if (CipherType == CipherModes.CBC)
                return new CBC(GetBlockEngine(EngineType, RoundCount, BlockSize, KdfEngine));
            else if (CipherType == CipherModes.CFB)
                return new CFB(GetBlockEngine(EngineType, RoundCount, BlockSize, KdfEngine), BlockSize * 8);
            else if (CipherType == CipherModes.OFB)
                return new OFB(GetBlockEngine(EngineType, RoundCount, BlockSize, KdfEngine));
            else
                return new CTR(GetBlockEngine(EngineType, RoundCount, BlockSize, KdfEngine));
        }

        private IPadding GetPadding(PaddingModes PaddingType)
        {
            if (PaddingType == PaddingModes.ISO7816)
                return new ISO7816();
            else if (PaddingType == PaddingModes.PKCS7)
                return new PKCS7();
            else if (PaddingType == PaddingModes.TBC)
                return new TBC();
            else if (PaddingType == PaddingModes.X923)
                return new X923();
            else
                return new PKCS7();
        }

        private IStreamCipher GetStreamEngine(Engines EngineType, int RoundCount, Digests KdfEngine)
        {
            if (EngineType == Engines.ChaCha)
                return new ChaCha(RoundCount);
            else if (EngineType == Engines.Fusion)
                return new Fusion(RoundCount, KdfEngine);
            else if (EngineType == Engines.Salsa)
                return new Salsa20(RoundCount);
            else
                return null;
        }

        private bool IsStreamCipher(Engines EngineType)
        {
            return EngineType == Engines.ChaCha ||
                EngineType == Engines.Salsa ||
                EngineType == Engines.Fusion;
        }

        private void ProcessParallel()
        {
            long bytesTotal = 0;
            int bytesRead = 0;
            byte[] inputBuffer = new byte[_blockSize];
            byte[] outputBuffer = new byte[_blockSize];

            // loop through file
            while ((bytesRead = _inStream.Read(inputBuffer, 0, _blockSize)) == _blockSize)
            {
                bytesTotal += bytesRead;
                _cipherEngine.Transform(inputBuffer, outputBuffer);
                _outStream.Write(outputBuffer, 0, bytesRead);
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
                    _outStream.Write(outputBuffer, 0, bytesRead);
                    bytesTotal += bytesRead;
                }
                else
                {
                    // decrypt cbc/cfb
                    int fnlSize = bytesRead - _cipherPadding.GetPaddingLength(outputBuffer);
                    _outStream.Write(outputBuffer, 0, fnlSize);
                    bytesTotal += fnlSize;
                }
            }

            CalculateProgress(bytesTotal, true);
        }

        private void ProcessStream()
        {
            int bytesRead = 0;
            long bytesTotal = 0;
            byte[] inputBuffer = new byte[_blockSize];
            byte[] outputBuffer = new byte[_blockSize];

            // loop through file
            while ((bytesRead = _inStream.Read(inputBuffer, 0, _blockSize)) == _blockSize)
            {
                _streamCipher.Transform(inputBuffer, outputBuffer);
                _outStream.Write(outputBuffer, 0, bytesRead);
                bytesTotal += bytesRead;
                CalculateProgress(bytesTotal);
            }

            // last block
            if (bytesRead > 0)
            {
                outputBuffer = new byte[bytesRead];
                _streamCipher.Transform(inputBuffer, outputBuffer);
                _outStream.Write(outputBuffer, 0, bytesRead);
                bytesTotal += bytesRead;
            }

            CalculateProgress(bytesTotal, true);
        }
        #endregion

        #region Helpers
        private void CalculateBlockSize()
        {
            int cipherBlock = 1024;
            int block = 0;

            if (!_isStreamCipher)
                cipherBlock = _cipherEngine.BlockSize;

            // calculate for even progress intervals -or- largest block size
            if (_parallelBlockProfile == BlockProfiles.ProgressProfile)
            {
                if (_inStream.Length / 100 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 100);
                else if (_inStream.Length / 200 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 200);
                else if (_inStream.Length / 400 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 400);
                else if (_inStream.Length / 600 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 600);
                else if (_inStream.Length / 800 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 800);
                else if (_inStream.Length / 1000 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 1000);
                else if (_inStream.Length / 2000 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 2000);
                else if (_inStream.Length / 4000 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 4000);
                else if (_inStream.Length / 6000 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 6000);
                else if (_inStream.Length / 8000 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 8000);
                else if (_inStream.Length / 10000 < ParallelMaximumSize)
                    block = (int)(_inStream.Length / 10000);
                else
                    block = ParallelMaximumSize;

                if (block < ParallelMinimumSize)
                    block = ParallelMinimumSize;

                if (block > cipherBlock && block % cipherBlock > 0)
                    block -= (block % ParallelMinimumSize);
            }
            else
            {
                if (_inStream.Length > MAXALLOC_MB100)
                    block = MAXALLOC_MB100;
                else
                    block = (int)(_inStream.Length - ((_inStream.Length - _inStream.Position) % ParallelMinimumSize));
            }

            if (block <= _inStream.Length)
                SetBlockSize(block);
        }

        private void CalculateInterval(long Offset)
        {
            if (_isParallel)
            {
                _progressInterval = _blockSize;
            }
            else
            {
                long interval = (_inStream.Length - Offset) / 100;

                if (interval < _blockSize)
                    _progressInterval = _blockSize;
                else
                    _progressInterval = interval - (interval % _blockSize);

                if (_progressInterval == 0)
                    _progressInterval = _blockSize;
            }
        }

        private void CalculateProgress(long Size, bool Completed = false)
        {
            if (ProgressPercent != null)
            {
                if (Completed || Size % _progressInterval == 0)
                {
                    double progress = 100.0 * (double)Size / _inStream.Length;
                    ProgressPercent(this, new System.ComponentModel.ProgressChangedEventArgs((int)progress, (object)Size));
                }
            }
        }

        private void SetBlockSize(int Size)
        {
            if (_isParallel)
            {
                if (Size % ParallelMinimumSize > 0)
                {
                    if (Size - Size % ParallelMinimumSize >= ParallelMinimumSize)
                        Size -= Size % ParallelMinimumSize;
                    else
                        Size = ParallelMinimumSize;
                }

                if (_isStreamCipher)
                {
                    if (_streamCipher.GetType().Equals(typeof(Fusion)))
                        ((Fusion)_streamCipher).ParallelBlockSize = Size;
                }
                else
                {
                    if (_cipherEngine.GetType().Equals(typeof(CTR)))
                        ((CTR)_cipherEngine).ParallelBlockSize = Size;
                    else if (_cipherEngine.GetType().Equals(typeof(CBC)))
                        ((CBC)_cipherEngine).ParallelBlockSize = Size;
                    else if (_cipherEngine.GetType().Equals(typeof(CFB)))
                        ((CFB)_cipherEngine).ParallelBlockSize = Size;
                }
            }

            _blockSize = Size;
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
                    if (_disposeStream)
                    {
                        if (_inStream != null)
                        {
                            _inStream.Dispose();
                            _inStream = null;
                        }
                        if (_outStream != null)
                        {
                            _outStream.Dispose();
                            _outStream = null;
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
