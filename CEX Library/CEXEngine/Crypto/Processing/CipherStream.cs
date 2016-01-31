﻿#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
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
    /// CipherStream: Used to wrap a streams cryptographic transformation.
    /// <para>Wraps encryption stream functions in an easy to use interface.</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example of encrypting and decrypting a Stream:</description>
    /// <code>
    /// public static void StreamCipherTest()
    /// {
    ///     KeyParams key;
    ///     byte[] data;
    ///     MemoryStream instrm;
    ///     MemoryStream outstrm = new MemoryStream();
    /// 
    ///     using (KeyGenerator kg = new KeyGenerator())
    ///     {
    ///         // get the key
    ///         key = kg.GetKeyParams(32, 16);
    ///         // 2048 bytes
    ///         data = kg.GetBytes(BLSZ * 2);
    ///     }
    ///     // data to encrypt
    ///     instrm = new MemoryStream(data);
    /// 
    ///     // Encrypt a stream //
    ///     // create the outbound cipher
    ///     using (ICipherMode cipher = new CTR(new RHX()))
    ///     {
    ///         // encrypt the stream
    ///         using (CipherStream sc = new CipherStream(cipher))
    ///         {
    ///             sc.Initialize(true, key);
    ///             // encrypt the buffer
    ///             sc.Write(instrm, outstrm);
    ///         }
    ///     }
    /// 
    ///     // reset stream position
    ///     outstrm.Seek(0, SeekOrigin.Begin);
    ///     MemoryStream tmpstrm = new MemoryStream();
    /// 
    ///     // Decrypt a stream //
    ///     // create the decryption cipher
    ///     using (ICipherMode cipher = new CTR(new RHX()))
    ///     {
    ///         // decrypt the stream
    ///         using (CipherStream sc = new CipherStream(cipher))
    ///         {
    ///             sc.Initialize(false, key);
    ///             // process the encrypted bytes
    ///             sc.Write(outstrm, tmpstrm);
    ///         }
    ///     }
    /// 
    ///     // compare decrypted output with data
    ///     if (!Equate.AreEqual(tmpstrm.ToArray(), data))
    ///         throw new Exception();
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
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
    /// <item><description>Cipher Engine can be Disposed when this class is <see cref="Dispose()">Disposed</see>, set the DisposeEngine parameter in the class Constructor to true to dispose automatically.</description></item>
    /// <item><description>Streams can be Disposed when the class is <see cref="Dispose()">Disposed</see>, set the DisposeStream parameter in the <see cref="Initialize(bool, KeyParams)"/> call to true to dispose automatically.</description></item>
    /// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per either of the <see cref="Write(Stream, Stream)">Write()</see> calls.</description></item>
    /// <item><description>Changes to the Cipher or CipherStream <see cref="ParallelBlockSize">ParallelBlockSize</see> must be set after initialization.</description></item>
    /// </list>
    /// </remarks>
    public class CipherStream : IDisposable
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
            ProgressProfile = 1,
            /// <summary>
            /// Set parallel block size for maximum possible speed
            /// </summary>
            SpeedProfile = 2,
            /// <summary>
            /// The block size is specified by the user
            /// </summary>
            UserDefined = 4
        }
        #endregion

        #region Constants
        // Max array size allocation base; multiply by processor count for actual
        // byte/memory allocation during parallel loop execution
        private const int MAXALLOC_MB100 = 100000000;
        // default parallel block size
        private const int PARALLEL_DEFBLOCK = 64000;
        #endregion

        #region Event Args
        /// <summary>
        /// An event arguments class containing the decrypted message data.
        /// </summary>
        public class ProgressEventArgs : EventArgs
        {
            #region Fields
            /// <summary>
            /// Length of the stream
            /// </summary>
            public long Length = 0;
            /// <summary>
            /// The percentage of data processed
            /// </summary>
            public int Percent = 0;
            #endregion

            #region Constructor
            /// <summary>
            /// Initialize this class
            /// </summary>
            /// 
            /// <param name="Length">Length of the stream</param>
            /// <param name="Percent">The percentage of data processed</param>
            public ProgressEventArgs(long Length, int Percent)
            {
                this.Length = Length;
                this.Percent = Percent;
            }
            #endregion
        }
        #endregion

        #region Events
        /// <summary>
        /// Progress indicator delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="args">Progress event arguments containing percentage and bytes processed as the UserState param</param>
        public delegate void ProgressDelegate(object sender, ProgressEventArgs args);

        /// <summary>
        /// Progress Percent Event; returns bytes processed as an integer percentage
        /// </summary>
        public event ProgressDelegate ProgressPercent;
        #endregion

        #region Fields
        private int _blockSize = 0;
        private ICipherMode _cipherEngine;
        private IPadding _cipherPadding;
        private bool _destroyEngine = false;
        private bool _isCounterMode = false;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private bool _isStreamCipher = false;
        private int _parallelBlockSize = PARALLEL_DEFBLOCK;
        private int _processorCount = 0;
        private BlockProfiles _parallelBlockProfile = BlockProfiles.UserDefined;
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
        /// <exception cref="CryptoProcessingException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, 
        /// or the size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return _blockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoProcessingException("CipherStream:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoProcessingException("CipherStream:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

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
                        return _blockSize * _processorCount;
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
        /// <param name="EngineType">The encryption engine type</param>
	    /// <param name="RoundCount">The number of transformation rounds</param>
	    /// <param name="CipherType">The cipher mode</param>
	    /// <param name="PaddingType">The padding type</param>
	    /// <param name="BlockSize">The cipher blocksize</param>
	    /// <param name="KdfEngine">The HX ciphers key schedule engine</param>
	    /// 
	    /// <exception cref="CryptoProcessingException">Thrown if an invalid <see cref="CipherDescription">CipherDescription</see> or <see cref="KeyParams">KeyParams</see> is used</exception>
	    public CipherStream(SymmetricEngines EngineType, int RoundCount = 22, CipherModes CipherType = CipherModes.CTR, PaddingModes PaddingType = PaddingModes.PKCS7, int BlockSize = 16, Digests KdfEngine = Digests.SHA512)
	    {
		    _destroyEngine = true;
		    SetScope();

		    if (EngineType == SymmetricEngines.ChaCha || EngineType == SymmetricEngines.Salsa)
		    {
			    try
			    {
				    _streamCipher = GetStreamCipher((StreamCiphers)EngineType, RoundCount);
			    }
			    catch (Exception ex)
			    {
				    throw new CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check method parameters!", ex);
			    }

                _isStreamCipher = true;
                ParametersCheck();
		    }
		    else
		    {
			    try
			    {
				    _cipherEngine = GetCipherMode(CipherType, (BlockCiphers)EngineType, BlockSize, RoundCount, KdfEngine);
			    }
                catch (Exception ex)
			    {
				    throw new CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check method parameters!", ex);
			    }

                _isStreamCipher = false;
                ParametersCheck();

			    if (!_isCounterMode)
				    _cipherPadding = GetPaddingMode(PaddingType);
		    }
	    }

	    /// <summary>
	    /// Initialize the class with a CipherDescription Structure; containing the cipher implementation details.
	    /// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription. 
	    /// Cipher modes, padding, and engines are destroyed automatically through this classes Destruct() method.</para>
	    /// </summary>
	    /// 
	    /// <param name="Header">A <see cref="CipherDescription"/> containing the cipher description</param>
	    /// 
	    /// <exception cref="CryptoProcessingException">Thrown if an invalid <see cref="CipherDescription">CipherDescription</see> is used</exception>
        public CipherStream(CipherDescription Header)
	    {
		    _destroyEngine = true;

		    if (Header == null)
			    throw new CryptoProcessingException("CipherStream:CTor", "The key Header is invalid!");

		    SetScope();

            if (Header.EngineType == (int)SymmetricEngines.ChaCha || Header.EngineType == (int)SymmetricEngines.Salsa)
		    {
			    try
			    {
				    _streamCipher = GetStreamCipher((StreamCiphers)Header.EngineType, (int)Header.RoundCount);
			    }
                catch (Exception ex)
			    {
				    throw new CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check description parameters!", ex);
			    }

                _isStreamCipher = true;
                ParametersCheck();
		    }
		    else
		    {
			    try
			    {
                    _cipherEngine = GetCipherMode((CipherModes)Header.CipherType, (BlockCiphers)Header.EngineType, (int)Header.BlockSize, (int)Header.RoundCount, (Digests)Header.KdfEngine);
			    }
                catch (Exception ex)
			    {
                    throw new CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check description parameters!", ex);
			    }

                _isStreamCipher = false;
                ParametersCheck();

			    if (!_isCounterMode)
				    _cipherPadding = GetPaddingMode((PaddingModes)Header.PaddingType);
		    }
	    }

	    /// <summary>
	    /// Initialize the class with a Block <see cref="ICipherMode">Cipher</see> and optional <see cref="IPadding">Padding</see> instances.
	    /// <para>This constructor requires a fully initialized <see cref="CipherModes">CipherMode</see> instance.
	    /// If the <see cref="PaddingModes">PaddingMode</see> parameter is null, X9.23 padding will be used if required.</para>
	    /// </summary>
	    /// 
	    /// <param name="Cipher">The <see cref="SymmetricEngines">Block Cipher</see> wrapped in a <see cref="ICipherMode">Cipher</see> mode</param>
	    /// <param name="Padding">The <see cref="IPadding">Padding</see> instance</param>
	    /// 
	    /// <exception cref="CryptoProcessingException">Thrown if a null or uninitialized <see cref="ICipherMode">Cipher</see> is used</exception>
        public CipherStream(ICipherMode Cipher, IPadding Padding = null)
	    {
		    _cipherEngine = Cipher;
		    _destroyEngine = false;
		    _isEncryption = Cipher.IsEncryption;
		    _isStreamCipher = false;

		    if (_cipherEngine.IsInitialized)
			    throw new CryptoProcessingException("CipherStream:CTor", "The cipher must be initialized through the local Initialize() method!");

		    SetScope();
            ParametersCheck();

			// default padding
			if (Padding != null)
				_cipherPadding = Padding;
            else if (_cipherEngine.Enumeral != CipherModes.CTR)
				_cipherPadding = GetPaddingMode(PaddingModes.X923);
	    }

	    /// <summary>
	    /// Initialize the class with a <see cref="IStreamCipher">Stream Cipher</see> instance.
	    /// <para>This constructor requires a fully initialized <see cref="SymmetricEngines">CipherStream</see> instance.</para>
	    /// </summary>
	    /// 
	    /// <param name="Cipher">The initialized <see cref="IStreamCipher">Stream Cipher</see> instance</param>
	    /// 
	    /// <exception cref="CryptoProcessingException">Thrown if a null or uninitialized <see cref="IStreamCipher">Stream Cipher</see> is used</exception>
        public CipherStream(IStreamCipher Cipher)
	    {
		    _destroyEngine = false;
		    _isStreamCipher = true;
            _streamCipher = Cipher;

		    if (Cipher == null)
			    throw new CryptoProcessingException("CipherStream:CTor", "The Cipher can not be null!");
		    if (Cipher.IsInitialized)
                throw new CryptoProcessingException("CipherStream:CTor", "The cipher must be initialized through the local Initialize() method!");

		    SetScope();
            ParametersCheck();
	    }

        /// <summary>
        /// Destroy this class
        /// </summary>
        ~CipherStream() 
	    {
            Dispose(false);
	    }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the cipher processing engine
        /// </summary>
        /// 
        /// <param name="Encryption">The cipher is used for encryption</param>
        /// <param name="KeyParam">The KeyParams containing the cipher key and initialization vector</param>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
	        try
	        {
		        if (!_isStreamCipher)
			        _cipherEngine.Initialize(Encryption, KeyParam);
		        else
			        _streamCipher.Initialize(KeyParam);
	        }
	        catch
	        {
		        throw new CryptoProcessingException("CipherStream:Initialize", "The key could not be loaded, check the key and iv sizes!");
	        }

	        _isEncryption = Encryption;
	        _isInitialized = true;
        }

        /// <summary>
        /// Process using streams.
        /// <para>The input stream is processed and returned in the output stream.</para>
        /// </summary>
        /// 
        /// <param name="InStream">The Input Stream</param>
        /// <param name="OutStream">The Output Stream</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if Write is called before Initialize(), or the Input stream is empty</exception>
        public void Write(Stream InStream, Stream OutStream)
        {
	        if (!_isInitialized)
		        throw new CryptoProcessingException("CipherStream:Write", "The cipher has not been initialized; call the Initialize() function first!");
	        if (InStream.Length - InStream.Position < 1)
		        throw new CryptoProcessingException("CipherStream:Write", "The Input stream is too short!");

	        // parallel min check and calc block size
	        long dlen = InStream.Length - InStream.Position;

            // par blk user size?
	        CalculateBlockSize(dlen);

            if (_isEncryption && dlen % _blockSize != 0)
            {
                long alen = (dlen - (dlen % _blockSize)) + _blockSize;
                OutStream.SetLength(alen);
            }
            else
            {
                OutStream.SetLength(dlen);
            }

	        if (!_isStreamCipher)
	        {
                if (_isParallel && IsParallelMin(dlen))
		        {
			        if (_isCounterMode)
			        {
				        ParallelCTR(InStream, OutStream);
			        }
			        else
			        {
				        if (_isEncryption)
					        BlockEncrypt(InStream, OutStream);
				        else
					        ParallelDecrypt(InStream, OutStream);
			        }
		        }
		        else
		        {
			        if (_isCounterMode)
			        {
				        BlockCTR(InStream, OutStream);
			        }
			        else
			        {
				        if (_isEncryption)
					        BlockEncrypt(InStream, OutStream);
				        else
					        BlockDecrypt(InStream, OutStream);
			        }
		        }
	        }
	        else
	        {
                if (_isParallel && IsParallelMin(dlen))
			        ParallelStream(InStream, OutStream);
		        else
			        ProcessStream(InStream, OutStream);
	        }

            OutStream.SetLength(OutStream.Position);
        }

        /// <summary>
        /// Process using byte arrays.
        /// <para>The Input array is processed and returned by the Output array.</para>
        /// </summary>
        /// 
        /// <param name="Input">The Input array</param>
        /// <param name="InOffset">The starting offset within the Input array</param>
        /// <param name="Output">The Output array</param>
        /// <param name="OutOffset">The starting offset within the Output array</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if Write is called before Initialize(), or if array sizes are misaligned</exception>
        public void Write(byte[] Input, int InOffset, ref byte[] Output, int OutOffset)
        {
	        if (!_isInitialized)
		        throw new CryptoProcessingException("CipherStream:Write", "The cipher has not been initialized; call the Initialize() function first!");
	        if (Input.Length - InOffset < 1)
		        throw new CryptoProcessingException("CipherStream:Write", "The Input array is too short!");
            if (Input.Length - InOffset > Output.Length - OutOffset)
                throw new CryptoProcessingException("CipherStream:Write", "The Output array is too short!");

	        // parallel min check and calc block size
            long dlen = Input.Length - InOffset;
	        CalculateBlockSize(dlen);

	        if (!_isStreamCipher)
	        {
                if (_isParallel && IsParallelMin(dlen))
		        {
			        if (_isCounterMode)
			        {
				        ParallelCTR(Input, InOffset, Output, OutOffset);
			        }
			        else
			        {
				        if (_isEncryption)
                            BlockEncrypt(Input, InOffset, ref Output, OutOffset);
				        else
					        ParallelDecrypt(Input, InOffset, ref Output, OutOffset);
			        }
		        }
		        else
		        {
			        if (_isCounterMode)
			        {
				        BlockCTR(Input, InOffset, Output, OutOffset);
			        }
			        else
			        {
				        if (_isEncryption)
                            BlockEncrypt(Input, InOffset, ref Output, OutOffset);
				        else
                            BlockDecrypt(Input, InOffset, ref Output, OutOffset);
			        }
		        }
	        }
	        else
	        {
                if (_isParallel && IsParallelMin(dlen))
			        ParallelStream(Input, InOffset, Output, OutOffset);
		        else
			        ProcessStream(Input, InOffset, Output, OutOffset);
	        }
        }
        #endregion

        #region Crypto
        private void BlockCTR(Stream InStream, Stream OutStream)
        {
	        int blkSize = _cipherEngine.BlockSize;
	        long inpSize = (InStream.Length - InStream.Position);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;
	        byte[] inpBuffer = new byte[blkSize];
	        byte[]  outBuffer = new byte[blkSize];

	        _cipherEngine.IsParallel = false;

	        while (count != alnSize)
	        {
		        InStream.Read(inpBuffer, 0, blkSize);
		        _cipherEngine.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, blkSize);
		        count += blkSize;
                CalculateProgress(inpSize, OutStream.Position);
	        }

	        if (alnSize != inpSize)
	        {
		        int fnlSize = (int)(inpSize - alnSize);
		        InStream.Read(inpBuffer, 0, fnlSize);
		        _cipherEngine.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, fnlSize);
		        count += fnlSize;
	        }

            CalculateProgress(inpSize, OutStream.Position);
        }

        private void BlockCTR(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
	        int blkSize = _cipherEngine.BlockSize;
	        long inpSize = (Input.Length - InOffset);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;

	        _cipherEngine.IsParallel = false;

	        while (count != alnSize)
	        {
		        _cipherEngine.Transform(Input, InOffset, Output, OutOffset);
		        InOffset += blkSize;
		        OutOffset += blkSize;
		        count += blkSize;
                CalculateProgress(inpSize, count);
	        }

	        // partial
	        if (alnSize != inpSize)
	        {
		        int cnkSize = (int)(inpSize - alnSize);
		        byte[] inpBuffer =  new byte[blkSize];
                Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, cnkSize);
		        byte[] outBuffer = new byte[blkSize];
		        _cipherEngine.Transform(inpBuffer, 0, outBuffer, 0);
                Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, cnkSize);
		        count += cnkSize;
	        }

            CalculateProgress(inpSize, count);
        }

        private void BlockDecrypt(Stream InStream, Stream OutStream)
        {
	        int blkSize = _cipherEngine.BlockSize;
	        long inpSize = (InStream.Length - InStream.Position);
	        long alnSize = (inpSize < blkSize) ? 0 : inpSize - blkSize;
	        long count = 0;
	        byte[] inpBuffer = new byte[blkSize];
	        byte[] outBuffer = new byte[blkSize];

	        _cipherEngine.IsParallel = false;

	        while (count != alnSize)
	        {
		        InStream.Read(inpBuffer, 0, blkSize);
		        _cipherEngine.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, blkSize);
		        count += blkSize;
                CalculateProgress(inpSize, OutStream.Position);
	        }

	        if (alnSize != inpSize)
	        {
		        int cnkSize = (int)(inpSize - alnSize);
		        InStream.Read(inpBuffer, 0, cnkSize);
		        _cipherEngine.Transform(inpBuffer, outBuffer);
		        int fnlSize = blkSize - _cipherPadding.GetPaddingLength(outBuffer, 0);
		        OutStream.Write(outBuffer, 0, fnlSize);
		        count += fnlSize;
	        }

            CalculateProgress(inpSize, OutStream.Position);
        }

        private void BlockDecrypt(byte[] Input, int InOffset, ref byte[] Output, int OutOffset)
        {
	        int blkSize = _cipherEngine.BlockSize;
	        long inpSize = (Input.Length - InOffset);
	        long alnSize = (inpSize < blkSize) ? 0 : inpSize - blkSize;
	        long count = 0;

	        _cipherEngine.IsParallel = false;

	        while (count != alnSize)
	        {
		        _cipherEngine.Transform(Input, InOffset, Output, OutOffset);
		        InOffset += blkSize;
		        OutOffset += blkSize;
		        count += blkSize;
                CalculateProgress(inpSize, count);
	        }

	        // last block
	        byte[] inpBuffer = new byte[blkSize];
            Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, blkSize);
	        byte[] outBuffer = new byte[blkSize];
	        _cipherEngine.Transform(inpBuffer, 0, outBuffer, 0);
	        int fnlSize = blkSize - _cipherPadding.GetPaddingLength(outBuffer, 0);
            Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, fnlSize);
	        OutOffset += fnlSize;

	        if (Output.Length != OutOffset)
		        Array.Resize(ref Output, OutOffset);

            CalculateProgress(inpSize, OutOffset);
        }

        private void BlockEncrypt(Stream InStream, Stream OutStream)
        {
	        int blkSize = _cipherEngine.BlockSize;
	        long inpSize = (InStream.Length - InStream.Position);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;
	        byte[] inpBuffer = new byte[blkSize];
	        byte[] outBuffer = new byte[blkSize];

	        _cipherEngine.IsParallel = false;

	        while (count != alnSize)
	        {
		        InStream.Read(inpBuffer, 0, blkSize);
		        _cipherEngine.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, blkSize);
		        count += blkSize;
                CalculateProgress(inpSize, OutStream.Position);
	        }

	        if (alnSize != inpSize)
	        {
		        int fnlSize = (int)(inpSize - alnSize);
		        InStream.Read(inpBuffer, 0, fnlSize);
		        _cipherPadding.AddPadding(inpBuffer, fnlSize);
		        _cipherEngine.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, blkSize);
		        count += blkSize;
	        }

            CalculateProgress(inpSize, OutStream.Position);
        }

        private void BlockEncrypt(byte[] Input, int InOffset, ref byte[] Output, int OutOffset)
        {
	        int blkSize = _cipherEngine.BlockSize;
	        long inpSize = (Input.Length - InOffset);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;

	        _cipherEngine.IsParallel = false;

	        while (count != alnSize)
	        {
		        _cipherEngine.Transform(Input, InOffset, Output, OutOffset);
		        InOffset += blkSize;
		        OutOffset += blkSize;
		        count += blkSize;
                CalculateProgress(inpSize, count);
	        }

	        if (alnSize != inpSize)
	        {
		        int fnlSize = (int)(inpSize - alnSize);
		        byte[] inpBuffer = new byte[blkSize];
                Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, fnlSize);
		        _cipherPadding.AddPadding(inpBuffer, fnlSize);
		        byte[] outBuffer = new byte[blkSize];
		        _cipherEngine.Transform(inpBuffer, 0, outBuffer, 0);
		        if (Output.Length != OutOffset + blkSize)
                    Array.Resize(ref Output, OutOffset + blkSize);
                Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, blkSize);
		        count += blkSize;
	        }

            CalculateProgress(inpSize, count);
        }

        private void ParallelCTR(Stream InStream, Stream OutStream)
        {
	        int blkSize = _parallelBlockSize;
	        long inpSize = (InStream.Length - InStream.Position);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;
	        byte[] inpBuffer = new byte[blkSize];
	        byte[] outBuffer = new byte[blkSize];

	        _cipherEngine.IsParallel = true;
	        _cipherEngine.ParallelBlockSize = blkSize;

	        while (count != alnSize)
	        {
		        InStream.Read(inpBuffer, 0, blkSize);
		        _cipherEngine.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, blkSize);
		        count += blkSize;
                CalculateProgress(inpSize, OutStream.Position);
	        }

	        if (alnSize != inpSize)
	        {
		        int cnkSize = (int)(inpSize - alnSize);
		        Array.Resize(ref inpBuffer, cnkSize);
		        InStream.Read(inpBuffer, 0, cnkSize);
		        Array.Resize(ref outBuffer, cnkSize);
		        _cipherEngine.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, cnkSize);
		        count += cnkSize;
	        }

            CalculateProgress(inpSize, OutStream.Position);
        }

        private void ParallelCTR(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
	        int blkSize = _parallelBlockSize;
	        long inpSize = (Input.Length - InOffset);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;

	        _cipherEngine.IsParallel = true;
	        _cipherEngine.ParallelBlockSize = blkSize;

	        // parallel blocks
	        while (count != alnSize)
	        {
		        _cipherEngine.Transform(Input, InOffset, Output, OutOffset);
		        InOffset += blkSize;
		        OutOffset += blkSize;
		        count += blkSize;
                CalculateProgress(inpSize, count);
	        }

	        if (alnSize != inpSize)
	        {
		        int cnkSize = (int)(inpSize - alnSize);
		        byte[] inpBuffer = new byte[cnkSize];
                Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, cnkSize);
		        byte[] outBuffer = new byte[cnkSize];
		        _cipherEngine.Transform(inpBuffer, outBuffer);
                Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, cnkSize);
		        count += cnkSize;
	        }

            CalculateProgress(inpSize, count);
        }

        private void ParallelDecrypt(Stream InStream, Stream OutStream)
        {
	        int blkSize = _parallelBlockSize;
	        long inpSize = (InStream.Length - InStream.Position);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;
	        byte[] inpBuffer = new byte[blkSize];
	        byte[] outBuffer = new byte[blkSize];

	        _cipherEngine.IsParallel = true;
	        _cipherEngine.ParallelBlockSize = blkSize;

	        while (count != alnSize)
	        {
		        InStream.Read(inpBuffer, 0, blkSize);
		        _cipherEngine.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, blkSize);
		        count += blkSize;
                CalculateProgress(inpSize, OutStream.Position);
	        }

	        if (alnSize != inpSize)
	        {
		        BlockDecrypt(InStream, OutStream);
		        count += (inpSize - alnSize);
	        }

            CalculateProgress(inpSize, OutStream.Position);
        }

        private void ParallelDecrypt(byte[] Input, int InOffset, ref byte[] Output, int OutOffset)
        {
	        int blkSize = _parallelBlockSize;
	        long inpSize = (Input.Length - InOffset);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;

	        _cipherEngine.IsParallel = true;
	        _cipherEngine.ParallelBlockSize = blkSize;

	        // parallel
	        while (count != alnSize)
	        {
		        _cipherEngine.Transform(Input, InOffset, Output, OutOffset);
		        InOffset += blkSize;
		        OutOffset += blkSize;
		        count += blkSize;
                CalculateProgress(inpSize, count);
	        }

	        if (alnSize != inpSize)
	        {
                BlockDecrypt(Input, InOffset, ref Output, OutOffset);
		        count += (inpSize - alnSize);
	        }

            CalculateProgress(inpSize, count);
        }

        private void ParallelStream(Stream InStream, Stream OutStream)
        {
	        int blkSize = _parallelBlockSize;
	        long inpSize = (InStream.Length - InStream.Position);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;
	        byte[] inpBuffer = new byte[blkSize];
	        byte[] outBuffer = new byte[blkSize];

	        _streamCipher.IsParallel = true;
	        _streamCipher.ParallelBlockSize = blkSize;

	        while (count != alnSize)
	        {
		        InStream.Read(inpBuffer, 0, blkSize);
		        _streamCipher.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, blkSize);
		        count += blkSize;
                CalculateProgress(inpSize, OutStream.Position);
	        }

	        if (alnSize != inpSize)
	        {
		        int cnkSize = (int)(inpSize - alnSize);
		        Array.Resize(ref inpBuffer, cnkSize);
		        InStream.Read(inpBuffer, 0, cnkSize);
		        Array.Resize(ref outBuffer, cnkSize);
		        _streamCipher.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, cnkSize);
		        count += cnkSize;
	        }

            CalculateProgress(inpSize, OutStream.Position);
        }

        private void ParallelStream(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
	        int blkSize = _parallelBlockSize;
	        long inpSize = (Input.Length - InOffset);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;

	        _streamCipher.IsParallel = true;
	        _streamCipher.ParallelBlockSize = blkSize;

	        // parallel blocks
	        while (count != alnSize)
	        {
		        _streamCipher.Transform(Input, InOffset, Output, OutOffset);
		        InOffset += blkSize;
		        OutOffset += blkSize;
		        count += blkSize;
                CalculateProgress(inpSize, count);
	        }

	        if (alnSize != inpSize)
	        {
		        int cnkSize = (int)(inpSize - alnSize);
		        byte[] inpBuffer = new byte[cnkSize];
                Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, cnkSize);
		        byte[] outBuffer = new byte[cnkSize];
		        _streamCipher.Transform(inpBuffer, outBuffer);
                Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, cnkSize);
		        count += cnkSize;
	        }

            CalculateProgress(inpSize, count);
        }

        private void ProcessStream(Stream InStream, Stream OutStream)
        {
	        int blkSize = _streamCipher.BlockSize;
	        long inpSize = (InStream.Length - InStream.Position);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;
	        byte[] inpBuffer = new byte[blkSize];
	        byte[] outBuffer = new byte[blkSize];

	        _streamCipher.IsParallel = false;

	        while (count != alnSize)
	        {
		        InStream.Read(inpBuffer, 0, blkSize);
		        _streamCipher.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, blkSize);
		        count += blkSize;
                CalculateProgress(inpSize, OutStream.Position);
	        }

	        if (alnSize != inpSize)
	        {
		        int cnkSize = (int)(inpSize - alnSize);
		        Array.Resize(ref inpBuffer, cnkSize);
		        InStream.Read(inpBuffer, 0, cnkSize);
		        Array.Resize(ref outBuffer, cnkSize);
		        _streamCipher.Transform(inpBuffer, outBuffer);
		        OutStream.Write(outBuffer, 0, cnkSize);
		        count += cnkSize;
	        }

            CalculateProgress(inpSize, OutStream.Position);
        }

        private void ProcessStream(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
	        int blkSize = _streamCipher.BlockSize;
	        long inpSize = (Input.Length - InOffset);
	        long alnSize = (inpSize / blkSize) * blkSize;
	        long count = 0;

	        _streamCipher.IsParallel = false;

	        while (count != alnSize)
	        {
		        _streamCipher.Transform(Input, InOffset, Output, OutOffset);
		        InOffset += blkSize;
		        OutOffset += blkSize;
		        count += blkSize;
                CalculateProgress(inpSize, count);
	        }

	        // partial
	        if (alnSize != inpSize)
	        {
		        int cnkSize = (int)(inpSize - alnSize);
		        byte[] inpBuffer = new byte[cnkSize];
                Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, cnkSize);
		        byte[] outBuffer = new byte[cnkSize];
		        _streamCipher.Transform(inpBuffer, outBuffer);
                Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, cnkSize);
		        count += cnkSize;
	        }

            CalculateProgress(inpSize, count);
        }
        #endregion

        #region Helpers
        private void CalculateBlockSize(long Length)
        {
	        int cipherBlock = 0;

	        if (_isStreamCipher)
		        cipherBlock = _streamCipher.BlockSize;
	        else
		        cipherBlock = _cipherEngine.BlockSize;

	        // parallel min check
	        if (Length < ParallelMinimumSize)
	        {
		        _parallelBlockSize = cipherBlock;
	        }

	        if (_parallelBlockProfile == BlockProfiles.ProgressProfile)
	        {
		        // get largest 10 base block 
		        int dsr = 10;
		        while (Length / dsr > ParallelMaximumSize)
			        dsr *= 2;

		        _parallelBlockSize = (int)(Length / dsr);
	        }
	        else if (_parallelBlockProfile == BlockProfiles.SpeedProfile)
	        {
		        if (Length < PARALLEL_DEFBLOCK)
		        {
			        // small block
			        _parallelBlockSize = (int)Length;
		        }
		        else
		        {
			        // get largest 64kb base block
                    long dsr = Length - (Length % PARALLEL_DEFBLOCK);

                    if (Length > ParallelMaximumSize)
                    {
                        while (dsr > ParallelMaximumSize)
                            dsr /= 2;

                        _parallelBlockSize = (int)dsr;
                    }
                    else
                    {
                        _parallelBlockSize = (int)dsr;
                    }
		        }
	        }

	        if (_isParallel && !_isCounterMode && !_isEncryption && !_isStreamCipher)
	        {
		        if (_parallelBlockSize % ParallelMinimumSize > 0)
			        _parallelBlockSize -= (_parallelBlockSize % ParallelMinimumSize);
		        else
			        _parallelBlockSize -= ParallelMinimumSize;
	        }
	        else
	        {
                if (_parallelBlockSize % ParallelMinimumSize != 0)
		            _parallelBlockSize -= (_parallelBlockSize % ParallelMinimumSize);
	        }

            // set the ciphers block size
            if (_parallelBlockSize >= ParallelMinimumSize)
            {
                if (!_isStreamCipher)
                    _cipherEngine.ParallelBlockSize = _parallelBlockSize;
                else
                    _streamCipher.ParallelBlockSize = _parallelBlockSize;
            }
        }

        private void CalculateProgress(long Length, long Processed)
        {
            if (ProgressPercent != null && Length >= Processed)
	        {
                double progress = 100.0 * ((double)Processed / Length);
                if (progress > 100.0)
                    progress = 100.0;

                if (_isParallel)
                {
                    ProgressPercent(this, new ProgressEventArgs(Length, (int)progress));
                }
                else
                {
                    long chunk = Length / 100;
                    if (chunk == 0)
                        ProgressPercent(this, new ProgressEventArgs(Length, (int)progress));
                    else if (Processed % chunk == 0)
                        ProgressPercent(this, new ProgressEventArgs(Length, (int)progress));
                }
	        }
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

        private bool IsParallelMin(long Length)
        {
            return (Length >= ParallelMinimumSize);
        }

        private void ParametersCheck()
        {
            if (_isStreamCipher)
            {
                _blockSize = _streamCipher.BlockSize;
                _isCounterMode = false;
                _isParallel = _streamCipher.IsParallel;
                _parallelBlockSize = _streamCipher.ParallelBlockSize;
            }
            else
            {
                _blockSize = _cipherEngine.BlockSize;
                _isCounterMode = _cipherEngine.Enumeral == CipherModes.CTR;

                if (_cipherEngine.Enumeral == CipherModes.CBC || _cipherEngine.Enumeral == CipherModes.CFB || _isCounterMode)
                {
                    _isParallel = _cipherEngine.IsParallel && !(!_isCounterMode && _cipherEngine.IsEncryption);
                    _parallelBlockSize = _cipherEngine.ParallelBlockSize;
                }
                else
                {
                    _isParallel = false;
                    _parallelBlockSize = _blockSize;
                }
            }
        }
        
	    private void SetScope()
	    {
            _processorCount = Environment.ProcessorCount;
		    if (_processorCount % 2 != 0)
			    _processorCount--;
		    if (_processorCount > 1)
			    _isParallel = true;
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
                    if (_destroyEngine)
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
