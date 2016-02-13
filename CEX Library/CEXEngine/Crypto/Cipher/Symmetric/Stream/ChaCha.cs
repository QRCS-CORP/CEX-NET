#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Utility;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
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
// Principal Algorithms:
// Portions of this cipher based on the ChaCha stream cipher designed by Daniel J. Bernstein:
// ChaCha20 <a href="http://cr.yp.to/chacha/chacha-20080128.pdf">Specification</a>.
// 
// Implementation Details:
// ChaCha20+
// An implementation based on the ChaCha stream cipher,
// using an extended key size, and higher variable rounds assignment.
// Valid Key sizes are 128 and 256 (16 and 32 bytes).
// Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.
// Written by John Underhill, October 21, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream
{
    /// <summary>
    /// ChaCha+: A parallelized ChaCha stream cipher implementation
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IStreamCipher</c> interface:</description>
    /// <code>
    /// using (IStreamCipher cipher = new ChaCha())
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Valid Key sizes are 128 and 256 (16 and 32 bytes).</description></item>
    /// <item><description>Block size is 64 bytes wide.</description></item>
    /// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>ChaCha20 <a href="http://cr.yp.to/chacha/chacha-20080128.pdf">Specification</a>.</description></item>
    /// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/design.pdf">Design</a>.</description></item>
    /// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/security.pdf">Security</a>.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Inspired in part by the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class ChaCha : IStreamCipher
    {
        #region Constants
        private const string ALG_NAME = "ChaCha";
        private const int ROUNDS20 = 20;
        private const int MAX_ROUNDS = 30;
        private const int MIN_ROUNDS = 8;
        private const int STATE_SIZE = 16;
        private const int VECTOR_SIZE = 8;
        private const int BLOCK_SIZE = 64;
        private const int PARALLEL_CHUNK = 1024;
        private const int MAXALLOC_MB100 = 100000000;
        private const int PARALLEL_DEFBLOCK = 64000;
        private static readonly byte[] SIGMA = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k");
        private static readonly byte[] TAU = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");
        #endregion

        #region Fields
        private UInt32[] _ctrVector = new UInt32[2];
        private byte[] _dstCode = null;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private int _parallelBlockSize = PARALLEL_DEFBLOCK;
        private ParallelOptions _parallelOption = null;
        private int _rndCount = ROUNDS20;
        private UInt32[] _wrkBuffer = new UInt32[STATE_SIZE];
        private UInt32[] _wrkState = new UInt32[14];
        #endregion

        #region Properties
        /// <summary>
	    /// Get: Unit block size of internal cipher in bytes.
	    /// <para>Block size is 64 bytes wide.</para>
	    /// </summary>
        public int BlockSize { get { return BLOCK_SIZE; } }

        /// <summary>
        /// Get the current counter value
        /// </summary>
        public long Counter
        {
            get { return ((long)_ctrVector[1] << 32) | (_ctrVector[0] & 0xffffffffL); }
        }

        /// <summary>
        /// Get/Set: Sets the Nonce value in the initialization parameters (Tau-Sigma). 
        /// <para>Must be set before <see cref="Initialize(KeyParams)"/> is called.
        /// Changing this code will create a unique distribution of the cipher.
        /// Code must be 16 bytes in length and sufficiently asymmetric (no more than 2 repeats, of 2 bytes, at a distance of 2 intervals).</para>
        /// </summary>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid distribution code is used</exception>
        public byte[] DistributionCode
        {
            get { return _dstCode; }
            set
            {
                if (value == null)
                    throw new CryptoSymmetricException("ChaCha:DistributionCode", "Distribution Code can not be null!", new ArgumentNullException());
                if (value.Length != 16)
                    throw new CryptoSymmetricException("ChaCha:DistributionCode", "Distribution Code must be 16 bytes in length!", new ArgumentNullException());
                if (!ValidCode(value))
                    throw new CryptoSymmetricException("ChaCha:DistributionCode", "Use a random value; distribution code is not asymmetric!", new ArgumentNullException());
                if (_isInitialized)
                    throw new CryptoSymmetricException("ChaCha:DistributionCode", "Distribution Code must be set before cipher is initialized!", new ArgumentNullException());

                _dstCode = value;
            }
        }

        /// <summary>
        /// Get: The stream ciphers type name
        /// </summary>
        public StreamCiphers Enumeral
        {
            get { return StreamCiphers.ChaCha; }
        }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return _isParallel; }
            set
            {
                if (ProcessorCount < 2)
                    _isParallel = false;
                else
                    _isParallel = value;
            }
        }

        /// <summary>
        /// Get: Available Encryption Key Sizes in bytes
        /// </summary>
        public int[] LegalKeySizes
        {
            get { return new int[] { 16, 32 }; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public int[] LegalRounds
        {
            get { return new int[] { 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 }; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
        /// </summary>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, or  block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return _parallelBlockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoSymmetricException("ChaCha:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoSymmetricException("ChaCha:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

                _parallelBlockSize = value;
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
            get { return ProcessorCount * (STATE_SIZE * 4); }
        }

        /// <summary>
        /// Get/Set: The parallel loops ParallelOptions
        /// <para>The MaxDegreeOfParallelism of the parallel loop is equal to the Environment.ProcessorCount by default</para>
        /// </summary>
        public ParallelOptions ParallelOption
        {
            get
            {
                if (_parallelOption == null)
                    _parallelOption = new ParallelOptions() { MaxDegreeOfParallelism = Environment.ProcessorCount };

                return _parallelOption;
            }
            set
            {
                if (value != null)
                {
                    if (value.MaxDegreeOfParallelism < 1)
                        throw new CryptoSymmetricException("ChaCha:ParallelOption", "MaxDegreeOfParallelism can not be less than 1!", new ArgumentException());
                    else if (value.MaxDegreeOfParallelism == 1)
                        _isParallel = false;
                    else if (value.MaxDegreeOfParallelism % 2 != 0)
                        throw new CryptoSymmetricException("ChaCha:ParallelOption", "MaxDegreeOfParallelism can not be an odd number; must be either 1, or a divisible of 2!", new ArgumentException());

                    _parallelOption = value;
                }
            }
        }

        /// <remarks>
        /// Get: Processor count
        /// </remarks>
        private int ProcessorCount { get; set; }

        /// <summary>
        /// Get: Number of rounds
        /// </summary>
        public int Rounds
        {
            get { return _rndCount; }
            private set { _rndCount = value; }
        }

        /// <summary>
        /// Get: Initialization vector size
        /// </summary>
        public int VectorSize
        {
            get { return VECTOR_SIZE; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 20 rounds.</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid rounds count is chosen</exception>
        public ChaCha(int Rounds = ROUNDS20)
        {
            if (Rounds <= 0 || (Rounds & 1) != 0)
                throw new CryptoSymmetricException("ChaCha:Ctor", "Rounds must be a positive even number!", new ArgumentOutOfRangeException());
            if (Rounds < MIN_ROUNDS || Rounds > MAX_ROUNDS)
                throw new CryptoSymmetricException("ChaCha:Ctor", String.Format("Rounds must be between {0} and {1)!", MIN_ROUNDS, MAX_ROUNDS), new ArgumentOutOfRangeException());

            _rndCount = Rounds;

            ProcessorCount = Environment.ProcessorCount;
            if (ProcessorCount % 2 != 0)
                ProcessorCount--;

            IsParallel = ProcessorCount > 1;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~ChaCha()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="KeyParam">Cipher key container. 
        /// <para>Uses the Key and IV fields of KeyParam. 
        /// The <see cref="LegalKeySizes"/> property contains valid Key sizes. 
        /// IV must be 8 bytes in size.</para>
        /// </param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null key or iv  is used</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid key or iv size  is used</exception>
        public void Initialize(KeyParams KeyParam)
        {
            if (KeyParam.IV == null)
                throw new CryptoSymmetricException("ChaCha:Initialize", "Init parameters must include an IV!", new ArgumentException());
            if (KeyParam.IV.Length != 8)
                throw new CryptoSymmetricException("ChaCha:Initialize", "Requires exactly 8 bytes of IV!", new ArgumentOutOfRangeException());
            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("ChaCha:Initialize", "Key can not be null!", new ArgumentException());
            if (KeyParam.Key.Length != 16 && KeyParam.Key.Length != 32)
                throw new CryptoSymmetricException("ChaCha:Initialize", "Key must be 16 or 32 bytes!", new ArgumentOutOfRangeException());

            if (DistributionCode == null)
            {
                if (KeyParam.Key.Length == 16)
                    _dstCode = (byte[])TAU.Clone();
                else
                    _dstCode = (byte[])SIGMA.Clone();
            }

            Reset();
            SetKey(KeyParam.Key, KeyParam.IV);

            _isInitialized = true;
        }

        /// <summary>
        /// Reset the primary internal counter
        /// </summary>
        public void Reset()
        {
            _ctrVector[0] = _ctrVector[1] = 0;
        }

        /// <summary>
        /// Process an array of bytes. 
        /// <para>This method processes the entire array; used when processing small data or buffers from a larger source.
        /// Parallel capable function if Output array length is at least equal to <see cref="ParallelMinimumSize"/>. 
        /// <see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            ProcessBlock(Input, Output);
        }

        /// <summary>
        /// Process a block of bytes using offset parameters.  
        /// <para>
        /// This method will process a single block from the source array of either ParallelBlockSize or Blocksize depending on IsParallel property setting.
        /// Parallel capable function if Output array length is at least equal to <see cref="ParallelMinimumSize"/>. 
        /// Partial blocks are permitted with both parallel and linear operation modes.
        /// The <see cref="Initialize(KeyParams)"/> method must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            ProcessBlock(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Process an array of bytes with offset and length parameters.
        /// <para>This method processes a specified length of the array; used when processing segments of a large source array.
        /// Parallel capable function if Output array length is at least equal to <see cref="ParallelMinimumSize"/>.
        /// This method automatically assigns the ParallelBlockSize as the Length divided by the number of processors.
        /// <see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        /// <param name="Length">Number of bytes to process</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset, int Length)
        {
            ProcessBlock(Input, InOffset, Output, OutOffset, Length);
        }
        #endregion

        #region Key Schedule
        private void SetKey(byte[] Key, byte[] Iv)
        {
            if (Key != null)
            {
                if (Key.Length == 32)
                {
                    _wrkState[0] = IntUtils.BytesToLe32(_dstCode, 0);
                    _wrkState[1] = IntUtils.BytesToLe32(_dstCode, 4);
                    _wrkState[2] = IntUtils.BytesToLe32(_dstCode, 8);
                    _wrkState[3] = IntUtils.BytesToLe32(_dstCode, 12);
                    _wrkState[4] = IntUtils.BytesToLe32(Key, 0);
                    _wrkState[5] = IntUtils.BytesToLe32(Key, 4);
                    _wrkState[6] = IntUtils.BytesToLe32(Key, 8);
                    _wrkState[7] = IntUtils.BytesToLe32(Key, 12);
                    _wrkState[8] = IntUtils.BytesToLe32(Key, 16);
                    _wrkState[9] = IntUtils.BytesToLe32(Key, 20);
                    _wrkState[10] = IntUtils.BytesToLe32(Key, 24);
                    _wrkState[11] = IntUtils.BytesToLe32(Key, 28);
                    _wrkState[12] = IntUtils.BytesToLe32(Iv, 0);
                    _wrkState[13] = IntUtils.BytesToLe32(Iv, 4);

                }
                else
                {
                    _wrkState[0] = IntUtils.BytesToLe32(_dstCode, 0);
                    _wrkState[1] = IntUtils.BytesToLe32(_dstCode, 4);
                    _wrkState[2] = IntUtils.BytesToLe32(_dstCode, 8);
                    _wrkState[3] = IntUtils.BytesToLe32(_dstCode, 12);
                    _wrkState[4] = IntUtils.BytesToLe32(Key, 0);
                    _wrkState[5] = IntUtils.BytesToLe32(Key, 4);
                    _wrkState[6] = IntUtils.BytesToLe32(Key, 8);
                    _wrkState[7] = IntUtils.BytesToLe32(Key, 12);
                    _wrkState[8] = IntUtils.BytesToLe32(Key, 0);
                    _wrkState[9] = IntUtils.BytesToLe32(Key, 4);
                    _wrkState[10] = IntUtils.BytesToLe32(Key, 8);
                    _wrkState[11] = IntUtils.BytesToLe32(Key, 12);
                    _wrkState[12] = IntUtils.BytesToLe32(Iv, 0);
                    _wrkState[13] = IntUtils.BytesToLe32(Iv, 4);
                }
            }
        }
        #endregion

        #region Transform
        private void ChaChaCore(byte[] Output, int OutOffset, UInt32[] Counter)
        {
            int ctr = 0;
            UInt32 X0 = _wrkState[ctr];
            UInt32 X1 = _wrkState[++ctr];
            UInt32 X2 = _wrkState[++ctr];
            UInt32 X3 = _wrkState[++ctr];
            UInt32 X4 = _wrkState[++ctr];
            UInt32 X5 = _wrkState[++ctr];
            UInt32 X6 = _wrkState[++ctr];
            UInt32 X7 = _wrkState[++ctr];
            UInt32 X8 = _wrkState[++ctr];
            UInt32 X9 = _wrkState[++ctr];
            UInt32 X10 = _wrkState[++ctr];
            UInt32 X11 = _wrkState[++ctr];
            UInt32 X12 = Counter[0];
            UInt32 X13 = Counter[1];
            UInt32 X14 = _wrkState[++ctr];
            UInt32 X15 = _wrkState[++ctr];

            ctr = Rounds;
            while (ctr != 0)
            {
                X0 += X4; 
                X12 = IntUtils.RotateLeft(X12 ^ X0, 16);
                X8 += X12; 
                X4 = IntUtils.RotateLeft(X4 ^ X8, 12);
                X0 += X4; 
                X12 = IntUtils.RotateLeft(X12 ^ X0, 8);
                X8 += X12; 
                X4 = IntUtils.RotateLeft(X4 ^ X8, 7);
                X1 += X5; 
                X13 = IntUtils.RotateLeft(X13 ^ X1, 16);
                X9 += X13; 
                X5 = IntUtils.RotateLeft(X5 ^ X9, 12);
                X1 += X5; 
                X13 = IntUtils.RotateLeft(X13 ^ X1, 8);
                X9 += X13; 
                X5 = IntUtils.RotateLeft(X5 ^ X9, 7);
                X2 += X6; 
                X14 = IntUtils.RotateLeft(X14 ^ X2, 16);
                X10 += X14; 
                X6 = IntUtils.RotateLeft(X6 ^ X10, 12);
                X2 += X6; 
                X14 = IntUtils.RotateLeft(X14 ^ X2, 8);
                X10 += X14; 
                X6 = IntUtils.RotateLeft(X6 ^ X10, 7);
                X3 += X7; 
                X15 = IntUtils.RotateLeft(X15 ^ X3, 16);
                X11 += X15; 
                X7 = IntUtils.RotateLeft(X7 ^ X11, 12);
                X3 += X7; 
                X15 = IntUtils.RotateLeft(X15 ^ X3, 8);
                X11 += X15; 
                X7 = IntUtils.RotateLeft(X7 ^ X11, 7);
                X0 += X5; 
                X15 = IntUtils.RotateLeft(X15 ^ X0, 16);
                X10 += X15;
                X5 = IntUtils.RotateLeft(X5 ^ X10, 12);
                X0 += X5; 
                X15 = IntUtils.RotateLeft(X15 ^ X0, 8);
                X10 += X15; 
                X5 = IntUtils.RotateLeft(X5 ^ X10, 7);
                X1 += X6; 
                X12 = IntUtils.RotateLeft(X12 ^ X1, 16);
                X11 += X12; 
                X6 = IntUtils.RotateLeft(X6 ^ X11, 12);
                X1 += X6;
                X12 = IntUtils.RotateLeft(X12 ^ X1, 8);
                X11 += X12; 
                X6 = IntUtils.RotateLeft(X6 ^ X11, 7);
                X2 += X7; 
                X13 = IntUtils.RotateLeft(X13 ^ X2, 16);
                X8 += X13; 
                X7 = IntUtils.RotateLeft(X7 ^ X8, 12);
                X2 += X7; 
                X13 = IntUtils.RotateLeft(X13 ^ X2, 8);
                X8 += X13; 
                X7 = IntUtils.RotateLeft(X7 ^ X8, 7);
                X3 += X4; 
                X14 = IntUtils.RotateLeft(X14 ^ X3, 16);
                X9 += X14; 
                X4 = IntUtils.RotateLeft(X4 ^ X9, 12);
                X3 += X4; 
                X14 = IntUtils.RotateLeft(X14 ^ X3, 8);
                X9 += X14; 
                X4 = IntUtils.RotateLeft(X4 ^ X9, 7);
                ctr -= 2;
            }

	        IntUtils.Le32ToBytes(X0 + _wrkState[ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X1 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X2 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X3 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X4 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X5 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X6 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X7 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X8 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X9 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X10 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X11 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X12 + Counter[0], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X13 + Counter[1], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X14 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	        IntUtils.Le32ToBytes(X15 + _wrkState[++ctr], Output, OutOffset);
        }

        private void Generate(int Size, UInt32[] Counter, byte[] Output, int OutOffset)
        {
            int aln = Size - (Size % BLOCK_SIZE);
	        int ctr = 0;

	        while (ctr != aln)
	        {
		        ChaChaCore(Output, OutOffset + ctr, Counter);
		        Increment(Counter);
		        ctr += BLOCK_SIZE;
	        }

	        if (ctr != Size)
	        {
		        byte[] outputBlock = new byte[BLOCK_SIZE];
		        ChaChaCore(outputBlock, 0, Counter);
		        int fnlSize = Size % BLOCK_SIZE;
                Buffer.BlockCopy(outputBlock, 0, Output, OutOffset + (Size - fnlSize), fnlSize);
		        Increment(Counter);
	        }
        }

        private void ProcessBlock(byte[] Input, byte[] Output)
        {
            if (!IsParallel || Output.Length < ParallelBlockSize)
            {
                // generate random
		        Generate(Output.Length, _ctrVector, Output, 0);
		        // output is input xor with random
		        int sze = Output.Length - (Output.Length % BLOCK_SIZE);

		        if (sze != 0)
			        IntUtils.XORBLK(Input, 0, Output, 0, sze);

		        // get the remaining bytes
		        if (sze != Output.Length)
		        {
                    for (int i = sze; i < Output.Length; i++)
				        Output[i] ^= Input[i];
		        }
            }
            else
            {
                // parallel CTR processing //
                int cnkSize = (Output.Length / BLOCK_SIZE / ProcessorCount) * BLOCK_SIZE;
                int rndSize = cnkSize * ProcessorCount;
                int subSize = (cnkSize / BLOCK_SIZE);
                // create jagged array of 'sub counters'
                uint[][] vectors = new uint[ProcessorCount][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, ProcessorCount, i =>
                {
                    // offset counter by chunk size / block size
                    vectors[i] = Increase(_ctrVector, subSize * i);
                    // create random at offset position
                    this.Generate(cnkSize, vectors[i], Output, (i * cnkSize));
                    // xor with input at offset
                    IntUtils.XORBLK(Input, i * cnkSize, Output, i * cnkSize, cnkSize);
                });

                // last block processing
                if (rndSize < Output.Length)
                {
                    int fnlSize = Output.Length % rndSize;
                    Generate(fnlSize, vectors[ProcessorCount - 1], Output, rndSize);

                    for (int i = rndSize; i < Output.Length; ++i)
				        Output[i] ^= Input[i];
                }

                // copy the last counter position to class variable
                Buffer.BlockCopy(vectors[ProcessorCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }

        private void ProcessBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int outSize = _isParallel ? (Output.Length - OutOffset) : BLOCK_SIZE;

            if (outSize < _parallelBlockSize)
            {
                // generate random
                Generate(outSize, _ctrVector, Output, OutOffset);
                // output is input xor with random
                int sze = outSize - (outSize % BLOCK_SIZE);

                if (sze != 0)
                    IntUtils.XORBLK(Input, InOffset, Output, OutOffset, sze);

                // get the remaining bytes
                if (sze != outSize)
                {
                    for (int i = sze; i < outSize; ++i)
                        Output[i + OutOffset] ^= Input[i + InOffset];
                }
            }
            else
            {
                // parallel CTR processing //
                int cnkSize = _parallelBlockSize / ProcessorCount;
                int rndSize = cnkSize * ProcessorCount;
                int subSize = (cnkSize / BLOCK_SIZE);
                // create jagged array of 'sub counters'
                uint[][] vectors = new uint[ProcessorCount][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, ProcessorCount, i =>
                {
                    // offset counter by chunk size / block size
                    vectors[i] = Increase(_ctrVector, subSize * i);
                    // create random at offset position
                    this.Generate(cnkSize, vectors[i], Output, (i * cnkSize));
                    // xor with input at offset
                    IntUtils.XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize);
                });

                // copy the last counter position to class variable
                Buffer.BlockCopy(vectors[ProcessorCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }

        private void ProcessBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset, int Length)
        {
            int blkSize = Length;

	        if (!_isParallel || blkSize < _parallelBlockSize)
	        {
		        // generate random
		        Generate(blkSize, _ctrVector, Output, OutOffset);
		        // output is input xor with random
		        int sze = Length - (Length % BLOCK_SIZE);

		        if (sze != 0)
			        IntUtils.XORBLK(Input, InOffset, Output, OutOffset, sze);

		        // get the remaining bytes
		        if (sze != Length)
		        {
			        for (int i = sze; i < Length; ++i)
				        Output[i + OutOffset] ^= Input[i + InOffset];
		        }
	        }
	        else
	        {
		        // parallel CTR processing //
		        int cnkSize = (Length / BLOCK_SIZE / ProcessorCount) * BLOCK_SIZE;
		        int rndSize = cnkSize * ProcessorCount;
		        int subSize = (cnkSize / BLOCK_SIZE);
		        // create jagged array of 'sub counters'
                uint[][] vectors = new uint[ProcessorCount][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, ProcessorCount, i =>
		        {
			        // offset counter by chunk size / block size
			        vectors[i] = Increase(_ctrVector, subSize * i);
			        // create random at offset position
			        this.Generate(cnkSize, vectors[i], Output, (i * cnkSize));
			        // xor with input at offset
                    IntUtils.XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize);
		        });

		        // last block processing
		        if (rndSize < Length)
		        {
			        int fnlSize = Length % rndSize;
			        Generate(fnlSize, vectors[ProcessorCount - 1], Output, rndSize);

			        for (int i = 0; i < fnlSize; ++i)
				        Output[i + OutOffset + rndSize] ^= (byte)(Input[i + InOffset + rndSize]);
		        }

		        // copy the last counter position to class variable
                Buffer.BlockCopy(vectors[ProcessorCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
	        }
        }
        #endregion

        #region Helpers
        private void Increment(UInt32[] Counter)
        {
            if (++Counter[0] == 0)
                ++Counter[1];
        }

        private UInt32[] Increase(UInt32[] Counter, int Size)
        {
            uint[] copy = new uint[Counter.Length];
            Array.Copy(Counter, 0, copy, 0, Counter.Length);

            for (int i = 0; i < Size; i++)
                Increment(copy);

            return copy;
        }

        private bool ValidCode(byte[] Code)
        {
            int ctr = 0;
            int rep = 0;

            // test for minimum asymmetry per sigma and tau constants; 
            // max 2 repeats, 2 times, distance of more than 4
            for (int i = 0; i < Code.Length; i++)
            {
                ctr = 0;
                for (int j = i + 1; j < Code.Length; j++)
                {
                    if (Code[i] == Code[j])
                    {
                        ctr++;

                        if (ctr > 1)
                            return false;
                        if (j - i < 5)
                            return false;
                    }
                }

                if (ctr == 1)
                    rep++;
                if (rep > 2)
                    return false;
            }

            return true;
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
                    if (_wrkBuffer != null)
                    {
                        Array.Clear(_wrkBuffer, 0, _wrkBuffer.Length);
                        _wrkBuffer = null;
                    }
                    if (_wrkState != null)
                    {
                        Array.Clear(_wrkState, 0, _wrkState.Length);
                        _wrkState = null;
                    }
                    if (_dstCode != null)
                    {
                        Array.Clear(_dstCode, 0, _dstCode.Length);
                        _dstCode = null;
                    }
                    _isInitialized = false;
                    _isParallel = false;
                    _parallelBlockSize = 0;
                    _rndCount = 0;
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
