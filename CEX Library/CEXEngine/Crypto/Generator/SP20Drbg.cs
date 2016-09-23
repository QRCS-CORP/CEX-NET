#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
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
// Implementation Details:
// An implementation of a Salsa20 Counter based Deterministic Random Byte Generator (SP20Drbg). 
// Written by John Underhill, November 21, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// SP20Drbg: A parallelized Salsa20 deterministic random byte generator implementation
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new SP20Drbg())
    /// {
    ///     // initialize
    ///     rnd.Initialize(Salt, [Ikm], [Nonce]);
    ///     // generate bytes
    ///     rnd.Generate(Output, [Offset], [Size]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Valid Key sizes are 128, 256 (16 and 32 bytes).</description></item>
    /// <item><description>Block size is 64 bytes wide.</description></item>
    /// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
    /// <item><description>Parallel block size is 64,000 bytes by default; but is configurable.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Salsa20 <a href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</a>.</description></item>
    /// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/design.pdf">Design</a>.</description></item>
    /// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/security.pdf">Security</a>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class SP20Drbg : IGenerator
    {
        #region Constants
        private const string ALG_NAME = "SP20Drbg";
        private const int DEFAULT_ROUNDS = 20;
        private const int MAX_ROUNDS = 30;
        private const int MIN_ROUNDS = 8;
        private const int STATE_SIZE = 16;
        private const int VECTOR_SIZE = 8;
        private const int BLOCK_SIZE = 64;
        private const int PARALLEL_CHUNK = 1024;
        private const int MAXALLOC_MB100 = 100000000;
        private const int PARALLEL_DEFBLOCK = 64000;
        private const int MAX_PARALLEL = 1024000;
        private const int MIN_PARALLEL = 1024;
        private static readonly byte[] SIGMA = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k");
        private static readonly byte[] TAU = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");
        #endregion

        #region Fields
        private uint[] _ctrVector = new uint[2];
        private byte[] _dstCode = null;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private int _parallelBlockSize = PARALLEL_DEFBLOCK;
        private int _rndCount = DEFAULT_ROUNDS;
        private uint[] _wrkState = new uint[14];
        private int _keySize = 32;
        #endregion

        #region Properties
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
        /// <para>The key size (in bytes) of the symmetric cipher</para>
        /// </summary>
        public int KeySize
        {
            get { return _keySize; }
            private set { _keySize = value; }
        }

        /// <summary>
        /// Get: Available Seed Sizes in bytes
        /// </summary>
        public static int[] LegalSeedSizes
        {
            get { return new int[] { 24, 40 }; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public static int[] LegalRounds
        {
            get { return new int[] { 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 }; }
        }

        /// <summary>
        /// Get: The generators type name
        /// </summary>
        public Generators Enumeral
        {
            get { return Generators.SP20Drbg; }
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
        /// <exception cref="System.ArgumentException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if parallel block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return _parallelBlockSize; }
            set
            {
                if (value % ParallelMinimumSize != 0)
                    throw new CryptoGeneratorException("SP20Drbg:ParallelBlockSize", String.Format("Parallel block size must be evenly divisible by ParallelMinimumSize: {0}", ParallelMinimumSize), new ArgumentException());
                if (value > ParallelMaximumSize || value < ParallelMinimumSize)
                    throw new CryptoGeneratorException("SP20Drbg:ParallelBlockSize", String.Format("Parallel block must be Maximum of ParallelMaximumSize: {0} and evenly divisible by ParallelMinimumSize: {1}", ParallelMaximumSize, ParallelMinimumSize), new ArgumentOutOfRangeException());

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
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid rounds count is chosen</exception>
        public SP20Drbg(int Rounds = 20)
        {
            if (Rounds <= 0 || (Rounds & 1) != 0)
                throw new CryptoGeneratorException("SP20Drbg:Ctor", "Rounds must be a positive, even number!", new ArgumentOutOfRangeException());
            if (Rounds < MIN_ROUNDS || Rounds > MAX_ROUNDS)
                throw new CryptoGeneratorException("SP20Drbg:Ctor", String.Format("Rounds must be between {0} and {1}!", MIN_ROUNDS, MAX_ROUNDS), new ArgumentOutOfRangeException());

            _rndCount = Rounds;

            ProcessorCount = Environment.ProcessorCount;
            if (ProcessorCount % 2 != 0)
                ProcessorCount--;

            IsParallel = ProcessorCount > 1;
        }

        private SP20Drbg()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SP20Drbg()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the generator with a MacParams structure containing the key, and optional salt, and info string
        /// </summary>
        /// 
        /// <param name="GenParam">The MacParams containing the generators keying material</param>
        public void Initialize(MacParams GenParam)
        {
	        if (GenParam.Salt.Length != 0)
	        {
		        if (GenParam.Info.Length != 0)

                    Initialize(GenParam.Key, GenParam.Salt, GenParam.Info);
		        else

                    Initialize(GenParam.Key, GenParam.Salt);
	        }
	        else
	        {

                Initialize(GenParam.Key);
	        }
        }

        /// <summary>
        /// Initialize the generator with a key
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null or invalid key is used</exception>
        public void Initialize(byte[] Key)
        {
            if (Key == null)
                throw new CryptoGeneratorException("SP20Drbg:Initialize", "Key can not be null!", new ArgumentNullException());
            if (Key.Length != LegalSeedSizes[0] && Key.Length != LegalSeedSizes[1])
                throw new CryptoGeneratorException("SP20Drbg:Initialize", String.Format("Invalid Key size has been added. Size must be at least {0} or {1} bytes!", LegalSeedSizes[0], LegalSeedSizes[1]), new ArgumentOutOfRangeException());

            _keySize = Key.Length;
            _ctrVector = new uint[2];
            byte[] iv = new byte[VECTOR_SIZE];

            Buffer.BlockCopy(Key, 0, iv, 0, VECTOR_SIZE);
            int keyLen = Key.Length - VECTOR_SIZE;
            byte[] key = new byte[keyLen];
            Buffer.BlockCopy(Key, VECTOR_SIZE, key, 0, keyLen);

            if (_keySize == 16)
                _dstCode = (byte[])TAU.Clone();
            else
                _dstCode = (byte[])SIGMA.Clone();

            SetKey(key, iv);
            _isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator with key and salt arrays
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// <param name="Salt">The salt value containing an additional source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null key or salt is used</exception>
        public void Initialize(byte[] Key, byte[] Salt)
        {
            byte[] seed = new byte[Key.Length + Salt.Length];

            Buffer.BlockCopy(Key, 0, seed, 0, Key.Length);
            Buffer.BlockCopy(Salt, 0, seed, Key.Length, Salt.Length);

            Initialize(seed);
        }

        /// <summary>
        /// Initialize the generator with a key, a salt array, and an information string or nonce
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// <param name="Salt">The salt value used as an additional source of entropy</param>
        /// <param name="Info">The information string or nonce used as a third source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null key, salt, or info string is used</exception>
        public void Initialize(byte[] Key, byte[] Salt, byte[] Info)
        {
            byte[] seed = new byte[Key.Length + Salt.Length + Info.Length];

            Buffer.BlockCopy(Key, 0, seed, 0, Key.Length);
            Buffer.BlockCopy(Salt, 0, seed, Key.Length, Salt.Length);
            Buffer.BlockCopy(Info, 0, seed, Salt.Length + Key.Length, Info.Length);

            Initialize(seed);
        }

        /// <summary>
        /// Generate a block of pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        public int Generate(byte[] Output)
        {
            ProcessBlock(Output, 0);

            return Output.Length;
        }

        /// <summary>
        /// Generate pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if the output buffer is too small</exception>
        public int Generate(byte[] Output, int OutOffset, int Size)
        {
            if ((Output.Length - Size) < OutOffset)
                throw new CryptoGeneratorException("SP20Drbg:Generate", "Output buffer too small!", new Exception());

            ProcessBlock(Output, OutOffset);

            return Size;
        }

        /// <summary>
        /// <para>Update the Seed material. Two state Seed paramater: 
        /// If Seed size is equal to cipher key size plus iv size, both are updated. 
        /// If Seed size is equal to counter size (8 bytes) counter is updated.</para>
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Seed is used</exception>
        public void Update(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("SP20Drbg:Update", "Seed can not be null!", new ArgumentNullException());

            if (Seed.Length >= 32)
                Initialize(Seed);
            else if (Seed.Length >= VECTOR_SIZE)
                Buffer.BlockCopy(Seed, 0, _ctrVector, 0, VECTOR_SIZE);
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
                    _wrkState[1] = IntUtils.BytesToLe32(Key, 0);
                    _wrkState[2] = IntUtils.BytesToLe32(Key, 4);
                    _wrkState[3] = IntUtils.BytesToLe32(Key, 8);
                    _wrkState[4] = IntUtils.BytesToLe32(Key, 12);
                    _wrkState[5] = IntUtils.BytesToLe32(_dstCode, 4);
                    _wrkState[6] = IntUtils.BytesToLe32(Iv, 0);
                    _wrkState[7] = IntUtils.BytesToLe32(Iv, 4);
                    _wrkState[8] = IntUtils.BytesToLe32(_dstCode, 8);
                    _wrkState[9] = IntUtils.BytesToLe32(Key, 16);
                    _wrkState[10] = IntUtils.BytesToLe32(Key, 20);
                    _wrkState[11] = IntUtils.BytesToLe32(Key, 24);
                    _wrkState[12] = IntUtils.BytesToLe32(Key, 28);
                    _wrkState[13] = IntUtils.BytesToLe32(_dstCode, 12);
                }
                else
                {
                    _wrkState[0] = IntUtils.BytesToLe32(_dstCode, 0);
                    _wrkState[1] = IntUtils.BytesToLe32(Key, 0);
                    _wrkState[2] = IntUtils.BytesToLe32(Key, 4);
                    _wrkState[3] = IntUtils.BytesToLe32(Key, 8);
                    _wrkState[4] = IntUtils.BytesToLe32(Key, 12);
                    _wrkState[5] = IntUtils.BytesToLe32(_dstCode, 4);
                    _wrkState[6] = IntUtils.BytesToLe32(Iv, 0);
                    _wrkState[7] = IntUtils.BytesToLe32(Iv, 4);
                    _wrkState[8] = IntUtils.BytesToLe32(_dstCode, 8);
                    _wrkState[9] = IntUtils.BytesToLe32(Key, 0);
                    _wrkState[10] = IntUtils.BytesToLe32(Key, 4);
                    _wrkState[11] = IntUtils.BytesToLe32(Key, 8);
                    _wrkState[12] = IntUtils.BytesToLe32(Key, 12);
                    _wrkState[13] = IntUtils.BytesToLe32(_dstCode, 12);
                }
            }
        }
        #endregion

        #region Transform
        private void SalsaCore(byte[] Output, int OutOffset, uint[] Counter)
        {
            int ctr = 0;
            uint X0 = _wrkState[ctr];
            uint X1 = _wrkState[++ctr];
            uint X2 = _wrkState[++ctr];
            uint X3 = _wrkState[++ctr];
            uint X4 = _wrkState[++ctr];
            uint X5 = _wrkState[++ctr];
            uint X6 = _wrkState[++ctr];
            uint X7 = _wrkState[++ctr];
            uint X8 = Counter[0];
            uint X9 = Counter[1];
            uint X10 = _wrkState[++ctr];
            uint X11 = _wrkState[++ctr];
            uint X12 = _wrkState[++ctr];
            uint X13 = _wrkState[++ctr];
            uint X14 = _wrkState[++ctr];
            uint X15 = _wrkState[++ctr];

            ctr = Rounds;

            while (ctr != 0)
            {
                X4 ^= IntUtils.RotateLeft(X0 + X12, 7);
                X8 ^= IntUtils.RotateLeft(X4 + X0, 9);
                X12 ^= IntUtils.RotateLeft(X8 + X4, 13);
                X0 ^= IntUtils.RotateLeft(X12 + X8, 18);
                X9 ^= IntUtils.RotateLeft(X5 + X1, 7);
                X13 ^= IntUtils.RotateLeft(X9 + X5, 9);
                X1 ^= IntUtils.RotateLeft(X13 + X9, 13);
                X5 ^= IntUtils.RotateLeft(X1 + X13, 18);
                X14 ^= IntUtils.RotateLeft(X10 + X6, 7);
                X2 ^= IntUtils.RotateLeft(X14 + X10, 9);
                X6 ^= IntUtils.RotateLeft(X2 + X14, 13);
                X10 ^= IntUtils.RotateLeft(X6 + X2, 18);
                X3 ^= IntUtils.RotateLeft(X15 + X11, 7);
                X7 ^= IntUtils.RotateLeft(X3 + X15, 9);
                X11 ^= IntUtils.RotateLeft(X7 + X3, 13);
                X15 ^= IntUtils.RotateLeft(X11 + X7, 18);
                X1 ^= IntUtils.RotateLeft(X0 + X3, 7);
                X2 ^= IntUtils.RotateLeft(X1 + X0, 9);
                X3 ^= IntUtils.RotateLeft(X2 + X1, 13);
                X0 ^= IntUtils.RotateLeft(X3 + X2, 18);
                X6 ^= IntUtils.RotateLeft(X5 + X4, 7);
                X7 ^= IntUtils.RotateLeft(X6 + X5, 9);
                X4 ^= IntUtils.RotateLeft(X7 + X6, 13);
                X5 ^= IntUtils.RotateLeft(X4 + X7, 18);
                X11 ^= IntUtils.RotateLeft(X10 + X9, 7);
                X8 ^= IntUtils.RotateLeft(X11 + X10, 9);
                X9 ^= IntUtils.RotateLeft(X8 + X11, 13);
                X10 ^= IntUtils.RotateLeft(X9 + X8, 18);
                X12 ^= IntUtils.RotateLeft(X15 + X14, 7);
                X13 ^= IntUtils.RotateLeft(X12 + X15, 9);
                X14 ^= IntUtils.RotateLeft(X13 + X12, 13);
                X15 ^= IntUtils.RotateLeft(X14 + X13, 18);
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
            IntUtils.Le32ToBytes(X8 + Counter[0], Output, OutOffset); OutOffset += 4;
            IntUtils.Le32ToBytes(X9 + Counter[1], Output, OutOffset); OutOffset += 4;
            IntUtils.Le32ToBytes(X10 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
            IntUtils.Le32ToBytes(X11 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
            IntUtils.Le32ToBytes(X12 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
            IntUtils.Le32ToBytes(X13 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
            IntUtils.Le32ToBytes(X14 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
            IntUtils.Le32ToBytes(X15 + _wrkState[++ctr], Output, OutOffset);
        }

        private void Generate(int Size, uint[] Counter, byte[] Output, int OutOffset)
        {
            int aln = Size - (Size % BLOCK_SIZE);
            int ctr = 0;

            while (ctr != aln)
            {
                SalsaCore(Output, OutOffset + ctr, Counter);
                Increment(Counter);
                ctr += BLOCK_SIZE;
            }

            if (ctr != Size)
            {
                byte[] outputBlock = new byte[BLOCK_SIZE];
                SalsaCore(outputBlock, 0, Counter);
                int fnlSize = Size % BLOCK_SIZE;
                Buffer.BlockCopy(outputBlock, 0, Output, OutOffset + (Size - fnlSize), fnlSize);
                Increment(Counter);
            }
        }

        private void ProcessBlock(byte[] Output, int OutOffset)
        {
            int outSize = Output.Length - OutOffset;

            if (!IsParallel || outSize < MIN_PARALLEL)
            {
                // generate random
                Generate(outSize, _ctrVector, Output, OutOffset);
            }
            else
            {
                // parallel CTR processing //
                int cnkSize = (outSize / BLOCK_SIZE / ProcessorCount) * BLOCK_SIZE;
                int rndSize = cnkSize * ProcessorCount;
                int subSize = (cnkSize / BLOCK_SIZE);
                // create jagged array of 'sub counters'
                uint[][] vectors = new uint[ProcessorCount][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, ProcessorCount, i =>
                {
                    // offset counter by chunk size / block size
                    vectors[i] = Increase(_ctrVector, subSize * i);
                    // create random with offset counter
                    this.Generate(cnkSize, vectors[i], Output, OutOffset + (i * cnkSize));
                });

                // last block processing
                if (rndSize < outSize)
                {
                    int fnlSize = outSize % rndSize;
                    Generate(fnlSize, vectors[ProcessorCount - 1], Output, OutOffset + rndSize);
                }

                // copy the last counter position to class variable
                Array.Copy(vectors[ProcessorCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }
        #endregion

        #region Helpers
        private void Increment(uint[] Counter)
        {
            if (++Counter[0] == 0)
                ++Counter[1];
        }

        private uint[] Increase(uint[] Counter, int Size)
        {
            uint[] copy = new uint[Counter.Length];
            Array.Copy(Counter, 0, copy, 0, Counter.Length);

            for (int i = 0; i < Size; i++)
                Increment(copy);

            return copy;
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
                    if (_ctrVector != null)
                    {
                        Array.Clear(_ctrVector, 0, _ctrVector.Length);
                        _ctrVector = null;
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
                    _keySize = 0;
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
