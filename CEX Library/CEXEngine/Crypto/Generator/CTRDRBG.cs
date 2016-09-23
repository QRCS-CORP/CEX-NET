#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
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
// An implementation of a Counter based Deterministic Random Byte Generator (CTRDRBG). 
// Written by John Underhill, November 21, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// CTRDrbg: An implementation of a Encryption Counter based Deterministic Random Byte Generator
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new CTRDrbg(new RHX()))
    /// {
    ///     // initialize
    ///     rnd.Initialize(Salt, [Ikm], [Nonce]);
    ///     // generate bytes
    ///     rnd.Generate(Output, [Offset], [Size]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with any block <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">cipher</see>.</description></item>
    /// <item><description>Parallelized by default on a multi processer system when an input byte array of <see cref="ParallelMinimumSize"/> bytes or larger is used.</description></item>
    /// <item><description>Parallelization can be disabled using the <see cref="IsParallel"/> property.</description></item>
    /// <item><description>The <see cref="CTRDrbg(IBlockCipher, bool, int)">Constructors</see> DisposeEngine parameter determines if Cipher engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Combination of [Key, Salt, Info] must be: cipher key size +  cipher block size in length.</description></item>
    /// <item><description>Salt and Info are optional, and combined to create key and initialization vector.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
    /// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the Codebook-based: Deterministic Random Bit Generator.</description></item>
    /// </list>
    /// </remarks>
    public sealed class CTRDrbg : IGenerator
    {
        #region Constants
        private const string ALG_NAME = "CTRDrbg";
        private const int BLOCK_SIZE = 16;
        private const int COUNTER_SIZE = 16;
        private const int MAX_PARALLEL = 1024000;
        private const int MIN_PARALLEL = 1024;
        #endregion

        #region Fields
        private int _blockSize = BLOCK_SIZE;
        private IBlockCipher _blockCipher;
        private byte[] _ctrVector;
        private bool _disposeEngine = true;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private int _keySize = 32 + COUNTER_SIZE;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Generator is ready to produce data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get/Set Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return _isParallel; }
            set
            {
                if (ProcessorCount == 1)
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
        /// Get: The generators type name
        /// </summary>
        public Generators Enumeral 
        {
            get { return Generators.CTRDrbg; }
        }

        /// <summary>
        /// Get: Maximum input size with parallel processing
        /// </summary>
        public static int ParallelMaximumSize
        {
            get { return MAX_PARALLEL; }
        }

        /// <summary>
        /// Processor count
        /// </summary>
        private int ProcessorCount { get; set; }

        /// <summary>
        /// Get: Algorithm Name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Minimum input size to trigger parallel processing
        /// </summary>
        public static int ParallelMinimumSize
        {
            get { return MIN_PARALLEL; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Creates a CTR Bytes Generator using a block cipher
        /// </summary>
        /// 
        /// <param name="Cipher">The block cipher</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// <param name="KeySize">The key size (in bytes) of the symmetric cipher; a <c>0</c> value will auto size the key</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null block cipher is used</exception>
        public CTRDrbg(IBlockCipher Cipher, bool DisposeEngine = true, int KeySize = 0)
        {
            if (Cipher == null)
                throw new CryptoGeneratorException("CTRDrbg:Ctor", "Cipher can not be null!", new ArgumentNullException());

            _disposeEngine = DisposeEngine;
            _blockCipher = Cipher;

            if (KeySize == 0)
            {
                // default the 256 bit key size
                _keySize = 32;
            }
            else
            {
                if (!IsValidKeySize(KeySize))
                    throw new CryptoGeneratorException("CTRDrbg:CTor", "The key size must be a ciphers legal key size!");
                else
                    _keySize = KeySize;
            }

            _blockSize = _blockCipher.BlockSize;

            ProcessorCount = Environment.ProcessorCount;
            if (ProcessorCount % 2 != 0)
                ProcessorCount--;

            IsParallel = ProcessorCount > 1;
        }

        private CTRDrbg()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CTRDrbg()
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
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null key is used</exception>
        public void Initialize(byte[] Key)
        {
            if (Key == null)
                throw new CryptoGeneratorException("CTRDrbg:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Key.Length < _keySize + COUNTER_SIZE)
                throw new CryptoGeneratorException("CTRDrbg:Initialize", string.Format("Minimum key size has not been added. Size must be at least {0} bytes!", _keySize + COUNTER_SIZE), new ArgumentOutOfRangeException());

            _ctrVector = new byte[_blockSize];
            Buffer.BlockCopy(Key, 0, _ctrVector, 0, _blockSize);
            int keyLen = Key.Length - _blockSize;
            byte[] key = new byte[keyLen];
            Buffer.BlockCopy(Key, _blockSize, key, 0, keyLen);

            _blockCipher.Initialize(true, new KeyParams(key));
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
            if (Key == null)
                throw new CryptoGeneratorException("CTRDrbg:Initialize", "Key can not be null!", new ArgumentNullException());
            if (Salt == null)
                throw new CryptoGeneratorException("CTRDrbg:Initialize", "Salt can not be null!", new ArgumentNullException());

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
            ParallelTransform(Output, 0);

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
                throw new CryptoGeneratorException("CTRDrbg:Generate", "Output buffer too small!", new Exception());

            ParallelTransform(Output, OutOffset);

            return Size;
        }

        /// <summary>
        /// <para>Update the Seed material. Two state Seed paramater: 
        /// If Seed size is equal to cipher key size plus counter size, both are updated. 
        /// If Seed size is equal to counter size (16 bytes) counter is updated.</para>
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Seed is used</exception>
        public void Update(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("CTRDrbg:Update", "Seed can not be null!", new ArgumentNullException());

            if (Seed.Length >= KeySize)
                Initialize(Seed);
            else if (Seed.Length >= COUNTER_SIZE)
                Buffer.BlockCopy(Seed, 0, _ctrVector, 0, _ctrVector.Length);
        }
        #endregion

        #region Random Generator
        private void Generate(int Size, byte[] Counter, byte[] Output, int OutOffset)
        {
            int aln = Size - (Size % _blockSize);
            int ctr = 0;

            while (ctr != aln)
            {
                _blockCipher.EncryptBlock(Counter, 0, Output, OutOffset + ctr);
                Increment(Counter);
                ctr += _blockSize;
            }

            if (ctr != Size)
            {
                byte[] outputBlock = new byte[_blockSize];
                _blockCipher.EncryptBlock(Counter, outputBlock);
                int fnlSize = Size % _blockSize;
                Buffer.BlockCopy(outputBlock, 0, Output, OutOffset + (Size - fnlSize), fnlSize);
                Increment(Counter);
            }
        }

        private void ParallelTransform(byte[] Output, int OutOffset)
        {
            int blklen = Output.Length - OutOffset;

            if (!_isParallel || blklen < MIN_PARALLEL)
	        {
		        // generate random
                Generate(blklen, _ctrVector, Output, OutOffset);
	        }
	        else
	        {
		        // parallel CTR processing //
                int cnksize = (blklen / _blockSize / ProcessorCount) * _blockSize;
		        int rndsize = cnksize * ProcessorCount;
		        int subsize = (cnksize / _blockSize);
		        // create jagged array of 'sub counters'
                byte[][] vectors = new byte[ProcessorCount][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, ProcessorCount, i =>
                {
                    // offset counter by chunk size / block size
                    vectors[i] = Increase(_ctrVector, subsize * i);
                    // create random at offset position
                    Generate(cnksize, vectors[i], Output, (i * cnksize));
                });

		        // last block processing
                if (rndsize < blklen)
		        {
                    int fnlsize = blklen % rndsize;
                    Generate(fnlsize, vectors[ProcessorCount - 1], Output, rndsize);
		        }

                // copy the last counter position to class variable
                Buffer.BlockCopy(vectors[ProcessorCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
	        }
        }

        private static void Increment(byte[] Counter)
        {
            int i = Counter.Length;
            while (--i >= 0 && ++Counter[i] == 0) { }
        }

        private static byte[] Increase(byte[] Counter, int Size)
        {
            int carry = 0;
            byte[] buffer = new byte[Counter.Length];
            int offset = buffer.Length - 1;
            byte[] cnt = BitConverter.GetBytes(Size);
            byte osrc, odst, ndst;
            Buffer.BlockCopy(Counter, 0, buffer, 0, Counter.Length);

            for (int i = offset; i > 0; i--)
            {
                odst = buffer[i];
                osrc = offset - i < cnt.Length ? cnt[offset - i] : (byte)0;
                ndst = (byte)(odst + osrc + carry);
                carry = ndst < odst ? 1 : 0;
                buffer[i] = ndst;
            }

            return buffer;
        }

        private bool IsValidKeySize(int KeySize = 0)
	    {
		    for (int i = 0; i < _blockCipher.LegalKeySizes.Length; ++i)
		    {
			    if (KeySize == _blockCipher.LegalKeySizes[i])
				    break;
			    if (i == _blockCipher.LegalKeySizes.Length - 1)
				    return false;
		    }
		    return true;
	    }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class, and dependant resources
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
                    if (_blockCipher != null && _disposeEngine)
                    {
                        _blockCipher.Dispose();
                        _blockCipher = null;
                    }
                    if (_ctrVector != null)
                    {
                        Array.Clear(_ctrVector, 0, _ctrVector.Length);
                        _ctrVector = null;
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
