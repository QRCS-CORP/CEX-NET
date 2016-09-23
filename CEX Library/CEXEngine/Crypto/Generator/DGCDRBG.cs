#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
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
// Code Base Guides:</description>
// Portions of this code based on the Bouncy Castle Java 
// <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a>.
// 
// Implementation Details:</description>
// An implementation of a Digest Counter based Deterministic Random Byte Generator (DGTDRBG),
// based on the NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">Hash_DRBG</a>, SP800-90A Appendix E1. 
// Written by John Underhill, January 09, 2014
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// DGTDRBG: An implementation of a Digest Counter based Deterministic Random Byte Generator
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new DGTDRBG(new SHA512()))
    /// {
    ///     // initialize
    ///     rnd.Initialize(Salt, [Ikm], [Nonce]);
    ///     // generate bytes
    ///     rnd.Generate(Output, [Offset], [Size]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with any <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">digest</see>.</description></item>
    /// <item><description>Combination of [Salt, Ikm, Nonce] must be at least: digest block size + counter (8 bytes) size in length.</description></item>
    /// <item><description>The <see cref="DGCDrbg(IDigest, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// <item><description>Output buffer is 4 * the digest return size.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">SP800-90A R1</a>: Appendix E1.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">SP800-90A</a>: Appendix E1.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
    /// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the Codebook-based: Deterministic Random Bit Generator.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class DGCDrbg : IGenerator
    {
        #region Constants
        private const string ALG_NAME = "DGCDrbg";
        private const int COUNTER_SIZE = 8;
        private const long CYCLE_COUNT = 10;
        #endregion

        #region Fields
        private byte[] _dgtSeed;
        private byte[] _dgtState;
        private bool _disposeEngine = true;
        private bool _isInitialized = false;
        private int _keySize = 32 + COUNTER_SIZE;
        private bool _isDisposed = false;
        private IDigest _msgDigest;
        private long _stateCtr = 1;
        private long _seedCtr = 1;
        private object _objLock = new object();
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
        /// <para>Minimum initialization key size in bytes; 
        /// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
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
            get { return Generators.DGCDrbg; }
        }

        /// <summary>
        /// Algorithm name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Digest">Hash function</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null digest is used</exception>
        public DGCDrbg(IDigest Digest, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoGeneratorException("DGCDrbg:Ctor", "Digest can not be null!", new ArgumentNullException());

            _disposeEngine = DisposeEngine;
            _msgDigest = Digest;
            _dgtSeed = new byte[Digest.DigestSize];
            _dgtState = new byte[Digest.DigestSize];
            _keySize = _msgDigest.BlockSize + COUNTER_SIZE;
        }

        private DGCDrbg()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~DGCDrbg()
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
                throw new CryptoGeneratorException("DGCDrbg:Initialize", "Key can not be null!", new ArgumentNullException());
            if (Key.Length < COUNTER_SIZE)
                throw new CryptoGeneratorException("DGCDrbg:Initialize", "Key must be at least 8 bytes!", new ArgumentOutOfRangeException());

            long[] counter = new long[1];
            int keyLen = (Key.Length - COUNTER_SIZE) < 0 ? 0 : Key.Length - COUNTER_SIZE;
            byte[] key = new byte[keyLen];
            int ctrLen = Math.Min(COUNTER_SIZE, Key.Length);

            Buffer.BlockCopy(Key, 0, counter, 0, ctrLen);
            Buffer.BlockCopy(Key, ctrLen, key, 0, keyLen);

            UpdateSeed(key);
            UpdateCounter(counter[0]);

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
            return Generate(Output, 0, Output.Length);
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
                throw new CryptoGeneratorException("DGCDrbg:Generate", "Output buffer too small!", new Exception());

            int offset = 0;
            int len = OutOffset + Size;

            GenerateState();

            for (int i = OutOffset; i < len; ++i)
            {
                if (offset == _dgtState.Length)
                {
                    GenerateState();
                    offset = 0;
                }

                Output[i] = _dgtState[offset++];
            }

            return Size;
        }

        /// <summary>
        /// <para>Update the Seed material. Three state Seed paramater: 
        /// If Seed size is equal to digest blocksize plus counter size, both are updated. 
        /// If Seed size is equal to digest block size, internal state seed is updated.
        /// If Seed size is equal to counter size (8 bytes) counter is updated.</para>
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null or invalid Seed is used</exception>
        public void Update(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("DGCDrbg:Update", "Seed can not be null!", new ArgumentNullException());
            if (Seed.Length < COUNTER_SIZE)
                throw new CryptoGeneratorException("DGCDrbg:Update", String.Format("Minimum key size has not been added. Size must be at least {0} bytes!", COUNTER_SIZE), new ArgumentOutOfRangeException());

            // update seed and counter
            if (Seed.Length >= _msgDigest.BlockSize + COUNTER_SIZE)
            {
                Initialize(Seed);
            }
            else if (Seed.Length == _msgDigest.BlockSize)
            {
                UpdateSeed(Seed);
            }
            else if (Seed.Length == COUNTER_SIZE)
            {
                // update counter only
                long[] counter = new long[1];
                Buffer.BlockCopy(Seed, 0, counter, 0, COUNTER_SIZE);
                UpdateCounter(counter[0]);
            }
            else
            {
                UpdateSeed(Seed);
            }
        }
        #endregion

        #region Private Methods
        private void CycleSeed()
        {
            _msgDigest.BlockUpdate(_dgtSeed, 0, _dgtSeed.Length);
            IncrementCounter(_seedCtr++);
            _msgDigest.DoFinal(_dgtSeed, 0);
        }

        private void IncrementCounter(long Counter)
        {
            for (int i = 0; i < 8; i++)
            {
                _msgDigest.Update((byte)Counter);
                Counter >>= 8;
            }
        }

        private void GenerateState()
        {
            lock (_objLock)
            {
                IncrementCounter(_stateCtr++);

                _msgDigest.BlockUpdate(_dgtState, 0, _dgtState.Length);
                _msgDigest.BlockUpdate(_dgtSeed, 0, _dgtSeed.Length);
                _msgDigest.DoFinal(_dgtState, 0);

                if ((_stateCtr % CYCLE_COUNT) == 0)
                    CycleSeed();
            }
        }

        private void UpdateCounter(long Counter)
        {
            lock (_objLock)
            {
                IncrementCounter(Counter);
                _msgDigest.BlockUpdate(_dgtSeed, 0, _dgtSeed.Length);
                _msgDigest.DoFinal(_dgtSeed, 0);
            }
        }

        private void UpdateSeed(byte[] Seed)
        {
            lock (_objLock)
            {
                _msgDigest.BlockUpdate(Seed, 0, Seed.Length);
                _msgDigest.BlockUpdate(_dgtSeed, 0, _dgtSeed.Length);
                _msgDigest.DoFinal(_dgtSeed, 0);
            }
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
                    if (_msgDigest != null && _disposeEngine)
                    {
                        _msgDigest.Dispose();
                        _msgDigest = null;
                    }
                    if (_dgtSeed != null)
                    {
                        Array.Clear(_dgtSeed, 0, _dgtSeed.Length);
                        _dgtSeed = null;
                    }
                    if (_dgtState != null)
                    {
                        Array.Clear(_dgtState, 0, _dgtState.Length);
                        _dgtState = null;
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
