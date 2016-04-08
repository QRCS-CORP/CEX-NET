#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.CryptoException;
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
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
// 
// Code Base Guides:
// Portions of this code based on the Bouncy Castle 
// <a href="http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.48/org/bouncycastle/crypto/generators/HKDFBytesGenerator.java">SHA512</a> class.
// 
// Implementation Details:
// An implementation of an Hash based Key Derivation Function (HKDF). 
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// HKDF: An implementation of an Hash based Key Derivation Function
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rnd = new HKDF(new SHA512()))
    /// {
    ///     // initialize
    ///     rnd.Initialize(Salt, Ikm, [Nonce]);
    ///     // generate bytes
    ///     rnd.Generate(Output, [Offset], [Size]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Mac.HMAC"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with a <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> or a <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Macs">Mac</see>.</description></item>
    /// <item><description>The <see cref="HKDF(IDigest, bool)">Constructors</see> DisposeEngine parameter determines if Digest engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// <item><description>Salt size should be multiple of Digest block size.</description></item>
    /// <item><description>Ikm size should be Digest hash return size.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2104">2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
    /// <item><description>RFC <a href="http://tools.ietf.org/html/rfc5869">5869</a>: HMAC-based Extract-and-Expand Key Derivation Function.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class HKDF : IGenerator
    {
        #region Constants
        private const string ALG_NAME = "HKDF";
        #endregion

        #region Fields
        private byte[] _currentT;
        private byte[] _digestInfo = new byte[0];
        private IMac _digestMac;
        private bool _disposeEngine = true;
        private int _hashLength;
        private bool _isInitialized = false;
        private int _keySize = 64;
        private bool _isDisposed = false;
        private int _generatedBytes;
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
            get { return Generators.HKDF; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class using the message digests enumeration name
        /// </summary>
        /// 
        /// <param name="DigestType">The message digest enumeration name</param>
        public HKDF(Digests DigestType)
        {
            IDigest digest = Helper.DigestFromName.GetInstance(DigestType);
            _disposeEngine = true;
            _digestMac = new HMAC(digest);
            _hashLength = digest.DigestSize;
            _keySize = digest.BlockSize;
        }

        /// <summary>
        /// Initialize this class class using a Digest instance
        /// </summary>
        /// 
        /// <param name="Digest">The message digest instance</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Digest is used</exception>
        public HKDF(IDigest Digest, bool DisposeEngine = true)
        {
            if (Digest == null)
                throw new CryptoGeneratorException("HKDF:Ctor", "Digest can not be null!", new ArgumentNullException());

            _disposeEngine = DisposeEngine;
            _digestMac = new HMAC(Digest);
            _hashLength = Digest.DigestSize;
            _keySize = Digest.BlockSize;
        }

        /// <summary>
        /// Initialize this class class using an Hmac instance
        /// </summary>
        /// 
        /// <param name="Hmac">The Hmac digest instance</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Hmac is used</exception>
        public HKDF(IMac Hmac)
        {
            if (Hmac == null)
                throw new CryptoGeneratorException("HKDF:Ctor", "Hmac can not be null!", new ArgumentNullException());

            _digestMac = Hmac;
            _hashLength = Hmac.MacSize;
            _keySize = Hmac.BlockSize;
        }

        private HKDF()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~HKDF()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Salt is used</exception>
        public void Initialize(byte[] Salt)
        {
            if (Salt == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "Salt can not be null!", new ArgumentNullException());

            _digestMac.Initialize(Salt, null);
            _generatedBytes = 0;
            _currentT = new byte[_hashLength];
            _isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Salt or Ikm is used</exception>
        public void Initialize(byte[] Salt, byte[] Ikm)
        {
            if (Salt == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Ikm == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "IKM can not be null!", new ArgumentNullException());

            _digestMac.Initialize(Extract(Salt, Ikm), null);
            _generatedBytes = 0;
            _currentT = new byte[_hashLength];
            _isInitialized = true;
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// <param name="Info">Nonce value</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Salt or Ikm is used</exception>
        public void Initialize(byte[] Salt, byte[] Ikm, byte[] Info)
        {
            if (Salt == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "Salt can not be null!", new ArgumentNullException());
            if (Ikm == null)
                throw new CryptoGeneratorException("HKDF:Initialize", "IKM can not be null!", new ArgumentNullException());

            _digestMac.Initialize(Extract(Salt, Ikm), null);

            if (Info != null)
                _digestInfo = Info;

            _generatedBytes = 0;
            _currentT = new byte[_hashLength];
            _isInitialized = true;
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
        /// <exception cref="CryptoGeneratorException">Thrown if the output buffer is too small, or the size requested exceeds maximum: 255 * HashLen bytes</exception>
        public int Generate(byte[] Output, int OutOffset, int Size)
        {
            if ((Output.Length - Size) < OutOffset)
                throw new CryptoGeneratorException("PBKDF2:Generate", "Output buffer too small!", new Exception());
            if (_generatedBytes + Size > 255 * _hashLength)
                throw new CryptoGeneratorException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output", new ArgumentOutOfRangeException());

            if (_generatedBytes % _hashLength == 0)
                ExpandNext();

            // copy what is left in the buffer
            int toGenerate = Size;
            int posInT = _generatedBytes % _hashLength;
            int leftInT = _hashLength - _generatedBytes % _hashLength;
            int toCopy = System.Math.Min(leftInT, toGenerate);

            Buffer.BlockCopy(_currentT, posInT, Output, OutOffset, toCopy);
            _generatedBytes += toCopy;
            toGenerate -= toCopy;
            OutOffset += toCopy;

            while (toGenerate > 0) //TODO: review- this can be faster
            {
                ExpandNext();
                toCopy = System.Math.Min(_hashLength, toGenerate);
                Buffer.BlockCopy(_currentT, 0, Output, OutOffset, toCopy);
                _generatedBytes += toCopy;
                toGenerate -= toCopy;
                OutOffset += toCopy;
            }

            return Size;
        }

        /// <summary>
        /// Update the Seed material
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null Seed is used</exception>
        public void Update(byte[] Seed)
        {
            if (Seed == null)
                throw new CryptoGeneratorException("HKDF:Update", "Seed can not be null!", new ArgumentNullException());

            Initialize(Seed);
        }
        #endregion

        #region Private Methods
        private byte[] Extract(byte[] Salt, byte[] Ikm)
        {
            byte[] prk = new byte[_hashLength];

            if (Salt == null)
                _digestMac.Initialize(new byte[_hashLength], null);
            else
                _digestMac.Initialize(Salt, null);

            _digestMac.BlockUpdate(Ikm, 0, Ikm.Length);
            _digestMac.DoFinal(prk, 0);

            return prk;
        }

        private void ExpandNext()
        {
            int n = _generatedBytes / _hashLength + 1;

            if (n >= 256)
                throw new CryptoGeneratorException("HKDF:ExpandNext", "HKDF cannot generate more than 255 blocks of HashLen size", new ArgumentOutOfRangeException());

            // special case for T(0): T(0) is empty, so no update
            if (_generatedBytes != 0)
                _digestMac.BlockUpdate(_currentT, 0, _hashLength);
            if (_digestInfo.Length > 0)
                _digestMac.BlockUpdate(_digestInfo, 0, _digestInfo.Length);

            _digestMac.Update((byte)n);
            _digestMac.DoFinal(_currentT, 0);
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
                    if (_digestMac != null && _disposeEngine)
                    {
                        _digestMac.Dispose();
                        _digestMac = null;
                    }
                    if (_currentT != null)
                    {
                        Array.Clear(_currentT, 0, _currentT.Length);
                        _currentT = null;
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
