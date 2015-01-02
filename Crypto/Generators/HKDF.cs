#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digests;
using VTDev.Libraries.CEXEngine.Crypto.Macs;
#endregion

#region License Information
/// <remarks>
/// <para>Permission is hereby granted, free of charge, to any person obtaining
/// a copy of this software and associated documentation files (the
/// "Software"), to deal in the Software without restriction, including
/// without limitation the rights to use, copy, modify, merge, publish,
/// distribute, sublicense, and/or sell copies of the Software, and to
/// permit persons to whom the Software is furnished to do so, subject to
/// the following conditions:</para>
/// 
/// <para>The copyright notice and this permission notice shall be
/// included in all copies or substantial portions of the Software.</para>
/// 
/// <para>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
/// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
/// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
/// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
/// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
/// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
/// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.</para>
#endregion

#region Class Notes
/// <para><description>Principal Algorithms:</description>
/// An implementation of the SHA-2 digest with a 512 bit return size.
/// SHA-2 <see cref="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</see>.</para>
/// 
/// <para><description>Guiding Publications:</description>
/// RFC 5869: <see cref="http://tools.ietf.org/html/rfc5869">Specification</see>.
/// HKDF Scheme: <see cref="http://tools.ietf.org/html/rfc5869">Whitepaper</see>.
/// </para>
/// 
/// <para><description>Code Base Guides:</description>
/// Portions of this code based on the Bouncy Castle 
/// <see cref="http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.48/org/bouncycastle/crypto/generators/HKDFBytesGenerator.java">SHA512Digest</see> class.</para>
/// 
/// <para><description>Implementation Details:</description>
/// An implementation of an Hash based Key Derivation Function (HKDF). 
/// Written by John Underhill, September 19, 2014
/// contact: steppenwolfe_2000@yahoo.com</para>
/// </remarks>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generators
{
    /// <summary>
    /// HKDF: An implementation of an Hash based Key Derivation Function (HKDF). 
    /// 
    /// <list type="bullet">
    /// <item><description>Can be initialized with a Digest or a Mac.</description></item>
    /// <item><description>Salt size should be multile of Digest block size.</description></item>
    /// <item><description>Ikm size should be Digest hash return size.</description></item>
    /// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
    /// </list>
    /// 
    /// <example>
    /// <description>Example using an <c>IGenerator</c> interface:</description>
    /// <code>
    /// using (IGenerator rand = new HKDF(new SHA512Digest()))
    /// {
    ///     // initialize
    ///     rand.Init(Salt, [Ikm], [Nonce]);
    ///     // generate bytes
    ///     rand.Generate(Size, Output);
    /// }
    /// </code>
    /// </example>
    /// </summary> 
    public class HKDF : IGenerator, IDisposable
    {
        #region Fields
        private byte[] _currentT;
        private byte[] _digestInfo = new byte[0];
        private int _hashLength;
        private IMac _Hmac;
        private bool _isDisposed = false;
        private int _generatedBytes;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return "HKDF"; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Creates a HKDF Bytes Generator based on the given hash function
        /// </summary>
        /// 
        /// <param name="Digest">The digest used</param>
        public HKDF(IDigest Digest)
        {
            this._Hmac = new HMAC(Digest);
            this._hashLength = Digest.DigestSize;
        }

        /// <summary>
        /// Creates a HKDF Bytes Generator based on the given HMAC function
        /// </summary>
        /// 
        /// <param name="Hmac">The HMAC digest used</param>
        public HKDF(IMac Hmac)
        {
            this._Hmac = Hmac;
            this._hashLength = Hmac.DigestSize;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null salt is used.</exception>
        public void Init(byte[] Salt)
        {
            if (Salt == null)
                throw new ArgumentNullException("Salt can not be null!");

            _Hmac.Init(Salt);
            _generatedBytes = 0;
            _currentT = new byte[_hashLength];
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null salt or ikm is used.</exception>
        public void Init(byte[] Salt, byte[] Ikm)
        {
            if (Salt == null)
                throw new ArgumentNullException("Salt can not be null!");
            if (Ikm == null)
                throw new ArgumentNullException("Ikm can not be null!");

            _Hmac.Init(Extract(Salt, Ikm));
            _generatedBytes = 0;
            _currentT = new byte[_hashLength];
        }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// <param name="Info">Nonce value</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null salt or ikm is used.</exception>
        public void Init(byte[] Salt, byte[] Ikm, byte[] Info)
        {
            if (Salt == null)
                throw new ArgumentNullException("Salt can not be null!");
            if (Ikm == null)
                throw new ArgumentNullException("Ikm can not be null!");

            _Hmac.Init(Extract(Salt, Ikm));

            if (Info != null)
                _digestInfo = Info;

            _generatedBytes = 0;
            _currentT = new byte[_hashLength];
        }

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        public int Generate(int Size, byte[] Output)
        {
            return Generate(Size, Output, 0);
        }

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        public int Generate(int Size, byte[] Output, int OutOffset)
        {
            if (_generatedBytes + Size > 255 * _hashLength)
                throw new ArgumentOutOfRangeException("HKDF may only be used for 255 * HashLen bytes of output");

            if (_generatedBytes % _hashLength == 0)
                ExpandNext();

            // copy what is left in the buffer
            int toGenerate = Size;
            int posInT = _generatedBytes % _hashLength;
            int leftInT = _hashLength - _generatedBytes % _hashLength;
            int toCopy = Math.Min(leftInT, toGenerate);

            Buffer.BlockCopy(_currentT, posInT, Output, OutOffset, toCopy);
            _generatedBytes += toCopy;
            toGenerate -= toCopy;
            OutOffset += toCopy;

            while (toGenerate > 0)
            {
                ExpandNext();
                toCopy = Math.Min(_hashLength, toGenerate);
                Buffer.BlockCopy(_currentT, 0, Output, OutOffset, toCopy);
                _generatedBytes += toCopy;
                toGenerate -= toCopy;
                OutOffset += toCopy;
            }

            return Size;
        }
        #endregion

        #region Private Methods
        private byte[] Extract(byte[] Salt, byte[] Ikm)
        {
            byte[] prk = new byte[_hashLength];

            _Hmac.Init(Ikm);

            if (Salt == null)
                _Hmac.Init(new byte[_hashLength]);
            else
                _Hmac.Init(Salt);

            _Hmac.BlockUpdate(Ikm, 0, Ikm.Length);
            _Hmac.DoFinal(prk, 0);

            return prk;
        }

        private void ExpandNext()
        {
            int n = _generatedBytes / _hashLength + 1;

            if (n >= 256)
                throw new ArgumentOutOfRangeException("HKDF cannot generate more than 255 blocks of HashLen size");
            
            // special case for T(0): T(0) is empty, so no update
            if (_generatedBytes != 0)
                _Hmac.BlockUpdate(_currentT, 0, _hashLength);
            if (_digestInfo.Length > 0)
                _Hmac.BlockUpdate(_digestInfo, 0, _digestInfo.Length);

            _Hmac.Update((byte)n);
            _Hmac.DoFinal(_currentT, 0);
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class, and dependant resources
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        void IDisposable.Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed)
            {
                if (Disposing)
                {
                    if (_Hmac != null)
                    {
                        _Hmac.Dispose();
                        _Hmac = null;
                    }
                    if (_currentT != null)
                    {
                        Array.Clear(_currentT, 0, _currentT.Length);
                        _currentT = null;
                    }

                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
