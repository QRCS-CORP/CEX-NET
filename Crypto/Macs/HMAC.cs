#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digests;
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
/// <para><description>Guiding Publications:</description>
/// HMAC: <see cref="http://tools.ietf.org/html/rfc2104">RFC 2104</see>.
/// Fips 180 SHA <see cref="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</see>.</para>
/// 
/// <para><description>Code Base Guides:</description>
/// Portions of this code based on the Bouncy Castle Java 
/// <see cref="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</para>
/// 
/// <para><description>Implementation Details:</description>
/// An implementation of a keyed hash function wrapper; Hash based Message Authentication Code (HMAC).
/// Written by John Underhill, September 24, 2014
/// contact: steppenwolfe_2000@yahoo.com</para>
/// </remarks>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Macs
{
    /// <summary>
    /// An implementation of a keyed hash function wrapper.
    /// 
    /// <example>
    /// <description>Use with an <c>IMac</c> interface:</description>
    /// <code>
    /// using (IMac mac = new HMAC(new SHA3Digest()))
    /// {
    ///     // initialize
    ///     mac.Init(Key);
    ///     // get mac
    ///     Output = mac.ComputeMac(Input);
    /// }
    /// </code>
    /// </example>
    /// </summary>
    public class HMAC : IMac, IDisposable
    {
        #region Fields
        private const byte IPAD = (byte)0x36;
        private const byte OPAD = (byte)0x5C;
        private IDigest _Digest;
        private int _digestSize;
        private int _blockLength;
        private bool _isDisposed = false;
        private byte[] _inputPad;
        private byte[] _outputPad;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return _Digest.BlockSize; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return _Digest.DigestSize; }
        }

        /// <summary>
        /// Get: Algorithm name
        /// </summary>
        public string Name
        {
            get { return _Digest.Name; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Hash">Hash function</param>
        public HMAC(IDigest Hash)
        {
            this._Digest = Hash;
            this._digestSize = Hash.DigestSize;
            this._blockLength = Hash.BlockSize;
            this._inputPad = new byte[_blockLength];
            this._outputPad = new byte[_blockLength];
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Hash">Hash function</param>
        /// <param name="IKm">HMAC Key</param>
        public HMAC(IDigest Hash, byte[] IKm)
        {
            this._Digest = Hash;
            this._digestSize = Hash.DigestSize;
            this._blockLength = Hash.BlockSize;
            this._inputPad = new byte[_blockLength];
            this._outputPad = new byte[_blockLength];

            Init(IKm);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the digest
        /// </summary>
        /// 
        /// <param name="Input">Hash input data</param>
        /// <param name="InOffset">Starting position with the Input array</param>
        /// <param name="Length">Length of data to process</param>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            _Digest.BlockUpdate(Input, InOffset, Length);
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>HMAC hash value</returns>
        public byte[] ComputeMac(byte[] Input)
        {
            byte[] hash = new byte[_Digest.DigestSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Completes processing and returns the HMAC code
        /// </summary>
        /// 
        /// <param name="Output">Output array that receives the hash code</param>
        /// <param name="OutOffset">Offset within Output array</param>
        /// 
        /// <returns>Hash size</returns>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            byte[] tmp = new byte[_digestSize];
            _Digest.DoFinal(tmp, 0);

            _Digest.BlockUpdate(_outputPad, 0, _outputPad.Length);
            _Digest.BlockUpdate(tmp, 0, tmp.Length);

            int len = _Digest.DoFinal(Output, OutOffset);

            // reinitialise the digest
            _Digest.BlockUpdate(_inputPad, 0, _inputPad.Length);

            return len;
        }

        /// <summary>
        /// Initialize the HMAC
        /// </summary>
        /// 
        /// <param name="Key">HMAC key</param>
        public void Init(byte[] Key)
        {
            _Digest.Reset();

            int keyLength = Key.Length;

            if (keyLength > _blockLength)
            {
                _Digest.BlockUpdate(Key, 0, Key.Length);
                _Digest.DoFinal(_inputPad, 0);

                keyLength = _digestSize;
            }
            else
            {
                Array.Copy(Key, 0, _inputPad, 0, keyLength);
            }

            Array.Clear(_inputPad, keyLength, _blockLength - keyLength);
            Array.Copy(_inputPad, 0, _outputPad, 0, _blockLength);

            xor(_inputPad, IPAD);
            xor(_outputPad, OPAD);

            // initialise the digest
            _Digest.BlockUpdate(_inputPad, 0, _inputPad.Length);
        }

        /// <summary>
        /// Reset and initialize the underlying digest
        /// </summary>
        public void Reset()
        {
            _Digest.Reset();
            _Digest.BlockUpdate(_inputPad, 0, _inputPad.Length);
        }

        /// <summary>
        /// Update the digest with 1 byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            _Digest.Update(Input);
        }

        #endregion

        #region Private Methods
        private static void xor(byte[] a, byte n)
        {
            for (int i = 0; i < a.Length; ++i)
                a[i] ^= n;
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
                    if (_Digest != null)
                    {
                        _Digest.Dispose();
                        _Digest = null;
                    }
                    if (_inputPad != null)
                    {
                        Array.Clear(_inputPad, 0, _inputPad.Length);
                        _inputPad = null;
                    }
                    if (_outputPad != null)
                    {
                        Array.Clear(_outputPad, 0, _outputPad.Length);
                        _outputPad = null;
                    }

                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
