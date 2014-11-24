using System;
using VTDev.Projects.CEX.Crypto.Digests;
using VTDev.Projects.CEX.Crypto.Macs;

/// C# implementation based in part on Bouncy Castles Java version HKDFBytesGenerator:
/// http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.48/org/bouncycastle/crypto/generators/HKDFBytesGenerator.java
/// RFC 5869: http://tools.ietf.org/html/rfc5869
/// White Paper: http://eprint.iacr.org/2010/264.pdf

namespace VTDev.Projects.CEX.Crypto.Generators
{
    public class HKDF : IDisposable
    {
        #region Fields
        private byte[] _currentT;
        private byte[] _digestInfo = new byte[0];
        private int _hashLength;
        private IMac _Hmac;
        private bool _isDisposed = false;
        private int _generatedBytes;
        #endregion

        #region Public Methods
        /// <summary>
        /// Creates a HKDF Bytes Generator based on the given hash function
        /// </summary>
        /// <param name="Digest">The digest used</param>
        public HKDF(IDigest Digest)
        {
            this._Hmac = new HMAC(Digest);
            this._hashLength = Digest.DigestSize;
        }

        /// <summary>
        /// Creates a HKDF Bytes Generator based on the given HMAC function
        /// </summary>
        /// <param name="Hmac">The HMAC digest used</param>
        public HKDF(IMac Hmac)
        {
            this._Hmac = Hmac;
            this._hashLength = Hmac.DigestSize;
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// <param name="Salt">HMAC salt</param>
        public void Init(byte[] Salt)
        {
            _Hmac.Init(Salt);
            _generatedBytes = 0;
            _currentT = new byte[_hashLength];
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// <param name="Salt">HMAC salt</param>
        public void Init(byte[] Salt, byte[] Ikm)
        {
            if (Ikm == null)
                throw new ArgumentException("Ikm can not be null!");

            _Hmac.Init(Extract(Salt, Ikm));
            _generatedBytes = 0;
            _currentT = new byte[_hashLength];
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">HMAC key</param>
        /// <param name="Ikm">Nonce value</param>
        public void Init(byte[] Salt, byte[] Ikm, byte[] Info)
        {
            if (Ikm == null)
                throw new ArgumentException("Ikm can not be null!");

            _Hmac.Init(Extract(Salt, Ikm));

            if (Info != null)
                _digestInfo = Info;

            _generatedBytes = 0;
            _currentT = new byte[_hashLength];
        }

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// <param name="Output">Output array</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
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
        /// Dispose of this class, releasing the resources
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
