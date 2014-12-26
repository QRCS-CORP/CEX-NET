using System;
using VTDev.Libraries.CEXEngine.Crypto.Digests;

/// Adapted from the Bouncy Castle HMAC class:
/// http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.48/org/bouncycastle/crypto/macs/HMac.java#HMac
/// H(K XOR opad, H(K XOR ipad, text))

namespace VTDev.Libraries.CEXEngine.Crypto.Macs
{
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
        /// The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return _Digest.BlockSize; }
        }

        /// <summary>
        /// Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return _Digest.DigestSize; }
        }

        /// <summary>
        /// Algorithm name
        /// </summary>
        public string Name
        {
            get { return _Digest.Name; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Class constructor
        /// </summary>
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
        /// 
        /// </summary>
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
        /// <param name="Input">Input data [bytes]</param>
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
        /// <param name="Output">Output array that receives the hash code</param>
        /// <param name="OutOffset">Offset within Output array</param>
        /// <returns></returns>
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
