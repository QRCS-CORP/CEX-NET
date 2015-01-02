#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Ciphers;
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
/// NIST: <see cref="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</see>.
/// 
/// <para><description>Code Base Guides:</description>
/// Portions of this code based on the Bouncy Castle Java 
/// <see cref="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</para>
/// 
/// <para><description>Implementation Details:</description>
/// An implementation of a Output FeedBack Mode (OFB).
/// Written by John Underhill, January 2, 2015
/// contact: steppenwolfe_2000@yahoo.com</para>
/// </remarks>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Modes
{
    /// <summary>
    /// Implements a Output FeedBack Mode (OFB) mode.
    /// Note: -Not Tested-
    /// </summary> 
    public class OFB : ICipherMode, IDisposable
    {
        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 8;
        private byte[] _ofbIv;
        private byte[] _ofbBuffer;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Unit block size of internal cipher.
        /// </summary>
        public int BlockSize
        {
            get { return _blockCipher.BlockSize; }
        }

        /// <summary>
        /// Get: Underlying Cipher
        /// </summary>
        public IBlockCipher Cipher
        {
            get { return _blockCipher; }
            private set { _blockCipher = value; }
        }

        /// <summary>
        /// Get/Set: Feedback size
        /// </summary>
        public int FeedBackSize
        {
            get { return _feedbackSize; }
            set { _feedbackSize = value; }
        }

        /// <summary>
        /// Get: Used as encryptor, false for decryption. 
        /// </summary>
        public bool IsEncryption
        {
            get { return _isEncryption; }
            private set { _isEncryption = value; }
        }

        /// <summary>
        /// Get: Uses parallel processing. 
        /// </summary>
        public bool IsParallel { get; set; }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return "CFB"; }
        }

        /// <summary>
        /// Get/Set: Intitialization Vector
        /// </summary>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if a null iv is used.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid iv size is used.</exception>
        public byte[] Vector
        {
            get { return _ofbIv; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("Invalid IV! IV can not be null.");
                if (value.Length != this.BlockSize)
                    throw new ArgumentOutOfRangeException("Invalid IV size! Valid size must be equal to cipher blocksize.");

                int vectorSize = value.Length;
                _ofbIv = new byte[vectorSize];
                _ofbBuffer = new byte[vectorSize];

                Buffer.BlockCopy(value, 0, _ofbIv, 0, vectorSize);
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        /// <param name="BlockSize">Block size</param>
        public OFB(IBlockCipher Cipher, int BlockSize = 8)
        {
            _blockCipher = Cipher;
            _blockSize = this.BlockSize;
        }
        #endregion

        #region Methods
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Encryption">Cipher is used for encryption, false to decrypt</param>
        /// <param name="KeyParam">KeyParam containing key and vector</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null key or iv is used.</exception>
        public void Init(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new ArgumentNullException("Key can not be null!");
            if (KeyParam.IV == null)
                throw new ArgumentNullException("IV can not be null!");

            _blockCipher.Init(true, KeyParam);
            this.Vector = KeyParam.IV;
            this.IsEncryption = Encryption;
        }

        /// <summary>
        /// Transform a block of bytes.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            ProcessBlock(Input, 0, Output, 0);
        }

        /// <summary>
        /// Transform a block of bytes within an array.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            ProcessBlock(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Private Methods
        private void ProcessBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            _blockCipher.Transform(_ofbIv, 0, _ofbBuffer, 0);

            // XOR the _ofbIv with the plaintext producing the cipher text (and the next Input block).
            for (int i = 0; i < _blockSize; i++)
                Output[OutOffset + i] = (byte)(_ofbBuffer[i] ^ Input[InOffset + i]);

            // change over the Input block.
            Buffer.BlockCopy(_ofbIv, _blockSize, _ofbIv, 0, _ofbIv.Length - _blockSize);
            Buffer.BlockCopy(_ofbBuffer, 0, _ofbIv, _ofbIv.Length - _blockSize, _blockSize);
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
            if (!_isDisposed && Disposing)
            {
                if (_blockCipher != null)
                    _blockCipher.Dispose();

                if (_ofbIv != null)
                {
                    Array.Clear(_ofbIv, 0, _ofbIv.Length);
                    _ofbIv = null;
                }
                if (_ofbBuffer != null)
                {
                    Array.Clear(_ofbBuffer, 0, _ofbBuffer.Length);
                    _ofbBuffer = null;
                }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
