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
/// An implementation of a Cipher FeedBack Mode (CFB).
/// Written by John Underhill, September 24, 2014
/// contact: steppenwolfe_2000@yahoo.com</para>
/// </remarks>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Modes
{
    /// <summary>
    /// Implements a Cipher FeedBack Mode (CBC) mode.
    /// Note: -Not Tested-
    /// </summary> 
    public class CFB : ICipherMode, IDisposable
    {
        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 16;
        private byte[] _cfbIv;
        private byte[] _cfbBuffer;
        private int _feedbackSize = 8;
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
        public bool IsParallel { get; set;  }

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
            get { return _cfbIv; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("Invalid IV! IV can not be null.");
                if (value.Length != this.BlockSize)
                    throw new ArgumentOutOfRangeException("Invalid IV size! Valid size must be equal to cipher blocksize.");

                int vectorSize = value.Length;
                _cfbIv = new byte[vectorSize];
                _cfbBuffer = new byte[vectorSize];

                Buffer.BlockCopy(value, 0, _cfbIv, 0, vectorSize);
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        public CFB(IBlockCipher Cipher)
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
            if (this.IsEncryption)
                EncryptBlock(Input, Output);
            else
                DecryptBlock(Input, Output);
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
            if (this.IsEncryption)
                EncryptBlock(Input, InOffset, Output, OutOffset);
            else
                DecryptBlock(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Decrypt a single block of bytes.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        public void DecryptBlock(byte[] Input, byte[] Output)
        {
            // decrypt input
            _blockCipher.EncryptBlock(_cfbIv, _cfbBuffer);

            // copy forward iv
            Buffer.BlockCopy(_cfbIv, _feedbackSize, _cfbIv, 0, _cfbIv.Length - _feedbackSize);
            Buffer.BlockCopy(Input, 0, _cfbIv, _cfbIv.Length - _feedbackSize, _feedbackSize);

            // xor output and iv
            for (int i = 0; i < _feedbackSize; i++)
                Output[i] = (byte)(_cfbBuffer[i] ^ Input[i]);
        }

        /// <summary>
        /// Decrypt a block of bytes within an array.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        public void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            // decrypt input
            _blockCipher.EncryptBlock(_cfbIv, _cfbBuffer);

            // copy forward iv
            Buffer.BlockCopy(_cfbIv, _feedbackSize, _cfbIv, 0, _cfbIv.Length - _feedbackSize);
            Buffer.BlockCopy(Input, InOffset, _cfbIv, _cfbIv.Length - _feedbackSize, _feedbackSize);

            // xor output and iv
            for (int i = 0; i < _feedbackSize; i++)
                Output[i + OutOffset] = (byte)(_cfbBuffer[i] ^ Input[i + InOffset]);
        }

        /// <summary>
        /// Encrypt a block of bytes.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        public void EncryptBlock(byte[] Input, byte[] Output)
        {
            // encrypt iv
            _blockCipher.EncryptBlock(_cfbIv, _cfbBuffer);

            for (int i = 0; i < _feedbackSize; i++)
                Output[i] = (byte)(_cfbBuffer[i] ^ Input[i]);

            // copy output to iv
            Buffer.BlockCopy(_cfbIv, _feedbackSize, _cfbIv, 0, _cfbIv.Length - _feedbackSize);
            Buffer.BlockCopy(Output, 0, _cfbIv, _cfbIv.Length - _feedbackSize, _feedbackSize);
        }

        /// <summary>
        /// Encrypt a block of bytes within an array.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        public void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            // encrypt iv
            _blockCipher.EncryptBlock(_cfbIv, _cfbBuffer);

            for (int i = 0; i < _feedbackSize; i++)
                Output[OutOffset + i] = (byte)(_cfbBuffer[i] ^ Input[InOffset + i]);

            // copy output to iv
            Buffer.BlockCopy(_cfbIv, _feedbackSize, _cfbIv, 0, _cfbIv.Length - _feedbackSize);
            Buffer.BlockCopy(Output, OutOffset, _cfbIv, _cfbIv.Length - _feedbackSize, _feedbackSize);
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

                if (_cfbIv != null)
                {
                    Array.Clear(_cfbIv, 0, _cfbIv.Length);
                    _cfbIv = null;
                }
                if (_cfbBuffer != null)
                {
                    Array.Clear(_cfbBuffer, 0, _cfbBuffer.Length);
                    _cfbBuffer = null;
                }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
