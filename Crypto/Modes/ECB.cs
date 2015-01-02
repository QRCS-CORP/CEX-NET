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
/// An implementation of an Electronic CodeBook Mode (ECB).
/// Written by John Underhill, September 24, 2014
/// contact: steppenwolfe_2000@yahoo.com</para>
/// </remarks>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Modes
{
    /// <summary>
    /// ECB mode (not recommended)
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode mode = new ECB(new RDX()))
    /// {
    ///     // initialize for encryption
    ///     mode.Init(true, new KeyParams(Key));
    ///     // encrypt a block
    ///     mode.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// </summary> 
    public class ECB : ICipherMode, IDisposable
    {
        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 16;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private byte[] _ecbVector;
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
            get { return "ECB"; }
        }

        /// <summary>
        /// Get/Set: Intitialization Vector
        /// </summary>
        public byte[] Vector
        {
            get { return _ecbVector; }
            set { _ecbVector = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        public ECB(IBlockCipher Cipher)
        {
            _blockCipher = Cipher;
            _blockSize = this.BlockSize;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Encryption">Cipher is used for encryption, false to decrypt</param>
        /// <param name="KeyParam">KeyParam containing key and vector</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if key is null.</exception>
        public void Init(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new ArgumentNullException("Key can not be null!");

            _blockCipher.Init(Encryption, KeyParam);
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
        /// 
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
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        public void DecryptBlock(byte[] Input, byte[] Output)
        {
            _blockCipher.DecryptBlock(Input, Output);
        }

        /// <summary>
        /// Decrypt a block of bytes within an array.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        public void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            _blockCipher.DecryptBlock(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Encrypt a block of bytes.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        public void EncryptBlock(byte[] Input, byte[] Output)
        {
            _blockCipher.EncryptBlock(Input, Output);
        }

        /// <summary>
        /// Encrypt a block of bytes within an array.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        public void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            _blockCipher.EncryptBlock(Input, InOffset, Output, OutOffset);
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

                if (_ecbVector != null)
                {
                    Array.Clear(_ecbVector, 0, _ecbVector.Length);
                    _ecbVector = null;
                }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
