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
/// An implementation of a Cipher Block Chaining mode (CBC).
/// Written by John Underhill, September 24, 2014
/// contact: steppenwolfe_2000@yahoo.com</para>
/// </remarks>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Modes
{
    /// <summary>
    /// Implements Cipher Block Chaining (CBC) mode.
    /// <para>Uses (default) parallel processing, or linear processing.</para>
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode mode = new CBC(new RDX()))
    /// {
    ///     // initialize for encryption
    ///     mode.Init(true, new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     mode.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// </summary> 
    public class CBC : ICipherMode, IDisposable
    {
        #region Constants
        private const Int32 MIN_PARALLEL = 1024;
        private const Int32 MAX_PARALLEL = 1024;
        #endregion

        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 16;
        private byte[] _cbcIv;
        private byte[] _cbcNextIv;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isParallel = false;
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
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return _isParallel; }
            set
            {
                if (this.ProcessorCount == 1)
                    this.IsParallel = false;
                else
                    _isParallel = value;
            }
        }

        /// <summary>
        /// Get: Maximum input size with parallel processing
        /// </summary>
        public static int MaxParallelSize
        {
            get { return MAX_PARALLEL; }
        }

        /// <summary>
        /// Get: Minimum input size to trigger parallel processing
        /// </summary>
        public static int MinParallelSize
        {
            get { return MIN_PARALLEL; }
        }

        /// <remarks>
        /// Processor count
        /// </remarks>
        private int ProcessorCount { get; set; }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return "CBC"; }
        }

        /// <summary>
        /// Get/Set: Intitialization Vector
        /// </summary>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if a null iv is used.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid iv size is used.</exception>
        public byte[] Vector
        {
            get { return _cbcIv; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("Invalid IV! IV can not be null.");
                if (value.Length != this.BlockSize)
                    throw new ArgumentOutOfRangeException("Invalid IV size! Valid size must be equal to cipher blocksize.");

                int vectorSize = value.Length;
                _cbcIv = new byte[vectorSize];
                _cbcNextIv = new byte[vectorSize];

                Buffer.BlockCopy(value, 0, _cbcIv, 0, vectorSize);
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        public CBC(IBlockCipher Cipher)
        {
            _blockCipher = Cipher;
            _blockSize = this.BlockSize;

            this.ProcessorCount = Environment.ProcessorCount;
            if (this.ProcessorCount % 2 != 0)
                this.ProcessorCount--;

            this.IsParallel = this.ProcessorCount > 1;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="Encryption">Cipher is used for encryption, false to decrypt</param>
        /// <param name="KeyParam">KeyParam containing key and vector</param>
        public void Init(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new ArgumentNullException("Key can not be null!");
            if (KeyParam.IV == null)
                throw new ArgumentNullException("IV can not be null!");

            _blockCipher.Init(Encryption, KeyParam);
            _blockSize = this.BlockSize;
            this.Vector = KeyParam.IV;
            this.IsEncryption = Encryption;
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
            if (this.IsParallel && Output.Length >= MIN_PARALLEL)
                ParallelDecrypt(Input, Output);
            else
                ProcessDecrypt(Input, Output);
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
            if (this.IsParallel && Output.Length - OutOffset >= MIN_PARALLEL)
                ParallelDecrypt(Input, InOffset, Output, OutOffset);
            else
                ProcessDecrypt(Input, InOffset, Output, OutOffset);
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
            // xor iv and input
            for (int i = 0; i < Input.Length; i++)
                _cbcIv[i] ^= Input[i];

            // encrypt iv
            _blockCipher.EncryptBlock(_cbcIv, Output);
            // copy output to iv
            Buffer.BlockCopy(Output, 0, _cbcIv, 0, _blockSize);
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
            // xor iv and input
            for (int i = 0; i < _blockSize; i++)
                _cbcIv[i] ^= Input[InOffset + i];

            // encrypt iv
            _blockCipher.EncryptBlock(_cbcIv, 0, Output, OutOffset);
            // copy output to iv
            Buffer.BlockCopy(Output, OutOffset, _cbcIv, 0, _blockSize);
        }

        /// <summary>
        /// Transform a block of bytes.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            if (this.IsEncryption)
            {
                EncryptBlock(Input, Output);
            }
            else
            {
                if (this.IsParallel && Output.Length >= MIN_PARALLEL)
                    ParallelDecrypt(Input, Output);
                else
                    ProcessDecrypt(Input, Output);
            }
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
            {
                EncryptBlock(Input, InOffset, Output, OutOffset);
            }
            else
            {
                if (this.IsParallel && Output.Length - OutOffset >= MIN_PARALLEL)
                    ParallelDecrypt(Input, InOffset, Output, OutOffset);
                else
                    ProcessDecrypt(Input, InOffset, Output, OutOffset);
            }
        }
        #endregion

        #region Parallel Decrypt
        private void ParallelDecrypt(byte[] Input, byte[] Output)
        {
            // parallel CBC decryption //
            int prcCount = this.ProcessorCount;
            int cnkSize = Output.Length / prcCount;
            int blkCount = (cnkSize / _blockSize);
            byte[][] vectors = new byte[prcCount][];

            for (int i = 0; i < prcCount; i++)
            {
                vectors[i] = new byte[_blockSize];
                // get the first iv
                if (i != 0)
                    Buffer.BlockCopy(Input, (i * cnkSize) - _blockSize, vectors[i], 0, _blockSize);
                else
                    Buffer.BlockCopy(_cbcIv, 0, vectors[i], 0, _blockSize);
            }

            System.Threading.Tasks.Parallel.For(0, prcCount, i =>
            {
                for (int j = 0; j < blkCount; j++)
                    ProcessDecrypt(Input, (i * cnkSize) + (j * _blockSize), Output, (i * cnkSize) + (j * _blockSize), vectors[i]);
            });

            // copy the last vector to class variable
            Buffer.BlockCopy(vectors[prcCount - 1], 0, _cbcIv, 0, _cbcIv.Length);
        }

        private void ParallelDecrypt(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            // parallel CBC decryption //
            int prcCount = this.ProcessorCount;
            int cnkSize = Output.Length / prcCount;
            int blkCount = (cnkSize / _blockSize);
            byte[][] vectors = new byte[prcCount][];

            for (int i = 0; i < prcCount; i++)
            {
                vectors[i] = new byte[_blockSize];
                // get the first iv
                if (i != 0)
                    Buffer.BlockCopy(Input, (InOffset + (i * cnkSize)) - _blockSize, vectors[i], 0, _blockSize);
                else
                    Buffer.BlockCopy(_cbcIv, 0, vectors[i], 0, _blockSize);
            }

            System.Threading.Tasks.Parallel.For(0, prcCount, i =>
            {
                for (int j = 0; j < blkCount; j++)
                    ProcessDecrypt(Input, InOffset + (i * cnkSize) + (j * _blockSize), Output, OutOffset + (i * cnkSize) + (j * _blockSize), vectors[i]);
            });

            // copy the last vector to class variable
            Buffer.BlockCopy(vectors[prcCount - 1], 0, _cbcIv, 0, _cbcIv.Length);
        }
        #endregion

        #region Private Methods
        private void ProcessDecrypt(byte[] Input, byte[] Output)
        {
            // copy input to temp iv
            Buffer.BlockCopy(Input, 0, _cbcNextIv, 0, Input.Length);
            // decrypt input
            _blockCipher.DecryptBlock(Input, Output);
            // xor output and iv
            for (int i = 0; i < _cbcIv.Length; i++)
                Output[i] ^= _cbcIv[i];

            // copy forward iv
            Buffer.BlockCopy(_cbcNextIv, 0, _cbcIv, 0, _cbcIv.Length);
        }

        private void ProcessDecrypt(byte[] Input, byte[] Output, byte[] Vector)
        {
            byte[] nextIv = new byte[Vector.Length];

            // copy input to temp iv
            Buffer.BlockCopy(Input, 0, nextIv, 0, _blockSize);
            // decrypt input
            _blockCipher.DecryptBlock(Input, Output);
            // xor output and iv
            for (int i = 0; i < Vector.Length; i++)
                Output[i] ^= Vector[i];

            // copy forward iv
            Buffer.BlockCopy(nextIv, 0, Vector, 0, _blockSize);
        }

        private void ProcessDecrypt(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            // copy input to temp iv
            Buffer.BlockCopy(Input, InOffset, _cbcNextIv, 0, _blockSize);
            // decrypt input
            _blockCipher.DecryptBlock(Input, InOffset, Output, OutOffset);
            // xor output and iv
            for (int i = 0; i < _cbcIv.Length; i++)
                Output[OutOffset + i] ^= _cbcIv[i];

            // copy forward iv
            Buffer.BlockCopy(_cbcNextIv, 0, _cbcIv, 0, _cbcIv.Length);
        }

        private void ProcessDecrypt(byte[] Input, int InOffset, byte[] Output, int OutOffset, byte[] Vector)
        {
            byte[] nextIv = new byte[Vector.Length];

            // copy input to temp iv
            Buffer.BlockCopy(Input, InOffset, nextIv, 0, _blockSize);
            // decrypt input
            _blockCipher.DecryptBlock(Input, InOffset, Output, OutOffset);
            // xor output and iv
            for (int i = 0; i < Vector.Length; i++)
                Output[OutOffset + i] ^= Vector[i];

            // copy forward iv
            Buffer.BlockCopy(nextIv, 0, Vector, 0, _blockSize);
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

                if (_cbcIv != null)
                {
                    Array.Clear(_cbcIv, 0, _cbcIv.Length);
                    _cbcIv = null;
                }
                if (_cbcNextIv != null)
                {
                    Array.Clear(_cbcNextIv, 0, _cbcNextIv.Length);
                    _cbcNextIv = null;
                }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
