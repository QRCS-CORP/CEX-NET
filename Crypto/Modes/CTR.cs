using System;
using VTDev.Projects.CEX.Crypto.Ciphers;

namespace VTDev.Projects.CEX.Crypto.Modes
{
    /// <summary>
    /// Implements Segmented Integer Counter (SIC-CTR) mode
    /// </summary>
    public class CTR : ICipherMode, IDisposable
    {
        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 16;
        private byte[] _ctrVector;
        private byte[] _ctrTemp;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        #endregion

        #region Properties
        /// <summary>
        /// Unit block size of internal cipher.
        /// </summary>
        public int BlockSize
        {
            get { return _blockCipher.BlockSize; }
        }

        /// <summary>
        /// Underlying Cipher
        /// </summary>
        public IBlockCipher Cipher
        {
            get { return _blockCipher; }
            set { _blockCipher = value; }
        }

        /// <summary>
        /// Used as encryptor, false for decryption. 
        /// </summary>
        public bool IsEncryption
        {
            get { return _isEncryption; }
            private set { _isEncryption = value; }
        }

        /// <summary>
        /// Cipher name
        /// </summary>
        public string Name
        {
            get { return "CTR"; }
        }

        /// <summary>
        /// Intitialization Vector
        /// </summary>
        public byte[] Vector
        {
            get { return _ctrVector; }
            set 
            {
                if (value == null)
                    throw new ArgumentOutOfRangeException("Invalid IV! IV can not be null.");
                if (value.Length != this.BlockSize)
                    throw new ArgumentOutOfRangeException("Invalid IV size! Valid size must be equal to cipher blocksize.");

                int vectorSize = value.Length;
                _ctrTemp = new byte[vectorSize];
                _ctrVector = new byte[vectorSize];
                Buffer.BlockCopy(value, 0, _ctrVector, 0, vectorSize);
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// <param name="Cipher">Underlying encryption algorithm</param>
        public CTR(IBlockCipher Cipher)
        {
            _blockCipher = Cipher;
            _blockSize = this.BlockSize;
        }
        #endregion

        #region Methods
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// <param name="Encryptor">Cipher is used for encryption, false to decrypt</param>
        /// <param name="KeyParam">KeyParam containing key and vector</param>
        public void Init(bool Encryptor, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new ArgumentNullException("Key can not be null!");
            if (KeyParam.IV == null)
                throw new ArgumentNullException("IV can not be null!");

            _blockCipher.Init(true, KeyParam);
            this.Vector = KeyParam.IV;
            this.IsEncryption = Encryptor;
        }

        /// <summary>
        /// Transform a block of bytes.
        /// Init must be called before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            ProcessBlock(Input, Output);
        }

        /// <summary>
        /// Transform a block of bytes within an array.
        /// Init must be called before this method can be used.
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
        /// <summary>
        /// Process a block of bytes.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        private void ProcessBlock(byte[] Input, byte[] Output)
        {
            // encrypt the counter
            _blockCipher.EncryptBlock(_ctrVector, _ctrTemp);

			// output = ciphertext xor input
            for (int i = 0; i < _blockSize; i++) 
				Output[i] = (byte)(_ctrTemp[i] ^ Input[i]);

            // increment the counter with carry
            Increment(_ctrVector);
        }

        /// <summary>
        /// Encrypt a block of bytes within an array.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        private void ProcessBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            // encrypt the counter
            _blockCipher.EncryptBlock(_ctrVector, _ctrTemp);

            // output = ciphertext xor input
            for (int i = 0; i < _blockSize; i++)
                Output[OutOffset + i] = (byte)(_ctrTemp[i] ^ Input[InOffset + i]);

            // increment the counter with carry
            Increment(_ctrVector);
        }

        /// <summary>
        /// Incremental counter with carry
        /// </summary>
        /// <param name="Counter">Counter</param>
        private void Increment(byte[] Counter)
        {
            int carry = 1;

            // increment by one bit
            for (int i = 1; i <= Counter.Length; i++)
            {
                int res = (Counter[Counter.Length - i] & 0xff) + carry;
                carry = (res > 0xff) ? 1 : 0;
                Counter[Counter.Length - i] = (byte)res;
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class and the underlying cipher
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

                if (_ctrVector != null)
                {
                    Array.Clear(_ctrVector, 0, _ctrVector.Length);
                    _ctrVector = null;
                }
                if (_ctrTemp != null)
                {
                    Array.Clear(_ctrTemp, 0, _ctrTemp.Length);
                    _ctrTemp = null;
                }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
