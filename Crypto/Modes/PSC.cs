using System;
using VTDev.Projects.CEX.Crypto.Ciphers;

namespace VTDev.Projects.CEX.Crypto.Modes
{
    /// <summary>
    /// Implements Parallel Segmented (Integer) Counter (PSC-CTR) mode.
    /// A Parallel processing segmented integer counter implementation.
    /// </summary>
    public class PSC : ICipherMode, IDisposable
    {
        #region Constants
        private const Int32 MIN_PARALLEL = 1024;
        private const int BLOCK_SIZE = 1024;
        #endregion

        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 16;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isParallel = false;
        private byte[] _pscVector;
        private byte[] _pscTemp;
        #endregion

        #region Properties
        /// <summary>
        /// Unit block size of internal cipher
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
            get { return "PSC"; }
        }

        /// <summary>
        /// Get/Set Automatic processor parallelization
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
        /// Minimum input size to trigger parallel processing
        /// </summary>
        public static int MinParallelSize
        {
            get { return MIN_PARALLEL; }
        }

        /// <summary>
        /// Processor count
        /// </summary>
        private int ProcessorCount { get; set; }

        /// <summary>
        /// Intitialization Vector
        /// </summary>
        public byte[] Vector
        {
            get { return _pscVector; }
            set
            {
                if (value == null)
                    throw new ArgumentOutOfRangeException("Invalid IV! IV can not be null.");
                if (value.Length != 16 && value.Length != 32)
                    throw new ArgumentOutOfRangeException("Invalid IV size! Valid size is 16 and 32 bytes.");

                int vectorSize = value.Length;
                _pscTemp = new byte[vectorSize];
                _pscVector = new byte[vectorSize];
                Buffer.BlockCopy(value, 0, _pscVector, 0, vectorSize);
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// <param name="Cipher">Underlying encryption algorithm</param>
        public PSC(IBlockCipher Cipher)
        {
            _blockCipher = Cipher;
            _blockSize = this.BlockSize;

            this.ProcessorCount = Environment.ProcessorCount;
            if (this.ProcessorCount % 2 != 0)
                this.ProcessorCount--;

            this.IsParallel = this.ProcessorCount > 1;
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
        /// Transform a block of bytes within an array.
        /// Init must be called before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int size = Input.Length - InOffset < MIN_PARALLEL ? Input.Length - InOffset : MIN_PARALLEL;

            if (Output.Length - OutOffset < size)
                throw new ArgumentOutOfRangeException("Invalid output array! Size can not be less than Input array.");

            byte[] input = new byte[size];
            byte[] output = new byte[size];

            Buffer.BlockCopy(Input, InOffset, input, 0, size);
            Transform(input, output);
            Buffer.BlockCopy(output, 0, Output, OutOffset, output.Length);
        }

        /// <summary>
        /// Transform a block of bytes.
        /// Init must be called before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            if (Output.Length < 1)
                throw new ArgumentOutOfRangeException("Invalid output array! Size can not be less than 1 byte.");
            if (Output.Length > Input.Length)
                throw new ArgumentOutOfRangeException("Invalid input array! Input array size can not be smaller than output array size.");

            int outputSize = Output.Length;

            if (!this.IsParallel || outputSize < MIN_PARALLEL)
            {
                // generate random
                byte[] random = Generate(outputSize, _pscVector);

                // output is input xor with random
                for (int i = 0; i < outputSize; i++)
                    Output[i] = (byte)(Input[i] ^ random[i]);
            }
            else
            {
                // parallel ctr processing //
                int count = this.ProcessorCount;
                int alignedSize = outputSize / _blockSize;
                int chunkSize = (alignedSize / count) * _blockSize;
                int roundSize = chunkSize * count;
                int subSize = (chunkSize / _blockSize);

                // create jagged array of 'sub counters'
                byte[][] counters = new byte[count][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, count, i =>
                {
                    // offset counter by chunk size / block size
                    counters[i] = Increase(_pscVector, subSize * i);
                    // create random with offset counter
                    byte[] random = Generate(chunkSize, counters[i]);
                    int offset = i * chunkSize;

                    // xor with input at offset
                    for (int j = 0; j < chunkSize; j++)
                        Output[j + offset] = (byte)(Input[j + offset] ^ random[j]);
                });

                // last block processing
                if (roundSize < outputSize)
                {
                    int finalSize = outputSize % roundSize;
                    byte[] random = Generate(finalSize, counters[count - 1]);

                    for (int i = 0; i < finalSize; i++)
                        Output[i + roundSize] = (byte)(Input[i + roundSize] ^ random[i]);
                }

                // copy the last counter position to class variable
                Buffer.BlockCopy(counters[count - 1], 0, _pscVector, 0, _pscVector.Length);
            }
        }

        /// <summary>
        /// Generates a block of p-rand using a counter
        /// </summary>
        /// <param name="Size">Size of return p-rand</param>
        /// <param name="Counter">The counter bytes, 16 or 32 bytes</param>
        /// <returns>Array of p-rand [byte[]]</returns>
        private byte[] Generate(Int32 Size, byte[] Counter)
        {
            // align to upper divisible of block size
            Int32 alignedSize = (Size % _blockSize == 0 ? Size : Size + _blockSize - (Size % _blockSize));
            Int32 lastBlock = alignedSize - _blockSize;
            byte[] outputBlock = new byte[_blockSize];
            byte[] outputData = new byte[Size];

            for (int i = 0; i < alignedSize; i += _blockSize)
            {
                // encrypt counter1 (aes: data, output, key)
                _blockCipher.EncryptBlock(Counter, outputBlock);

                // copy to output
                if (i != lastBlock)
                {
                    // copy transform to output
                    Buffer.BlockCopy(outputBlock, 0, outputData, i, _blockSize);
                }
                else
                {
                    // copy last block
                    int finalSize = (Size % _blockSize) == 0 ? _blockSize : (Size % _blockSize);
                    Buffer.BlockCopy(outputBlock, 0, outputData, i, finalSize);
                }

                // increment counter
                Increment(Counter);
            }

            return outputData;
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

                /// <summary>
        /// Increase a byte array by a numerical value
        /// </summary>
        /// <param name="Counter">Original byte array</param>
        /// <param name="Count">Number to increase by</param>
        /// <returns>Array with increased value [byte[]]</returns>
        private byte[] Increase(byte[] Counter, Int32 Count)
        {
            byte[] buffer = new byte[Counter.Length];

            Buffer.BlockCopy(Counter, 0, buffer, 0, Counter.Length);

            for (int i = 0; i < Count; i++)
                Increment(buffer);

            return buffer;
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

                if (_pscVector != null)
                {
                    Array.Clear(_pscVector, 0, _pscVector.Length);
                    _pscVector = null;
                }
                if (_pscTemp != null)
                {
                    Array.Clear(_pscTemp, 0, _pscTemp.Length);
                    _pscTemp = null;
                }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
