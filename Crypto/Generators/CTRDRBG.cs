using System;
using VTDev.Libraries.CEXEngine.Crypto.Ciphers;

namespace VTDev.Libraries.CEXEngine.Crypto.Generators
{
    public class CTRDRBG : IGenerator, IDisposable
    {
        #region Constants
        private const int BLOCK_SIZE = 16;
        private const int COUNTER_SIZE = 16;
        private const Int32 MAX_PARALLEL = 1024000;
        private const Int32 MIN_PARALLEL = 1024;
        #endregion

        #region Fields
        private int _blockSize = BLOCK_SIZE;
        private IBlockCipher Cipher;
        private byte[] _ctrVector;
        private bool _isDisposed = false;
        private bool _isParallel = false;
        private int _userKeySize = 32;
        #endregion

        #region Constructor
        /// <summary>
        /// Creates a CTR Bytes Generator using a block cipher
        /// </summary>
        /// <param name="Digest">The block cipher</param>
        public CTRDRBG(IBlockCipher Cipher)
        {
            this.Cipher = Cipher;
            _userKeySize = GetKeySize() + COUNTER_SIZE;
            _blockSize = this.Cipher.BlockSize;

            this.ProcessorCount = Environment.ProcessorCount;
            if (this.ProcessorCount % 2 != 0)
                this.ProcessorCount--;

            this.IsParallel = this.ProcessorCount > 1;
        }
        #endregion

        #region Properties
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
        /// Get: Legal key size for selected cipher
        /// </summary>
        public int KeySize
        {
            get { return _userKeySize; }
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

        /// <summary>
        /// Processor count
        /// </summary>
        private int ProcessorCount { get; set; }

        /// <summary>
        /// Get: Algorithm Name
        /// </summary>
        public string Name
        {
            get { return "CTRDRBG"; }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the algorithm
        /// </summary>
        /// <param name="Salt">Salt value</param>
        public void Init(byte[] Salt)
        {
            if (Salt.Length < _userKeySize)
                throw (new ArgumentOutOfRangeException("Minimum key size has not been added. Size must be at least " + _userKeySize + " bytes!"));

            _ctrVector = new byte[_blockSize];
            Buffer.BlockCopy(Salt, 0, _ctrVector, 0, _blockSize);
            int keyLen = Salt.Length - _blockSize;
            byte[] key = new byte[keyLen];
            Buffer.BlockCopy(Salt, _blockSize, key, 0, keyLen);

            this.Cipher.Init(true, new KeyParams(key));
        }

        /// <summary>
        /// Initialize the algorithm
        /// </summary>
        /// <param name="Salt">Salt value</param>
        /// <param name="Info">Nonce value</param>
        public void Init(byte[] Salt, byte[] Ikm)
        {
            byte[] seed = new byte[Salt.Length + Ikm.Length];

            Buffer.BlockCopy(Salt, 0, seed, 0, Salt.Length);
            Buffer.BlockCopy(Ikm, 0, seed, Salt.Length, Ikm.Length);

            Init(seed);
        }

        /// <summary>
        /// Initialize the algorithm
        /// </summary>
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// <param name="Info">Nonce value</param>
        public void Init(byte[] Salt, byte[] Ikm, byte[] Info)
        {
            byte[] seed = new byte[Salt.Length + Ikm.Length + Info.Length];

            Buffer.BlockCopy(Salt, 0, seed, 0, Salt.Length);
            Buffer.BlockCopy(Ikm, 0, seed, Salt.Length, Ikm.Length);
            Buffer.BlockCopy(Info, 0, seed, Ikm.Length + Salt.Length, Info.Length);

            Init(seed);
        }

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// <param name="Output">Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// <returns>Number of bytes generated</returns>
        public int Generate(int Size, byte[] Output)
        {
            ParallelTransform(Output, 0);

            return Size;
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
            ParallelTransform(Output, OutOffset);

            return Size;
        }
        #endregion

        #region Random Generator
        private void ParallelTransform(byte[] Output, int OutOffset)
        {
            if (!this.IsParallel || Output.Length < MIN_PARALLEL)
            {
                // generate random
                byte[] prand = Transform(Output.Length, _ctrVector);
                // copy to output array
                Buffer.BlockCopy(prand, 0, Output, OutOffset, prand.Length);
            }
            else
            {
                // parallel CTR processing //
                int prcCount = this.ProcessorCount;
                int algSize = Output.Length / _blockSize;
                int cnkSize = (algSize / prcCount) * _blockSize;
                int rndSize = cnkSize * prcCount;
                int subSize = (cnkSize / _blockSize);

                // create jagged array of 'sub counters'
                byte[][] counters = new byte[prcCount][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, prcCount, i =>
                {
                    // offset counter by chunk size / block size
                    counters[i] = Increase(_ctrVector, subSize * i);
                    // create random with offset counter
                    byte[] prand = Transform(cnkSize, counters[i]);
                    // copy to output array
                    Buffer.BlockCopy(prand, 0, Output, OutOffset + (i * cnkSize), cnkSize);
                });

                // last block processing
                if (rndSize < Output.Length)
                {
                    int finalSize = Output.Length % rndSize;
                    byte[] prand = Transform(finalSize, counters[prcCount - 1]);

                    // copy to output array
                    Buffer.BlockCopy(prand, 0, Output, OutOffset + rndSize, finalSize);
                }

                // copy the last counter position to class variable
                Buffer.BlockCopy(counters[prcCount - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }

        private byte[] Transform(Int32 Size, byte[] Counter)
        {
            // align to upper divisible of block size
            Int32 alignedSize = (Size % _blockSize == 0 ? Size : Size + _blockSize - (Size % _blockSize));
            Int32 lastBlock = alignedSize - _blockSize;
            byte[] prandBlock = new byte[_blockSize];
            byte[] outputData = new byte[Size];

            for (int i = 0; i < alignedSize; i += _blockSize)
            {
                // encrypt counter
                this.Cipher.EncryptBlock(Counter, prandBlock);

                // copy to output
                if (i != lastBlock)
                {
                    // copy transform to output
                    Buffer.BlockCopy(prandBlock, 0, outputData, i, _blockSize);
                }
                else
                {
                    // copy last block
                    int finalSize = (Size % _blockSize) == 0 ? _blockSize : (Size % _blockSize);
                    Buffer.BlockCopy(prandBlock, 0, outputData, i, finalSize);
                }

                // increment counters
                Increment(Counter);
            }

            return outputData;
        }

        private void Increment(byte[] Counter)
        {
            int i = Counter.Length;
            while (--i >= 0 && ++Counter[i] == 0) { }
        }

        private byte[] Increase(byte[] Counter, int Size)
        {
            int carry = 0;
            byte[] buffer = new byte[Counter.Length];
            int offset = buffer.Length - 1;
            byte[] cnt = BitConverter.GetBytes(Size);
            byte osrc, odst, ndst;

            Buffer.BlockCopy(Counter, 0, buffer, 0, Counter.Length);

            for (int i = offset; i > 0; i--)
            {
                odst = buffer[i];
                osrc = offset - i < cnt.Length ? cnt[offset - i] : (byte)0;
                ndst = (byte)(odst + osrc + carry);
                carry = ndst < odst ? 1 : 0;
                buffer[i] = ndst;
            }

            return buffer;
        }
        #endregion

        #region Helpers
        private int GetKeySize()
        {
            switch (Cipher.Name)
            {
                case "RHX":
                case "RSM":
                case "SHX":
                case "THX":
                case "TSM":
                    return 320;
                default:
                    return 32;
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
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
                if (this.Cipher != null)
                {
                    this.Cipher.Dispose();
                    this.Cipher = null;
                }
                if (_ctrVector != null)
                {
                    Array.Clear(_ctrVector, 0, _ctrVector.Length);
                    _ctrVector = null;
                }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
