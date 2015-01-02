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
/// An implementation of an segmented Counter Mode (CTR).
/// Written by John Underhill, September 24, 2014
/// contact: steppenwolfe_2000@yahoo.com</para>
/// </remarks>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Modes
{
    /// <summary>
    /// Implements a Parallel Segmented Counter (CTR) mode.
    /// <para>Uses (default) parallel processing, or linear processing.</para>
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode mode = new CTR(new RDX()))
    /// {
    ///     // initialize for encryption
    ///     mode.Init(true, new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     mode.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// </summary> 
    public class CTR : ICipherMode, IDisposable
    {
        #region Constants
        private const Int32 MAX_PARALLEL = 1024000;
        private const Int32 MIN_PARALLEL = 1024;
        private const Int32 BLOCK_SIZE = 1024;
        #endregion

        #region Fields
        private IBlockCipher _blockCipher;
        private int _blockSize = 16;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isParallel = false;
        private byte[] _ctrVector;
        private byte[] _ctrTemp;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Unit block size of internal cipher
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
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return "CTR"; }
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
        /// Get: Processor count
        /// </remarks>
        private int ProcessorCount { get; set; }

        /// <summary>
        /// Get/Set: Intitialization Vector
        /// </summary>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if a null iv is used.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid iv size is used.</exception>
        public byte[] Vector
        {
            get { return _ctrVector; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("Invalid IV! IV can not be null.");
                if (value.Length != 16 && value.Length != 32)
                    throw new ArgumentOutOfRangeException("Invalid IV size! Valid size is 16 and 32 bytes.");

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
        /// 
        /// <param name="Cipher">Underlying encryption algorithm</param>
        public CTR(IBlockCipher Cipher)
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
            if (this.IsParallel && Output.Length >= MIN_PARALLEL)
                ParallelTransform(Input, Output);
            else
                ProcessBlock(Input, Output);
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
            if (this.IsParallel && Output.Length - OutOffset >= MIN_PARALLEL)
            {
                int size = Output.Length - OutOffset < MIN_PARALLEL ? Output.Length - OutOffset : MIN_PARALLEL;
                byte[] input = new byte[size];
                byte[] output = new byte[size];

                Buffer.BlockCopy(Input, InOffset, input, 0, size);
                ParallelTransform(input, output);
                Buffer.BlockCopy(output, 0, Output, OutOffset, output.Length);
            }
            else
                ProcessBlock(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Parallel Methods
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

        private void ParallelTransform(byte[] Input, byte[] Output)
        {
            if (!this.IsParallel || Output.Length < MIN_PARALLEL)
            {
                // generate random
                byte[] random = Generate(Output.Length, _ctrVector);

                // output is input xor with random
                for (int i = 0; i < Output.Length; i++)
                    Output[i] = (byte)(Input[i] ^ random[i]);
            }
            else
            {
                // parallel CTR processing //
                int count = this.ProcessorCount;
                int alignedSize = Output.Length / _blockSize;
                int chunkSize = (alignedSize / count) * _blockSize;
                int roundSize = chunkSize * count;
                int subSize = (chunkSize / _blockSize);

                // create jagged array of 'sub counters'
                byte[][] counters = new byte[count][];

                // create random, and xor to output in parallel
                System.Threading.Tasks.Parallel.For(0, count, i =>
                {
                    // offset counter by chunk size / block size
                    counters[i] = Increase(_ctrVector, subSize * i);
                    // create random with offset counter
                    byte[] random = Generate(chunkSize, counters[i]);

                    // xor with input at offset
                    for (int j = 0; j < chunkSize; j++)
                        Output[j + (i * chunkSize)] = (byte)(Input[j + (i * chunkSize)] ^ random[j]);
                });

                // last block processing
                if (roundSize < Output.Length)
                {
                    int finalSize = Output.Length % roundSize;
                    byte[] random = Generate(finalSize, counters[count - 1]);

                    for (int i = 0; i < finalSize; i++)
                        Output[i + roundSize] = (byte)(Input[i + roundSize] ^ random[i]);
                }

                // copy the last counter position to class variable
                Buffer.BlockCopy(counters[count - 1], 0, _ctrVector, 0, _ctrVector.Length);
            }
        }

        private void ParallelTransform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int size = Output.Length - OutOffset;
            byte[] input = new byte[size];
            byte[] output = new byte[size];

            Buffer.BlockCopy(Input, InOffset, input, 0, size);
            Transform(input, output);
            Buffer.BlockCopy(output, 0, Output, OutOffset, output.Length);
        }
        #endregion

        #region Private Methods
        /// <remarks>
        /// Incremental counter with carry
        /// </remarks>
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

        private void ProcessBlock(byte[] Input, byte[] Output)
        {
            // encrypt the counter
            _blockCipher.EncryptBlock(_ctrVector, _ctrTemp);

            // output = ciphertext xor input
            for (int i = 0; i < _ctrTemp.Length; i++)
                Output[i] = (byte)(_ctrTemp[i] ^ Input[i]);

            // increment the counter with carry
            Increment(_ctrVector);
        }

        private void ProcessBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            // encrypt the counter
            _blockCipher.EncryptBlock(_ctrVector, _ctrTemp);

            // output = ciphertext xor input
            for (int i = 0; i < _ctrTemp.Length; i++)
                Output[OutOffset + i] = (byte)(_ctrTemp[i] ^ Input[InOffset + i]);

            // increment the counter with carry
            Increment(_ctrVector);
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
