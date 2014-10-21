using System;

namespace VTDev.Projects.CEX.CryptoGraphic
{
    internal class SHA256HMAC : IDisposable
    {
        #region Constants
        private const Int32 BLOCK_SIZE = 64;
        private const Int32 DIGEST_SIZE = 32;
        private const byte IPAD = (byte)0x36;
        private const byte OPAD = (byte)0x5C;
        #endregion

        #region Fields
        private Int32 _bufferOffset = 0;
        private Int64 _byteCount = 0;
        private UInt32[] _hashTable = new UInt32[8];
        private byte[] _inputPad = new byte[BLOCK_SIZE];
        private bool _isDisposed = false;
        private byte[] _outputPad = new byte[BLOCK_SIZE];
        private byte[] _processBuffer = new byte[4];
        private UInt32[] _wordBuffer = new uint[64];
        private Int32 _wordOffset = 0;
        #endregion

        #region Constructor
        public SHA256HMAC(byte[] Key)
        {
            // The first 32 bits of the fractional parts of the square roots of the first eight prime numbers
            _hashTable = new UInt32[8] { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

            int keyLength = Key.Length;

            if (keyLength > BLOCK_SIZE)
            {
                BlockUpdate(Key, 0, Key.Length);
                HashFinalize(_inputPad, 0);

                keyLength = DIGEST_SIZE;
            }
            else
            {
                Array.Copy(Key, 0, _inputPad, 0, keyLength);
            }

            Array.Clear(_inputPad, keyLength, BLOCK_SIZE - keyLength);
            Array.Copy(_inputPad, 0, _outputPad, 0, BLOCK_SIZE);

            for (int i = 0; i < _inputPad.Length; ++i)
                _inputPad[i] ^= IPAD;

            for (int i = 0; i < _outputPad.Length; ++i)
                _outputPad[i] ^= OPAD;

            // Initialise the digest
            BlockUpdate(_inputPad, 0, _inputPad.Length);
        }

        /// <summary>
        /// Update the hash buffer
        /// </summary>
        /// <param name="Input">Input data [bytes]</param>
        /// <param name="InputOffset">Offset within Input</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        public void BlockUpdate(byte[] Input, int InputOffset, int Length)
        {
            // fill the current word
            while ((_bufferOffset != 0) && (Length > 0))
            {
                Update(Input[InputOffset]);
                InputOffset++;
                Length--;
            }

            // process whole words
            while (Length > _processBuffer.Length)
            {
                ProcessWord(Input, InputOffset);

                InputOffset += _processBuffer.Length;
                Length -= _processBuffer.Length;
                _byteCount += _processBuffer.Length;
            }

            // load in the remainder
            while (Length > 0)
            {
                Update(Input[InputOffset]);

                InputOffset++;
                Length--;
            }
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// <param name="Input"></param>
        /// <returns>Hash value [32 bytes]</returns>
        public byte[] ComputeHash(byte[] Input)
        {
            byte[] hash = new byte[32];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Process the last block of data
        /// </summary>
        /// <param name="Output">The hash value return</param>
        /// <param name="Offset">The offset in the data</param>
        /// <returns>bytes processed</returns>
        public int DoFinal(byte[] Output, int Offset)
        {
            byte[] tmp = new byte[DIGEST_SIZE];
            HashFinalize(tmp, 0);

            BlockUpdate(_outputPad, 0, _outputPad.Length);
            BlockUpdate(tmp, 0, tmp.Length);

            int len = HashFinalize(Output, Offset);
            // Initialise the digest
            BlockUpdate(_inputPad, 0, _inputPad.Length);

            return len;
        }
        #endregion

        #region Properties
        /// <summary>
        /// The Ciphers internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return DIGEST_SIZE; }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Do final processing
        /// </summary>
        /// <param name="Output">Inputs the final block, and returns the Hash value</param>
        /// <param name="OutputOffset">The starting positional offset within the Output array</param>
        /// <returns>Size of Hash value, Always 32 bytes</returns>
        private Int32 HashFinalize(byte[] Output, Int32 OutputOffset)
        {
            Finish();

            UInt32ToBE((uint)_hashTable[0], Output, OutputOffset);
            UInt32ToBE((uint)_hashTable[1], Output, OutputOffset + 4);
            UInt32ToBE((uint)_hashTable[2], Output, OutputOffset + 8);
            UInt32ToBE((uint)_hashTable[3], Output, OutputOffset + 12);
            UInt32ToBE((uint)_hashTable[4], Output, OutputOffset + 16);
            UInt32ToBE((uint)_hashTable[5], Output, OutputOffset + 20);
            UInt32ToBE((uint)_hashTable[6], Output, OutputOffset + 24);
            UInt32ToBE((uint)_hashTable[7], Output, OutputOffset + 28);

            Reset();

            return DIGEST_SIZE;
        }

        private void Finish()
        {
            Int64 bitLength = (_byteCount << 3);

            Update((byte)128);

            while (_bufferOffset != 0)
                Update((byte)0);

            ProcessLength(bitLength);
            ProcessBlock();
        }

        private void ProcessBlock()
        {
            Int32 ct = 0;
            UInt32[] workingSet = new UInt32[8];

            // copy the hashtable in
            Buffer.BlockCopy(_hashTable, 0, workingSet, 0, 32);

            // expand 16 word block into 64 word blocks
            for (int i = 16; i <= 63; i++)
                _wordBuffer[i] = Theta1(_wordBuffer[i - 2]) + _wordBuffer[i - 7] + Theta0(_wordBuffer[i - 15]) + _wordBuffer[i - 16];

            for (int i = 0; i < 8; ++i)
            {
                // t = 8 * i
                workingSet[7] += Sum1Ch(workingSet[4], workingSet[5], workingSet[6]) + K1C[ct] + _wordBuffer[ct];
                workingSet[3] += workingSet[7];
                workingSet[7] += Sum0Maj(workingSet[0], workingSet[1], workingSet[2]);
                ++ct;
                // t = 8 * i + 1
                workingSet[6] += Sum1Ch(workingSet[3], workingSet[4], workingSet[5]) + K1C[ct] + _wordBuffer[ct];
                workingSet[2] += workingSet[6];
                workingSet[6] += Sum0Maj(workingSet[7], workingSet[0], workingSet[1]);
                ++ct;
                // t = 8 * i + 2
                workingSet[5] += Sum1Ch(workingSet[2], workingSet[3], workingSet[4]) + K1C[ct] + _wordBuffer[ct];
                workingSet[1] += workingSet[5];
                workingSet[5] += Sum0Maj(workingSet[6], workingSet[7], workingSet[0]);
                ++ct;
                // t = 8 * i + 3
                workingSet[4] += Sum1Ch(workingSet[1], workingSet[2], workingSet[3]) + K1C[ct] + _wordBuffer[ct];
                workingSet[0] += workingSet[4];
                workingSet[4] += Sum0Maj(workingSet[5], workingSet[6], workingSet[7]);
                ++ct;
                // t = 8 * i + 4
                workingSet[3] += Sum1Ch(workingSet[0], workingSet[1], workingSet[2]) + K1C[ct] + _wordBuffer[ct];
                workingSet[7] += workingSet[3];
                workingSet[3] += Sum0Maj(workingSet[4], workingSet[5], workingSet[6]);
                ++ct;
                // t = 8 * i + 5
                workingSet[2] += Sum1Ch(workingSet[7], workingSet[0], workingSet[1]) + K1C[ct] + _wordBuffer[ct];
                workingSet[6] += workingSet[2];
                workingSet[2] += Sum0Maj(workingSet[3], workingSet[4], workingSet[5]);
                ++ct;
                // t = 8 * i + 6
                workingSet[1] += Sum1Ch(workingSet[6], workingSet[7], workingSet[0]) + K1C[ct] + _wordBuffer[ct];
                workingSet[5] += workingSet[1];
                workingSet[1] += Sum0Maj(workingSet[2], workingSet[3], workingSet[4]);
                ++ct;
                // t = 8 * i + 7
                workingSet[0] += Sum1Ch(workingSet[5], workingSet[6], workingSet[7]) + K1C[ct] + _wordBuffer[ct];
                workingSet[4] += workingSet[0];
                workingSet[0] += Sum0Maj(workingSet[1], workingSet[2], workingSet[3]);
                ++ct;
            }

            _hashTable[0] += workingSet[0];
            _hashTable[1] += workingSet[1];
            _hashTable[2] += workingSet[2];
            _hashTable[3] += workingSet[3];
            _hashTable[4] += workingSet[4];
            _hashTable[5] += workingSet[5];
            _hashTable[6] += workingSet[6];
            _hashTable[7] += workingSet[7];

            // reset the offset and clear the word buffer
            _wordOffset = 0;
            Array.Clear(_wordBuffer, 0, 16);
        }

        private void ProcessLength(long BitLength)
        {
            if (_wordOffset > 14)
                ProcessBlock();

            _wordBuffer[14] = (uint)((ulong)BitLength >> 32);
            _wordBuffer[15] = (uint)((ulong)BitLength);
        }

        private void ProcessWord(byte[] input, int inOff)
        {
            _wordBuffer[_wordOffset] = BEToUInt32(input, inOff);

            if (++_wordOffset == 16)
                ProcessBlock();
        }

        private void Reset()
        {
            _byteCount = 0;
            _bufferOffset = 0;
            Array.Clear(_processBuffer, 0, _processBuffer.Length);
        }

        private void Update(byte Input)
        {
            _processBuffer[_bufferOffset++] = Input;

            if (_bufferOffset == _processBuffer.Length)
            {
                ProcessWord(_processBuffer, 0);
                _bufferOffset = 0;
            }

            _byteCount++;
        }
        #endregion

        #region Helpers
        /// <summary>
        /// Big Endian to UInt32
        /// </summary>
        private uint BEToUInt32(byte[] bs, int off)
        {
            uint n = (uint)bs[off] << 24;
            n |= (uint)bs[++off] << 16;
            n |= (uint)bs[++off] << 8;
            n |= (uint)bs[++off];
            return n;
        }

        /// <summary>
        /// UInt32 to Big Endian
        /// </summary>
        private void UInt32ToBE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[++off] = (byte)(n >> 16);
            bs[++off] = (byte)(n >> 8);
            bs[++off] = (byte)(n);
        }

        private uint Sum1Ch(uint x, uint y, uint z)
        {
            return (((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7))) + ((x & y) ^ ((~x) & z));
        }

        private uint Sum0Maj(uint x, uint y, uint z)
        {
            return (((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10))) + ((x & y) ^ (x & z) ^ (y & z));
        }

        private uint Theta0(uint x)
        {
            return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
        }

        private uint Theta1(uint x)
        {
            return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);
        }
        #endregion

        #region Constant Tables
        /// <summary>
        /// the first 32 bits of the fractional parts of the cube roots of the first sixty-four prime numbers)
        /// </summary>
        private readonly uint[] K1C = { 
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
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
                    if (_hashTable != null)
                        Array.Clear(_hashTable, 0, _hashTable.Length);
                    if (_inputPad != null)
                        Array.Clear(_inputPad, 0, _inputPad.Length);
                    if (_outputPad != null)
                        Array.Clear(_outputPad, 0, _outputPad.Length);
                    if (_processBuffer != null)
                        Array.Clear(_processBuffer, 0, _processBuffer.Length);
                    if (_wordBuffer != null)
                        Array.Clear(_wordBuffer, 0, _wordBuffer.Length);
                    if (K1C != null)
                        Array.Clear(K1C, 0, K1C.Length);
                }
                _isDisposed = true;
            }
        }
        #endregion
    }
}
