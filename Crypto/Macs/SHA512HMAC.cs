using System;

namespace VTDev.Projects.CEX.Crypto.Macs
{
    public class SHA512HMAC : IMac, IDisposable
    {
        #region Constants
        private const Int32 BLOCK_SIZE = 128;
        private const Int32 DIGEST_SIZE = 64;
        private const byte IPAD = (byte)0x36;
        private const byte OPAD = (byte)0x5C;
        #endregion

        #region Fields
        private Int32 _bufferOffset = 0;
        private long _btCounter1 = 0;
        private long _btCounter2 = 0;
        private ulong H1, H2, H3, H4, H5, H6, H7, H8;
        private byte[] _inputPad = new byte[BLOCK_SIZE];
        private bool _isDisposed = false;
        private byte[] _outputPad = new byte[BLOCK_SIZE];
        private byte[] _prcBuffer = new byte[8];
        private ulong[] _wordBuffer = new ulong[80];
        private Int32 _wordOffset = 0;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        public SHA512HMAC()
        {
        }

        /// <summary>
        /// Initialize the class and working variables.
        /// Can be used in place of Init() call.
        /// </summary>
        /// <param name="Key">HMAC Key</param>
        public SHA512HMAC(byte[] Key)
        {
            Init(Key);
        }
        #endregion

        #region Properties
        /// <summary>
        /// The Digests internal blocksize in bytes
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

        /// <summary>
        /// Algorithm name
        /// </summary>
        public string Name
        {
            get { return "SHA512HMAC"; }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the SHA256 buffer
        /// </summary>
        /// <param name="Input">Input data [bytes]</param>
        /// <param name="InOffset">Offset within Input array</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            // fill the current word
            while ((_bufferOffset != 0) && (Length > 0))
            {
                Update(Input[InOffset]);

                InOffset++;
                Length--;
            }

            // process whole words.
            while (Length > _prcBuffer.Length)
            {
                ProcessWord(Input, InOffset);

                InOffset += _prcBuffer.Length;
                Length -= _prcBuffer.Length;
                _btCounter1 += _prcBuffer.Length;
            }

            // load in the remainder.
            while (Length > 0)
            {
                Update(Input[InOffset]);

                InOffset++;
                Length--;
            }
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// <param name="Input">Input data [bytes]</param>
        /// <returns>Hash value [64 bytes]</returns>
        public byte[] ComputeMac(byte[] Input)
        {
            byte[] hash = new byte[64];

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
            Finalize(tmp, 0);

            BlockUpdate(_outputPad, 0, _outputPad.Length);
            BlockUpdate(tmp, 0, tmp.Length);

            int len = Finalize(Output, Offset);
            BlockUpdate(_inputPad, 0, _inputPad.Length);

            return len;
        }

        /// <summary>
        /// Initialize the HMAC
        /// </summary>
        /// <param name="Key">HMAC key</param>
        public void Init(byte[] Key)
        {
            int keyLength = Key.Length;

            Init();

            if (keyLength > BLOCK_SIZE)
            {
                BlockUpdate(Key, 0, Key.Length);
                Finalize(_inputPad, 0);

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
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            _btCounter1 = 0;
            _btCounter2 = 0;
            _bufferOffset = 0;

            for (int i = 0; i < _prcBuffer.Length; i++)
                _prcBuffer[i] = 0;

            _wordOffset = 0;
            Array.Clear(_wordBuffer, 0, _wordBuffer.Length);

            Init();
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            _prcBuffer[_bufferOffset++] = Input;

            if (_bufferOffset == _prcBuffer.Length)
            {
                ProcessWord(_prcBuffer, 0);
                _bufferOffset = 0;
            }

            _btCounter1++;
        }
        #endregion

        #region Private Methods
        private void AdjustByteCounts()
        {
            if (_btCounter1 > 0x1fffffffffffffffL)
            {
                _btCounter2 += (long)((ulong)_btCounter1 >> 61);
                _btCounter1 &= 0x1fffffffffffffffL;
            }
        }

        private int Finalize(byte[] Output, int OutOffset)
        {
            Finish();

            UInt64ToBE(H1, Output, OutOffset);
            UInt64ToBE(H2, Output, OutOffset + 8);
            UInt64ToBE(H3, Output, OutOffset + 16);
            UInt64ToBE(H4, Output, OutOffset + 24);
            UInt64ToBE(H5, Output, OutOffset + 32);
            UInt64ToBE(H6, Output, OutOffset + 40);
            UInt64ToBE(H7, Output, OutOffset + 48);
            UInt64ToBE(H8, Output, OutOffset + 56);

            Reset();

            return DIGEST_SIZE;
        }

        private void Finish()
        {
            AdjustByteCounts();

            long lowBitLength = _btCounter1 << 3;
            long hiBitLength = _btCounter2;

            // add the pad bytes.
            Update((byte)128);

            while (_bufferOffset != 0)
                Update((byte)0);

            ProcessLength(lowBitLength, hiBitLength);
            ProcessBlock();
        }

        private void Init()
        {
            H1 = 0x6a09e667f3bcc908;
            H2 = 0xbb67ae8584caa73b;
            H3 = 0x3c6ef372fe94f82b;
            H4 = 0xa54ff53a5f1d36f1;
            H5 = 0x510e527fade682d1;
            H6 = 0x9b05688c2b3e6c1f;
            H7 = 0x1f83d9abfb41bd6b;
            H8 = 0x5be0cd19137e2179;
        }

        private void ProcessBlock()
        {
            AdjustByteCounts();

            // expand 16 word block into 80 word blocks.
            for (int ti = 16; ti <= 79; ++ti)
                _wordBuffer[ti] = Sigma1(_wordBuffer[ti - 2]) + _wordBuffer[ti - 7] + Sigma0(_wordBuffer[ti - 15]) + _wordBuffer[ti - 16];

            // set up working variables.
            ulong a = H1;
            ulong b = H2;
            ulong c = H3;
            ulong d = H4;
            ulong e = H5;
            ulong f = H6;
            ulong g = H7;
            ulong h = H8;
            int t = 0;

            for (int i = 0; i < 10; i++)
            {
                // t = 8 * i
                h += Sum1(e) + Ch(e, f, g) + K[t] + _wordBuffer[t++];
                d += h;
                h += Sum0(a) + Maj(a, b, c);
                // t = 8 * i + 1
                g += Sum1(d) + Ch(d, e, f) + K[t] + _wordBuffer[t++];
                c += g;
                g += Sum0(h) + Maj(h, a, b);
                // t = 8 * i + 2
                f += Sum1(c) + Ch(c, d, e) + K[t] + _wordBuffer[t++];
                b += f;
                f += Sum0(g) + Maj(g, h, a);
                // t = 8 * i + 3
                e += Sum1(b) + Ch(b, c, d) + K[t] + _wordBuffer[t++];
                a += e;
                e += Sum0(f) + Maj(f, g, h);
                // t = 8 * i + 4
                d += Sum1(a) + Ch(a, b, c) + K[t] + _wordBuffer[t++];
                h += d;
                d += Sum0(e) + Maj(e, f, g);
                // t = 8 * i + 5
                c += Sum1(h) + Ch(h, a, b) + K[t] + _wordBuffer[t++];
                g += c;
                c += Sum0(d) + Maj(d, e, f);
                // t = 8 * i + 6
                b += Sum1(g) + Ch(g, h, a) + K[t] + _wordBuffer[t++];
                f += b;
                b += Sum0(c) + Maj(c, d, e);
                // t = 8 * i + 7
                a += Sum1(f) + Ch(f, g, h) + K[t] + _wordBuffer[t++];
                e += a;
                a += Sum0(b) + Maj(b, c, d);
            }

            H1 += a;
            H2 += b;
            H3 += c;
            H4 += d;
            H5 += e;
            H6 += f;
            H7 += g;
            H8 += h;

            // reset the offset and clean out the word buffer.
            _wordOffset = 0;
            Array.Clear(_wordBuffer, 0, 16);
        }

        private void ProcessLength(long LowW, long HiW)
        {
            if (_wordOffset > 14)
                ProcessBlock();

            _wordBuffer[14] = (ulong)HiW;
            _wordBuffer[15] = (ulong)LowW;
        }

        private void ProcessWord(byte[] Input, int InOffset)
        {
            _wordBuffer[_wordOffset] = BEToUInt64(Input, InOffset);

            if (++_wordOffset == 16)
                ProcessBlock();
        }
        #endregion

        #region Helpers
        private ulong BEToUInt64(byte[] bs, int off)
        {
            uint hi = BEToUInt32(bs, off);
            uint lo = BEToUInt32(bs, off + 4);

            return ((ulong)hi << 32) | (ulong)lo;
        }

        private uint BEToUInt32(byte[] bs, int off)
        {
            uint n = (uint)bs[off] << 24;
            n |= (uint)bs[++off] << 16;
            n |= (uint)bs[++off] << 8;
            n |= (uint)bs[++off];

            return n;
        }

        private ulong Ch(ulong x, ulong y, ulong z)
        {
            return (x & y) ^ (~x & z);
        }

        private ulong Maj(ulong x, ulong y, ulong z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        private ulong Sigma0(ulong x)
        {
            return ((x << 63) | (x >> 1)) ^ ((x << 56) | (x >> 8)) ^ (x >> 7);
        }

        private static ulong Sigma1(ulong x)
        {
            return ((x << 45) | (x >> 19)) ^ ((x << 3) | (x >> 61)) ^ (x >> 6);
        }

        private ulong Sum0(ulong x)
        {
            return ((x << 36) | (x >> 28)) ^ ((x << 30) | (x >> 34)) ^ ((x << 25) | (x >> 39));
        }

        private ulong Sum1(ulong x)
        {
            return ((x << 50) | (x >> 14)) ^ ((x << 46) | (x >> 18)) ^ ((x << 23) | (x >> 41));
        }

        private void UInt64ToBE(ulong n, byte[] bs, int off)
        {
            UInt32ToBE((uint)(n >> 32), bs, off);
            UInt32ToBE((uint)(n), bs, off + 4);
        }

        private void UInt32ToBE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[++off] = (byte)(n >> 16);
            bs[++off] = (byte)(n >> 8);
            bs[++off] = (byte)(n);
        }
        #endregion

        #region Constant Tables
        internal static readonly ulong[] K =
		{
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
			0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
			0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
			0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
			0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
			0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
			0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
			0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
			0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
			0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
			0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
			0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
			0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
			0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
			0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
			0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
			0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
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
                    if (_prcBuffer != null)
                    {
                        Array.Clear(_prcBuffer, 0, _prcBuffer.Length);
                        _prcBuffer = null;
                    }
                    if (_wordBuffer != null)
                    {
                        Array.Clear(_wordBuffer, 0, _wordBuffer.Length);
                        _wordBuffer = null;
                    }

                    _isDisposed = true;
                }
            }
        }
        #endregion
    }

}
