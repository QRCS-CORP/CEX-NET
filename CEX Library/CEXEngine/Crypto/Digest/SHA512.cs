#region Directives
using System;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Principal Algorithms:
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
// 
// Implementation Details:
// An implementation of the SHA-2 digest with a 512 bit return size. 
// Refactoring, a couple of small optimizations, Dispose, and a ComputeHash method added.
// Many thanks to the authors of BouncyCastle for their great contributions.
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// SHA512: An implementation of the SHA-2 digest with a 512 bit digest return size
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new SHA512())
    /// {
    ///     // compute a hash
    ///     byte[] Output = ComputeHash(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Block size is 128 bytes, (1024 bits).</description></item>
    /// <item><description>Digest size is 64 bytes, (512 bits).</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">SHA-2 Specification</a>.</description></item>
    /// </list>
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class SHA512 : IDigest
    {
        #region Constants
        private const string ALG_NAME = "SHA512";
        private int BLOCK_SIZE = 128;
        private int DIGEST_SIZE = 64;
        #endregion

        #region Fields
        private long _btCounter1 = 0;
        private long _btCounter2 = 0;
        private int _bufferOffset = 0;
        private ulong _H0, _H1, _H2, _H3, _H4, _H5, _H6, _H7;
        private bool _isDisposed = false;
        private byte[] _prcBuffer = new byte[8];
        private ulong[] _wordBuffer = new ulong[80];
        private int _wordOffset = 0;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return DIGEST_SIZE; }
        }

        /// <summary>
        /// Get: The digests type name
        /// </summary>
        public Digests Enumeral
        {
            get { return Digests.SHA512; }
        }

        /// <summary>
        /// Get: Digest name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the digest
        /// </summary>
        public SHA512()
        {
			Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SHA512()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the SHA256 buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input array</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        /// 
        /// <exception cref="CryptoHashException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if ((InOffset + Length) > Input.Length)
                throw new CryptoHashException("SHA512:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

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
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Hash value [64 bytes]</returns>
        public byte[] ComputeHash(byte[] Input)
        {
            byte[] hash = new byte[DigestSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Do final processing and get the hash value
        /// </summary>
        /// 
        /// <param name="Output">The Hash value container</param>
        /// <param name="OutOffset">The starting offset within the Output array</param>
        /// 
        /// <returns>Size of Hash value, Always 64 bytes</returns>
        /// 
        /// <exception cref="CryptoHashException">Thrown if Output array is too small</exception>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (Output.Length - OutOffset < DigestSize)
                throw new CryptoHashException("SHA512:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            Finish();

            IntUtils.Be64ToBytes(_H0, Output, OutOffset);
            IntUtils.Be64ToBytes(_H1, Output, OutOffset + 8);
            IntUtils.Be64ToBytes(_H2, Output, OutOffset + 16);
            IntUtils.Be64ToBytes(_H3, Output, OutOffset + 24);
            IntUtils.Be64ToBytes(_H4, Output, OutOffset + 32);
            IntUtils.Be64ToBytes(_H5, Output, OutOffset + 40);
            IntUtils.Be64ToBytes(_H6, Output, OutOffset + 48);
            IntUtils.Be64ToBytes(_H7, Output, OutOffset + 56);

            Reset();

            return DIGEST_SIZE;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            _btCounter1 = 0;
            _btCounter2 = 0;
            _bufferOffset = 0;

            for ( int i = 0; i < _prcBuffer.Length; i++ )
                _prcBuffer[i] = 0;

            _wordOffset = 0;
			Array.Clear(_wordBuffer, 0, _wordBuffer.Length);

            Initialize();
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
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

        private void Finish()
        {
            AdjustByteCounts();

            long lowBitLen = _btCounter1 << 3;
            long hiBitLen = _btCounter2;

            // add the pad bytes.
            Update((byte)128);

            while (_bufferOffset != 0)
                Update((byte)0);

            ProcessLength(lowBitLen, hiBitLen);
            ProcessBlock();
        }

        private void Initialize()
        {
            _H0 = 0x6a09e667f3bcc908;
            _H1 = 0xbb67ae8584caa73b;
            _H2 = 0x3c6ef372fe94f82b;
            _H3 = 0xa54ff53a5f1d36f1;
            _H4 = 0x510e527fade682d1;
            _H5 = 0x9b05688c2b3e6c1f;
            _H6 = 0x1f83d9abfb41bd6b;
            _H7 = 0x5be0cd19137e2179;
        }

        private void ProcessBlock()
        {
            // set up working variables
            ulong w0 = _H0;
            ulong w1 = _H1;
            ulong w2 = _H2;
            ulong w3 = _H3;
            ulong w4 = _H4;
            ulong w5 = _H5;
            ulong w6 = _H6;
            ulong w7 = _H7;
            int ctr = 0;

            AdjustByteCounts();

            // expand 16 word block into 80 word blocks
            _wordBuffer[16] = Sigma1(_wordBuffer[14]) + _wordBuffer[9] + Sigma0(_wordBuffer[1]) + _wordBuffer[0];
            _wordBuffer[17] = Sigma1(_wordBuffer[15]) + _wordBuffer[10] + Sigma0(_wordBuffer[2]) + _wordBuffer[1];
            _wordBuffer[18] = Sigma1(_wordBuffer[16]) + _wordBuffer[11] + Sigma0(_wordBuffer[3]) + _wordBuffer[2];
            _wordBuffer[19] = Sigma1(_wordBuffer[17]) + _wordBuffer[12] + Sigma0(_wordBuffer[4]) + _wordBuffer[3];
            _wordBuffer[20] = Sigma1(_wordBuffer[18]) + _wordBuffer[13] + Sigma0(_wordBuffer[5]) + _wordBuffer[4];
            _wordBuffer[21] = Sigma1(_wordBuffer[19]) + _wordBuffer[14] + Sigma0(_wordBuffer[6]) + _wordBuffer[5];
            _wordBuffer[22] = Sigma1(_wordBuffer[20]) + _wordBuffer[15] + Sigma0(_wordBuffer[7]) + _wordBuffer[6];
            _wordBuffer[23] = Sigma1(_wordBuffer[21]) + _wordBuffer[16] + Sigma0(_wordBuffer[8]) + _wordBuffer[7];
            _wordBuffer[24] = Sigma1(_wordBuffer[22]) + _wordBuffer[17] + Sigma0(_wordBuffer[9]) + _wordBuffer[8];
            _wordBuffer[25] = Sigma1(_wordBuffer[23]) + _wordBuffer[18] + Sigma0(_wordBuffer[10]) + _wordBuffer[9];
            _wordBuffer[26] = Sigma1(_wordBuffer[24]) + _wordBuffer[19] + Sigma0(_wordBuffer[11]) + _wordBuffer[10];
            _wordBuffer[27] = Sigma1(_wordBuffer[25]) + _wordBuffer[20] + Sigma0(_wordBuffer[12]) + _wordBuffer[11];
            _wordBuffer[28] = Sigma1(_wordBuffer[26]) + _wordBuffer[21] + Sigma0(_wordBuffer[13]) + _wordBuffer[12];
            _wordBuffer[29] = Sigma1(_wordBuffer[27]) + _wordBuffer[22] + Sigma0(_wordBuffer[14]) + _wordBuffer[13];
            _wordBuffer[30] = Sigma1(_wordBuffer[28]) + _wordBuffer[23] + Sigma0(_wordBuffer[15]) + _wordBuffer[14];
            _wordBuffer[31] = Sigma1(_wordBuffer[29]) + _wordBuffer[24] + Sigma0(_wordBuffer[16]) + _wordBuffer[15];
            _wordBuffer[32] = Sigma1(_wordBuffer[30]) + _wordBuffer[25] + Sigma0(_wordBuffer[17]) + _wordBuffer[16];
            _wordBuffer[33] = Sigma1(_wordBuffer[31]) + _wordBuffer[26] + Sigma0(_wordBuffer[18]) + _wordBuffer[17];
            _wordBuffer[34] = Sigma1(_wordBuffer[32]) + _wordBuffer[27] + Sigma0(_wordBuffer[19]) + _wordBuffer[18];
            _wordBuffer[35] = Sigma1(_wordBuffer[33]) + _wordBuffer[28] + Sigma0(_wordBuffer[20]) + _wordBuffer[19];
            _wordBuffer[36] = Sigma1(_wordBuffer[34]) + _wordBuffer[29] + Sigma0(_wordBuffer[21]) + _wordBuffer[20];
            _wordBuffer[37] = Sigma1(_wordBuffer[35]) + _wordBuffer[30] + Sigma0(_wordBuffer[22]) + _wordBuffer[21];
            _wordBuffer[38] = Sigma1(_wordBuffer[36]) + _wordBuffer[31] + Sigma0(_wordBuffer[23]) + _wordBuffer[22];
            _wordBuffer[39] = Sigma1(_wordBuffer[37]) + _wordBuffer[32] + Sigma0(_wordBuffer[24]) + _wordBuffer[23];
            _wordBuffer[40] = Sigma1(_wordBuffer[38]) + _wordBuffer[33] + Sigma0(_wordBuffer[25]) + _wordBuffer[24];
            _wordBuffer[41] = Sigma1(_wordBuffer[39]) + _wordBuffer[34] + Sigma0(_wordBuffer[26]) + _wordBuffer[25];
            _wordBuffer[42] = Sigma1(_wordBuffer[40]) + _wordBuffer[35] + Sigma0(_wordBuffer[27]) + _wordBuffer[26];
            _wordBuffer[43] = Sigma1(_wordBuffer[41]) + _wordBuffer[36] + Sigma0(_wordBuffer[28]) + _wordBuffer[27];
            _wordBuffer[44] = Sigma1(_wordBuffer[42]) + _wordBuffer[37] + Sigma0(_wordBuffer[29]) + _wordBuffer[28];
            _wordBuffer[45] = Sigma1(_wordBuffer[43]) + _wordBuffer[38] + Sigma0(_wordBuffer[30]) + _wordBuffer[29];
            _wordBuffer[46] = Sigma1(_wordBuffer[44]) + _wordBuffer[39] + Sigma0(_wordBuffer[31]) + _wordBuffer[30];
            _wordBuffer[47] = Sigma1(_wordBuffer[45]) + _wordBuffer[40] + Sigma0(_wordBuffer[32]) + _wordBuffer[31];
            _wordBuffer[48] = Sigma1(_wordBuffer[46]) + _wordBuffer[41] + Sigma0(_wordBuffer[33]) + _wordBuffer[32];
            _wordBuffer[49] = Sigma1(_wordBuffer[47]) + _wordBuffer[42] + Sigma0(_wordBuffer[34]) + _wordBuffer[33];
            _wordBuffer[50] = Sigma1(_wordBuffer[48]) + _wordBuffer[43] + Sigma0(_wordBuffer[35]) + _wordBuffer[34];
            _wordBuffer[51] = Sigma1(_wordBuffer[49]) + _wordBuffer[44] + Sigma0(_wordBuffer[36]) + _wordBuffer[35];
            _wordBuffer[52] = Sigma1(_wordBuffer[50]) + _wordBuffer[45] + Sigma0(_wordBuffer[37]) + _wordBuffer[36];
            _wordBuffer[53] = Sigma1(_wordBuffer[51]) + _wordBuffer[46] + Sigma0(_wordBuffer[38]) + _wordBuffer[37];
            _wordBuffer[54] = Sigma1(_wordBuffer[52]) + _wordBuffer[47] + Sigma0(_wordBuffer[39]) + _wordBuffer[38];
            _wordBuffer[55] = Sigma1(_wordBuffer[53]) + _wordBuffer[48] + Sigma0(_wordBuffer[40]) + _wordBuffer[39];
            _wordBuffer[56] = Sigma1(_wordBuffer[54]) + _wordBuffer[49] + Sigma0(_wordBuffer[41]) + _wordBuffer[40];
            _wordBuffer[57] = Sigma1(_wordBuffer[55]) + _wordBuffer[50] + Sigma0(_wordBuffer[42]) + _wordBuffer[41];
            _wordBuffer[58] = Sigma1(_wordBuffer[56]) + _wordBuffer[51] + Sigma0(_wordBuffer[43]) + _wordBuffer[42];
            _wordBuffer[59] = Sigma1(_wordBuffer[57]) + _wordBuffer[52] + Sigma0(_wordBuffer[44]) + _wordBuffer[43];
            _wordBuffer[60] = Sigma1(_wordBuffer[58]) + _wordBuffer[53] + Sigma0(_wordBuffer[45]) + _wordBuffer[44];
            _wordBuffer[61] = Sigma1(_wordBuffer[59]) + _wordBuffer[54] + Sigma0(_wordBuffer[46]) + _wordBuffer[45];
            _wordBuffer[62] = Sigma1(_wordBuffer[60]) + _wordBuffer[55] + Sigma0(_wordBuffer[47]) + _wordBuffer[46];
            _wordBuffer[63] = Sigma1(_wordBuffer[61]) + _wordBuffer[56] + Sigma0(_wordBuffer[48]) + _wordBuffer[47];
            _wordBuffer[64] = Sigma1(_wordBuffer[62]) + _wordBuffer[57] + Sigma0(_wordBuffer[49]) + _wordBuffer[48];
            _wordBuffer[65] = Sigma1(_wordBuffer[63]) + _wordBuffer[58] + Sigma0(_wordBuffer[50]) + _wordBuffer[49];
            _wordBuffer[66] = Sigma1(_wordBuffer[64]) + _wordBuffer[59] + Sigma0(_wordBuffer[51]) + _wordBuffer[50];
            _wordBuffer[67] = Sigma1(_wordBuffer[65]) + _wordBuffer[60] + Sigma0(_wordBuffer[52]) + _wordBuffer[51];
            _wordBuffer[68] = Sigma1(_wordBuffer[66]) + _wordBuffer[61] + Sigma0(_wordBuffer[53]) + _wordBuffer[52];
            _wordBuffer[69] = Sigma1(_wordBuffer[67]) + _wordBuffer[62] + Sigma0(_wordBuffer[54]) + _wordBuffer[53];
            _wordBuffer[70] = Sigma1(_wordBuffer[68]) + _wordBuffer[63] + Sigma0(_wordBuffer[55]) + _wordBuffer[54];
            _wordBuffer[71] = Sigma1(_wordBuffer[69]) + _wordBuffer[64] + Sigma0(_wordBuffer[56]) + _wordBuffer[55];
            _wordBuffer[72] = Sigma1(_wordBuffer[70]) + _wordBuffer[65] + Sigma0(_wordBuffer[57]) + _wordBuffer[56];
            _wordBuffer[73] = Sigma1(_wordBuffer[71]) + _wordBuffer[66] + Sigma0(_wordBuffer[58]) + _wordBuffer[57];
            _wordBuffer[74] = Sigma1(_wordBuffer[72]) + _wordBuffer[67] + Sigma0(_wordBuffer[59]) + _wordBuffer[58];
            _wordBuffer[75] = Sigma1(_wordBuffer[73]) + _wordBuffer[68] + Sigma0(_wordBuffer[60]) + _wordBuffer[59];
            _wordBuffer[76] = Sigma1(_wordBuffer[74]) + _wordBuffer[69] + Sigma0(_wordBuffer[61]) + _wordBuffer[60];
            _wordBuffer[77] = Sigma1(_wordBuffer[75]) + _wordBuffer[70] + Sigma0(_wordBuffer[62]) + _wordBuffer[61];
            _wordBuffer[78] = Sigma1(_wordBuffer[76]) + _wordBuffer[71] + Sigma0(_wordBuffer[63]) + _wordBuffer[62];
            _wordBuffer[79] = Sigma1(_wordBuffer[77]) + _wordBuffer[72] + Sigma0(_wordBuffer[64]) + _wordBuffer[63];

            // t = 8 * i
            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            // t = 8 * i + 1
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            // t = 8 * i + 2
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            // t = 8 * i + 3
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            // t = 8 * i + 4
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            // t = 8 * i + 5
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            // t = 8 * i + 6
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            // t = 8 * i + 7
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            w7 += Sum1(w4) + Ch(w4, w5, w6) + K64[++ctr] + _wordBuffer[ctr];
            w3 += w7;
            w7 += Sum0(w0) + Maj(w0, w1, w2);
            w6 += Sum1(w3) + Ch(w3, w4, w5) + K64[++ctr] + _wordBuffer[ctr];
            w2 += w6;
            w6 += Sum0(w7) + Maj(w7, w0, w1);
            w5 += Sum1(w2) + Ch(w2, w3, w4) + K64[++ctr] + _wordBuffer[ctr];
            w1 += w5;
            w5 += Sum0(w6) + Maj(w6, w7, w0);
            w4 += Sum1(w1) + Ch(w1, w2, w3) + K64[++ctr] + _wordBuffer[ctr];
            w0 += w4;
            w4 += Sum0(w5) + Maj(w5, w6, w7);
            w3 += Sum1(w0) + Ch(w0, w1, w2) + K64[++ctr] + _wordBuffer[ctr];
            w7 += w3;
            w3 += Sum0(w4) + Maj(w4, w5, w6);
            w2 += Sum1(w7) + Ch(w7, w0, w1) + K64[++ctr] + _wordBuffer[ctr];
            w6 += w2;
            w2 += Sum0(w3) + Maj(w3, w4, w5);
            w1 += Sum1(w6) + Ch(w6, w7, w0) + K64[++ctr] + _wordBuffer[ctr];
            w5 += w1;
            w1 += Sum0(w2) + Maj(w2, w3, w4);
            w0 += Sum1(w5) + Ch(w5, w6, w7) + K64[++ctr] + _wordBuffer[ctr];
            w4 += w0;
            w0 += Sum0(w1) + Maj(w1, w2, w3);

            _H0 += w0;
            _H1 += w1;
            _H2 += w2;
            _H3 += w3;
            _H4 += w4;
            _H5 += w5;
            _H6 += w6;
            _H7 += w7;

            // reset the offset and clean out the word buffer.
            _wordOffset = 0;
			Array.Clear(_wordBuffer, 0, 16);
		}

        private void ProcessLength(long LowWord, long HiWord)
        {
            if (_wordOffset > 14)
                ProcessBlock();

            _wordBuffer[14] = (ulong)HiWord;
            _wordBuffer[15] = (ulong)LowWord;
        }

        private void ProcessWord(byte[] Input, int InOffset)
        {
            _wordBuffer[_wordOffset] = IntUtils.BytesToBe64(Input, InOffset);

            if (++_wordOffset == 16)
                ProcessBlock();
        }
        #endregion

        #region Helpers
        private static ulong Ch(ulong X, ulong Y, ulong Z)
        {
            return (X & Y) ^ (~X & Z);
        }

        private static ulong Maj(ulong X, ulong Y, ulong Z)
        {
            return (X & Y) ^ (X & Z) ^ (Y & Z);
        }

        private static ulong Sigma0(ulong X)
        {
            return ((X << 63) | (X >> 1)) ^ ((X << 56) | (X >> 8)) ^ (X >> 7);
        }

        private static ulong Sigma1(ulong X)
        {
            return ((X << 45) | (X >> 19)) ^ ((X << 3) | (X >> 61)) ^ (X >> 6);
        }

        private static ulong Sum0(ulong X)
        {
            return ((X << 36) | (X >> 28)) ^ ((X << 30) | (X >> 34)) ^ ((X << 25) | (X >> 39));
        }

        private static ulong Sum1(ulong X)
        {
            return ((X << 50) | (X >> 14)) ^ ((X << 46) | (X >> 18)) ^ ((X << 23) | (X >> 41));
        }
        #endregion

        #region Constant Tables
        internal static readonly ulong[] K64 =
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
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
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
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
