using System;

/// Based on the Bouncy Castle implementation: <a href="http://bouncycastle.org/">
/// Serpent is a 128-bit 32-round block cipher with variable key lengths,
/// including 128, 192 and 256 bit keys conjectured to be at least as
/// secure as three-key triple-DES.
/// Serpent was designed by Ross Anderson, Eli Biham and Lars Knudsen as a
/// candidate algorithm for the NIST AES Quest.>
/// For full details see the <a href="http://www.cl.cam.ac.uk/~rja14/serpent.html">The Serpent home page</a>
/// The sboxes below are based on the work of Brian Gladman and
/// Sam Simpson, whose original notice appears below.
/// For further details see: <a href="http://fp.gladman.plus.com/cryptography_technology/serpent/">
/// 
///  Permission is hereby granted, free of charge, to any person obtaining
///  a copy of this software and associated documentation files (the
///  "Software"), to deal in the Software without restriction, including
///  without limitation the rights to use, copy, modify, merge, publish,
///  distribute, sublicense, and/or sell copies of the Software, and to
///  permit persons to whom the Software is furnished to do so, subject to
///  the following conditions:
///  
///  The above copyright notice and this permission notice shall be
///  included in all copies or substantial portions of the Software.
///  
///  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
///  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
///  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
///  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
///  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
///  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
///  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

///  An implementation of the Serpent block cipher
///  Written by John Underhill, September 12, 2014

namespace VTDev.Projects.CEX.CryptoGraphic
{
    public class Serpent : IDisposable
    {
        #region Constants
        private const Int32 BLOCK_SIZE = 16;
        private const Int32 ROUNDS = 32;
        private const Int32 PHI = unchecked((int)0x9E3779B9);
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private byte[] _Key = new byte[0];
        private bool _isEncryption;
        private Int32[] _expandedKey;
        private Int32[] _registers = new Int32[4];
        #endregion

        #region Properties
        /// <summary>
        /// Unit block size of internal cipher.
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Used as encryptor, false for decryption. 
        /// Value set in class constructor.
        /// </summary>
        public bool IsEncryption
        {
            get { return _isEncryption; }
            private set { _isEncryption = value; }
        }

        /// <summary>
        /// Encryption Key, read only
        /// </summary>
        public byte[] Key
        {
            get { return _Key; }
            private set { _Key = value; }
        }

        /// <summary>
        /// Available Encryption Key Sizes in bits
        /// </summary>
        public Int32[] KeySizes
        {
            get { return new Int32[] { 128, 192, 256 }; }
        }
        #endregion

        #region Constructor
        public Serpent()
        {
        }
        #endregion

        #region Public Methods
        public void Init(bool Encryption, byte[] Key)
        {
            if (Key == null)
                throw new ArgumentOutOfRangeException("Invalid key! Key can not be null.");
            if (Key.Length != 16 && Key.Length != 24 && Key.Length != 32)
                throw new ArgumentOutOfRangeException("Invalid key size! Valid sizes are 16, 24, and 32 bytes.");

            this.IsEncryption = Encryption;
            this.Key = Key;
            _expandedKey = ExpandKey(Key);
        }

        /// <summary>
        /// Decrypt one block of ciphertext
        /// </summary>
        /// <param name="Input">in the array containing the input data</param>
        /// <param name="InputOffset">inOff offset into the in array the data starts at</param>
        /// <param name="Output">out the array the output data will be copied into</param>
        /// <param name="OutputOffset">outOff the offset into the out array the output will start at</param>
        public void DecryptBlock(byte[] Input, int InputOffset, byte[] Output, int OutputOffset)
        {
            _registers[3] = _expandedKey[131] ^ BytesToWord(Input, InputOffset);
            _registers[2] = _expandedKey[130] ^ BytesToWord(Input, InputOffset + 4);
            _registers[1] = _expandedKey[129] ^ BytesToWord(Input, InputOffset + 8);
            _registers[0] = _expandedKey[128] ^ BytesToWord(Input, InputOffset + 12);

            Ib7(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[124]; _registers[1] ^= _expandedKey[125]; _registers[2] ^= _expandedKey[126]; _registers[3] ^= _expandedKey[127];
            InverseLT(); Ib6(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[120]; _registers[1] ^= _expandedKey[121]; _registers[2] ^= _expandedKey[122]; _registers[3] ^= _expandedKey[123];
            InverseLT(); Ib5(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[116]; _registers[1] ^= _expandedKey[117]; _registers[2] ^= _expandedKey[118]; _registers[3] ^= _expandedKey[119];
            InverseLT(); Ib4(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[112]; _registers[1] ^= _expandedKey[113]; _registers[2] ^= _expandedKey[114]; _registers[3] ^= _expandedKey[115];
            InverseLT(); Ib3(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[108]; _registers[1] ^= _expandedKey[109]; _registers[2] ^= _expandedKey[110]; _registers[3] ^= _expandedKey[111];
            InverseLT(); Ib2(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[104]; _registers[1] ^= _expandedKey[105]; _registers[2] ^= _expandedKey[106]; _registers[3] ^= _expandedKey[107];
            InverseLT(); Ib1(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[100]; _registers[1] ^= _expandedKey[101]; _registers[2] ^= _expandedKey[102]; _registers[3] ^= _expandedKey[103];
            InverseLT(); Ib0(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[96]; _registers[1] ^= _expandedKey[97]; _registers[2] ^= _expandedKey[98]; _registers[3] ^= _expandedKey[99];
            InverseLT(); Ib7(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[92]; _registers[1] ^= _expandedKey[93]; _registers[2] ^= _expandedKey[94]; _registers[3] ^= _expandedKey[95];
            InverseLT(); Ib6(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[88]; _registers[1] ^= _expandedKey[89]; _registers[2] ^= _expandedKey[90]; _registers[3] ^= _expandedKey[91];
            InverseLT(); Ib5(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[84]; _registers[1] ^= _expandedKey[85]; _registers[2] ^= _expandedKey[86]; _registers[3] ^= _expandedKey[87];
            InverseLT(); Ib4(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[80]; _registers[1] ^= _expandedKey[81]; _registers[2] ^= _expandedKey[82]; _registers[3] ^= _expandedKey[83];
            InverseLT(); Ib3(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[76]; _registers[1] ^= _expandedKey[77]; _registers[2] ^= _expandedKey[78]; _registers[3] ^= _expandedKey[79];
            InverseLT(); Ib2(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[72]; _registers[1] ^= _expandedKey[73]; _registers[2] ^= _expandedKey[74]; _registers[3] ^= _expandedKey[75];
            InverseLT(); Ib1(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[68]; _registers[1] ^= _expandedKey[69]; _registers[2] ^= _expandedKey[70]; _registers[3] ^= _expandedKey[71];
            InverseLT(); Ib0(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[64]; _registers[1] ^= _expandedKey[65]; _registers[2] ^= _expandedKey[66]; _registers[3] ^= _expandedKey[67];
            InverseLT(); Ib7(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[60]; _registers[1] ^= _expandedKey[61]; _registers[2] ^= _expandedKey[62]; _registers[3] ^= _expandedKey[63];
            InverseLT(); Ib6(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[56]; _registers[1] ^= _expandedKey[57]; _registers[2] ^= _expandedKey[58]; _registers[3] ^= _expandedKey[59];
            InverseLT(); Ib5(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[52]; _registers[1] ^= _expandedKey[53]; _registers[2] ^= _expandedKey[54]; _registers[3] ^= _expandedKey[55];
            InverseLT(); Ib4(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[48]; _registers[1] ^= _expandedKey[49]; _registers[2] ^= _expandedKey[50]; _registers[3] ^= _expandedKey[51];
            InverseLT(); Ib3(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[44]; _registers[1] ^= _expandedKey[45]; _registers[2] ^= _expandedKey[46]; _registers[3] ^= _expandedKey[47];
            InverseLT(); Ib2(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[40]; _registers[1] ^= _expandedKey[41]; _registers[2] ^= _expandedKey[42]; _registers[3] ^= _expandedKey[43];
            InverseLT(); Ib1(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[36]; _registers[1] ^= _expandedKey[37]; _registers[2] ^= _expandedKey[38]; _registers[3] ^= _expandedKey[39];
            InverseLT(); Ib0(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[32]; _registers[1] ^= _expandedKey[33]; _registers[2] ^= _expandedKey[34]; _registers[3] ^= _expandedKey[35];
            InverseLT(); Ib7(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[28]; _registers[1] ^= _expandedKey[29]; _registers[2] ^= _expandedKey[30]; _registers[3] ^= _expandedKey[31];
            InverseLT(); Ib6(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[24]; _registers[1] ^= _expandedKey[25]; _registers[2] ^= _expandedKey[26]; _registers[3] ^= _expandedKey[27];
            InverseLT(); Ib5(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[20]; _registers[1] ^= _expandedKey[21]; _registers[2] ^= _expandedKey[22]; _registers[3] ^= _expandedKey[23];
            InverseLT(); Ib4(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[16]; _registers[1] ^= _expandedKey[17]; _registers[2] ^= _expandedKey[18]; _registers[3] ^= _expandedKey[19];
            InverseLT(); Ib3(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[12]; _registers[1] ^= _expandedKey[13]; _registers[2] ^= _expandedKey[14]; _registers[3] ^= _expandedKey[15];
            InverseLT(); Ib2(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[8]; _registers[1] ^= _expandedKey[9]; _registers[2] ^= _expandedKey[10]; _registers[3] ^= _expandedKey[11];
            InverseLT(); Ib1(_registers[0], _registers[1], _registers[2], _registers[3]);
            _registers[0] ^= _expandedKey[4]; _registers[1] ^= _expandedKey[5]; _registers[2] ^= _expandedKey[6]; _registers[3] ^= _expandedKey[7];
            InverseLT(); Ib0(_registers[0], _registers[1], _registers[2], _registers[3]);

            WordToBytes(_registers[3] ^ _expandedKey[3], Output, OutputOffset);
            WordToBytes(_registers[2] ^ _expandedKey[2], Output, OutputOffset + 4);
            WordToBytes(_registers[1] ^ _expandedKey[1], Output, OutputOffset + 8);
            WordToBytes(_registers[0] ^ _expandedKey[0], Output, OutputOffset + 12);
        }

        /// <summary>
        /// Encrypt one block of plaintext
        /// </summary>
        /// <param name="Input">The input array containing the input data</param>
        /// <param name="InputOffset">offset into the in array the data starts at</param>
        /// <param name="Output">the array the output data will be copied into</param>
        /// <param name="OutputOffset">the offset into the out array the output will start at</param>
        public void EncryptBlock(byte[] Input, int InputOffset, byte[] Output, int OutputOffset)
        {
            _registers[3] = BytesToWord(Input, InputOffset);
            _registers[2] = BytesToWord(Input, InputOffset + 4);
            _registers[1] = BytesToWord(Input, InputOffset + 8);
            _registers[0] = BytesToWord(Input, InputOffset + 12);

            Sb0(_expandedKey[0] ^ _registers[0], _expandedKey[1] ^ _registers[1], _expandedKey[2] ^ _registers[2], _expandedKey[3] ^ _registers[3]); LT();
            Sb1(_expandedKey[4] ^ _registers[0], _expandedKey[5] ^ _registers[1], _expandedKey[6] ^ _registers[2], _expandedKey[7] ^ _registers[3]); LT();
            Sb2(_expandedKey[8] ^ _registers[0], _expandedKey[9] ^ _registers[1], _expandedKey[10] ^ _registers[2], _expandedKey[11] ^ _registers[3]); LT();
            Sb3(_expandedKey[12] ^ _registers[0], _expandedKey[13] ^ _registers[1], _expandedKey[14] ^ _registers[2], _expandedKey[15] ^ _registers[3]); LT();
            Sb4(_expandedKey[16] ^ _registers[0], _expandedKey[17] ^ _registers[1], _expandedKey[18] ^ _registers[2], _expandedKey[19] ^ _registers[3]); LT();
            Sb5(_expandedKey[20] ^ _registers[0], _expandedKey[21] ^ _registers[1], _expandedKey[22] ^ _registers[2], _expandedKey[23] ^ _registers[3]); LT();
            Sb6(_expandedKey[24] ^ _registers[0], _expandedKey[25] ^ _registers[1], _expandedKey[26] ^ _registers[2], _expandedKey[27] ^ _registers[3]); LT();
            Sb7(_expandedKey[28] ^ _registers[0], _expandedKey[29] ^ _registers[1], _expandedKey[30] ^ _registers[2], _expandedKey[31] ^ _registers[3]); LT();
            Sb0(_expandedKey[32] ^ _registers[0], _expandedKey[33] ^ _registers[1], _expandedKey[34] ^ _registers[2], _expandedKey[35] ^ _registers[3]); LT();
            Sb1(_expandedKey[36] ^ _registers[0], _expandedKey[37] ^ _registers[1], _expandedKey[38] ^ _registers[2], _expandedKey[39] ^ _registers[3]); LT();
            Sb2(_expandedKey[40] ^ _registers[0], _expandedKey[41] ^ _registers[1], _expandedKey[42] ^ _registers[2], _expandedKey[43] ^ _registers[3]); LT();
            Sb3(_expandedKey[44] ^ _registers[0], _expandedKey[45] ^ _registers[1], _expandedKey[46] ^ _registers[2], _expandedKey[47] ^ _registers[3]); LT();
            Sb4(_expandedKey[48] ^ _registers[0], _expandedKey[49] ^ _registers[1], _expandedKey[50] ^ _registers[2], _expandedKey[51] ^ _registers[3]); LT();
            Sb5(_expandedKey[52] ^ _registers[0], _expandedKey[53] ^ _registers[1], _expandedKey[54] ^ _registers[2], _expandedKey[55] ^ _registers[3]); LT();
            Sb6(_expandedKey[56] ^ _registers[0], _expandedKey[57] ^ _registers[1], _expandedKey[58] ^ _registers[2], _expandedKey[59] ^ _registers[3]); LT();
            Sb7(_expandedKey[60] ^ _registers[0], _expandedKey[61] ^ _registers[1], _expandedKey[62] ^ _registers[2], _expandedKey[63] ^ _registers[3]); LT();
            Sb0(_expandedKey[64] ^ _registers[0], _expandedKey[65] ^ _registers[1], _expandedKey[66] ^ _registers[2], _expandedKey[67] ^ _registers[3]); LT();
            Sb1(_expandedKey[68] ^ _registers[0], _expandedKey[69] ^ _registers[1], _expandedKey[70] ^ _registers[2], _expandedKey[71] ^ _registers[3]); LT();
            Sb2(_expandedKey[72] ^ _registers[0], _expandedKey[73] ^ _registers[1], _expandedKey[74] ^ _registers[2], _expandedKey[75] ^ _registers[3]); LT();
            Sb3(_expandedKey[76] ^ _registers[0], _expandedKey[77] ^ _registers[1], _expandedKey[78] ^ _registers[2], _expandedKey[79] ^ _registers[3]); LT();
            Sb4(_expandedKey[80] ^ _registers[0], _expandedKey[81] ^ _registers[1], _expandedKey[82] ^ _registers[2], _expandedKey[83] ^ _registers[3]); LT();
            Sb5(_expandedKey[84] ^ _registers[0], _expandedKey[85] ^ _registers[1], _expandedKey[86] ^ _registers[2], _expandedKey[87] ^ _registers[3]); LT();
            Sb6(_expandedKey[88] ^ _registers[0], _expandedKey[89] ^ _registers[1], _expandedKey[90] ^ _registers[2], _expandedKey[91] ^ _registers[3]); LT();
            Sb7(_expandedKey[92] ^ _registers[0], _expandedKey[93] ^ _registers[1], _expandedKey[94] ^ _registers[2], _expandedKey[95] ^ _registers[3]); LT();
            Sb0(_expandedKey[96] ^ _registers[0], _expandedKey[97] ^ _registers[1], _expandedKey[98] ^ _registers[2], _expandedKey[99] ^ _registers[3]); LT();
            Sb1(_expandedKey[100] ^ _registers[0], _expandedKey[101] ^ _registers[1], _expandedKey[102] ^ _registers[2], _expandedKey[103] ^ _registers[3]); LT();
            Sb2(_expandedKey[104] ^ _registers[0], _expandedKey[105] ^ _registers[1], _expandedKey[106] ^ _registers[2], _expandedKey[107] ^ _registers[3]); LT();
            Sb3(_expandedKey[108] ^ _registers[0], _expandedKey[109] ^ _registers[1], _expandedKey[110] ^ _registers[2], _expandedKey[111] ^ _registers[3]); LT();
            Sb4(_expandedKey[112] ^ _registers[0], _expandedKey[113] ^ _registers[1], _expandedKey[114] ^ _registers[2], _expandedKey[115] ^ _registers[3]); LT();
            Sb5(_expandedKey[116] ^ _registers[0], _expandedKey[117] ^ _registers[1], _expandedKey[118] ^ _registers[2], _expandedKey[119] ^ _registers[3]); LT();
            Sb6(_expandedKey[120] ^ _registers[0], _expandedKey[121] ^ _registers[1], _expandedKey[122] ^ _registers[2], _expandedKey[123] ^ _registers[3]); LT();
            Sb7(_expandedKey[124] ^ _registers[0], _expandedKey[125] ^ _registers[1], _expandedKey[126] ^ _registers[2], _expandedKey[127] ^ _registers[3]);

            WordToBytes(_expandedKey[131] ^ _registers[3], Output, OutputOffset);
            WordToBytes(_expandedKey[130] ^ _registers[2], Output, OutputOffset + 4);
            WordToBytes(_expandedKey[129] ^ _registers[1], Output, OutputOffset + 8);
            WordToBytes(_expandedKey[128] ^ _registers[0], Output, OutputOffset + 12);
        }
        #endregion

        #region Helpers
        private int BytesToWord(byte[] src, int srcOff)
        {
            return (((src[srcOff] & 0xff) << 24) | ((src[srcOff + 1] & 0xff) << 16) |
            ((src[srcOff + 2] & 0xff) << 8) | ((src[srcOff + 3] & 0xff)));
        }

        /// <summary>
        /// Expand a user-supplied key material into a session key
        /// </summary>
        /// <param name="Key">The user-key bytes (multiples of 4) to use</param>
        /// <returns>Expanded key</returns>
        private int[] ExpandKey(byte[] Key)
        {
            // create the temp array as 2k
            int[] kPad = new int[16];
            int offset = 0;
            int length = 0;

            // step 1: copy key to temp array
            for (offset = Key.Length - 4; offset > 0; offset -= 4)
                kPad[length++] = BytesToWord(Key, offset);
            // copy 8th
            if (offset == 0)
            {
                kPad[length++] = BytesToWord(Key, 0);

                if (length < 8)
                    kPad[length] = 1;
            }
            else
            {
                throw new ArgumentException("key must be a multiple of 4 bytes");
            }

            // step 2: calculate rounds
            // expand the padded key up to 33 x 128 bits of key material
            int amount = (ROUNDS + 1) * 4;
            int[] Wk = new int[amount];

            // step 3: rotate k into next w(k) ints
            // compute w0 to w7 from w-8 to w-1
            for (int i = 8; i < 16; i++)
                kPad[i] = RotateLeft(kPad[i - 8] ^ kPad[i - 5] ^ kPad[i - 3] ^ kPad[i - 1] ^ PHI ^ (i - 8), 11);

            // copy kpad to working key
            Array.Copy(kPad, 8, Wk, 0, 8);

            // step 4: calculate remainder of rounds with rotational primitive
            for (int i = 8; i < amount; i++)
                Wk[i] = RotateLeft(Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i, 11);

            // create the working keys by processing with the Sbox and IP
            int ct = 0;
            int pos = 0;
            // sbox mix
            while (ct < 128)
            {
                Sb3(Wk[ct++], Wk[ct++], Wk[ct++], Wk[ct++]);
                Buffer.BlockCopy(_registers, 0, Wk, pos, 16); pos += 16;
                Sb2(Wk[ct++], Wk[ct++], Wk[ct++], Wk[ct++]);
                Buffer.BlockCopy(_registers, 0, Wk, pos, 16); pos += 16;
                Sb1(Wk[ct++], Wk[ct++], Wk[ct++], Wk[ct++]);
                Buffer.BlockCopy(_registers, 0, Wk, pos, 16); pos += 16;
                Sb0(Wk[ct++], Wk[ct++], Wk[ct++], Wk[ct++]);
                Buffer.BlockCopy(_registers, 0, Wk, pos, 16); pos += 16;
                Sb7(Wk[ct++], Wk[ct++], Wk[ct++], Wk[ct++]);
                Buffer.BlockCopy(_registers, 0, Wk, pos, 16); pos += 16;
                Sb6(Wk[ct++], Wk[ct++], Wk[ct++], Wk[ct++]);
                Buffer.BlockCopy(_registers, 0, Wk, pos, 16); pos += 16;
                Sb5(Wk[ct++], Wk[ct++], Wk[ct++], Wk[ct++]);
                Buffer.BlockCopy(_registers, 0, Wk, pos, 16); pos += 16;
                Sb4(Wk[ct++], Wk[ct++], Wk[ct++], Wk[ct++]);
                Buffer.BlockCopy(_registers, 0, Wk, pos, 16); pos += 16;
            }

            Sb3(Wk[ct++], Wk[ct++], Wk[ct++], Wk[ct++]);
            Buffer.BlockCopy(_registers, 0, Wk, pos, 16);

            return Wk;
        }

        private int RotateLeft(int x, int bits)
        {
            return ((x << bits) | (int)((uint)x >> (32 - bits)));
        }

        private int RotateRight(int x, int bits)
        {
            return ((int)((uint)x >> bits) | (x << (32 - bits)));
        }

        private void WordToBytes(int word, byte[] dst, int dstOff)
        {
            dst[dstOff + 3] = (byte)(word);
            dst[dstOff + 2] = (byte)((uint)word >> 8);
            dst[dstOff + 1] = (byte)((uint)word >> 16);
            dst[dstOff] = (byte)((uint)word >> 24);
        }
        #endregion

        #region SBox Calculations
        private void Sb0(int a, int b, int c, int d)
        {
            int t1 = a ^ d;
            int t3 = c ^ t1;
            int t4 = b ^ t3;
            _registers[3] = (a & d) ^ t4;
            int t7 = a ^ (b & t1);
            _registers[2] = t4 ^ (c | t7);
            int t12 = _registers[3] & (t3 ^ t7);
            _registers[1] = (~t3) ^ t12;
            _registers[0] = t12 ^ (~t7);
        }

        /// <summary>
        /// InvSO - {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 } - 15 terms.
        /// </summary>
        private void Ib0(int a, int b, int c, int d)
        {
            int t1 = ~a;
            int t2 = a ^ b;
            int t4 = d ^ (t1 | t2);
            int t5 = c ^ t4;
            _registers[2] = t2 ^ t5;
            int t8 = t1 ^ (d & t2);
            _registers[1] = t4 ^ (_registers[2] & t8);
            _registers[3] = (a & t4) ^ (t5 | _registers[1]);
            _registers[0] = _registers[3] ^ (t5 ^ t8);
        }

        /// <summary>
        /// S1 - {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 } - 14 terms
        /// </summary>
        private void Sb1(int a, int b, int c, int d)
        {
            int t2 = b ^ (~a);
            int t5 = c ^ (a | t2);
            _registers[2] = d ^ t5;
            int t7 = b ^ (d | t2);
            int t8 = t2 ^ _registers[2];
            _registers[3] = t8 ^ (t5 & t7);
            int t11 = t5 ^ t7;
            _registers[1] = _registers[3] ^ t11;
            _registers[0] = t5 ^ (t8 & t11);
        }

        /// <summary>
        /// InvS1 - { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 } - 14 steps
        /// </summary>
        private void Ib1(int a, int b, int c, int d)
        {
            int t1 = b ^ d;
            int t3 = a ^ (b & t1);
            int t4 = t1 ^ t3;
            _registers[3] = c ^ t4;
            int t7 = b ^ (t1 & t3);
            int t8 = _registers[3] | t7;
            _registers[1] = t3 ^ t8;
            int t10 = ~_registers[1];
            int t11 = _registers[3] ^ t7;
            _registers[0] = t10 ^ t11;
            _registers[2] = t4 ^ (t10 | t11);
        }

        /// <summary>
        /// S2 - { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 } - 16 terms
        /// </summary>
        private void Sb2(int a, int b, int c, int d)
        {
            int t1 = ~a;
            int t2 = b ^ d;
            int t3 = c & t1;
            _registers[0] = t2 ^ t3;
            int t5 = c ^ t1;
            int t6 = c ^ _registers[0];
            int t7 = b & t6;
            _registers[3] = t5 ^ t7;
            _registers[2] = a ^ ((d | t7) & (_registers[0] | t5));
            _registers[1] = (t2 ^ _registers[3]) ^ (_registers[2] ^ (d | t1));
        }

        /// <summary>
        /// InvS2 - {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 } - 16 steps
        /// </summary>
        private void Ib2(int a, int b, int c, int d)
        {
            int t1 = b ^ d;
            int t2 = ~t1;
            int t3 = a ^ c;
            int t4 = c ^ t1;
            int t5 = b & t4;
            _registers[0] = t3 ^ t5;
            int t7 = a | t2;
            int t8 = d ^ t7;
            int t9 = t3 | t8;
            _registers[3] = t1 ^ t9;
            int t11 = ~t4;
            int t12 = _registers[0] | _registers[3];
            _registers[1] = t11 ^ t12;
            _registers[2] = (d & t11) ^ (t3 ^ t12);
        }

        /// <summary>
        /// S3 - { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 } - 16 terms
        /// </summary>
        private void Sb3(int a, int b, int c, int d)
        {
            int t1 = a ^ b;
            int t2 = a & c;
            int t3 = a | d;
            int t4 = c ^ d;
            int t5 = t1 & t3;
            int t6 = t2 | t5;
            _registers[2] = t4 ^ t6;
            int t8 = b ^ t3;
            int t9 = t6 ^ t8;
            int t10 = t4 & t9;
            _registers[0] = t1 ^ t10;
            int t12 = _registers[2] & _registers[0];
            _registers[1] = t9 ^ t12;
            _registers[3] = (b | d) ^ (t4 ^ t12);
        }

        /// <summary>
        /// InvS3 - { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 } - 15 terms
        /// </summary>
        private void Ib3(int a, int b, int c, int d)
        {
            int t1 = a | b;
            int t2 = b ^ c;
            int t3 = b & t2;
            int t4 = a ^ t3;
            int t5 = c ^ t4;
            int t6 = d | t4;
            _registers[0] = t2 ^ t6;
            int t8 = t2 | t6;
            int t9 = d ^ t8;
            _registers[2] = t5 ^ t9;
            int t11 = t1 ^ t9;
            int t12 = _registers[0] & t11;
            _registers[3] = t4 ^ t12;
            _registers[1] = _registers[3] ^ (_registers[0] ^ t11);
        }

        /// <summary>
        /// S4 - { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 } - 15 terms
        /// </summary>
        private void Sb4(int a, int b, int c, int d)
        {
            int t1 = a ^ d;
            int t2 = d & t1;
            int t3 = c ^ t2;
            int t4 = b | t3;
            _registers[3] = t1 ^ t4;
            int t6 = ~b;
            int t7 = t1 | t6;
            _registers[0] = t3 ^ t7;
            int t9 = a & _registers[0];
            int t10 = t1 ^ t6;
            int t11 = t4 & t10;
            _registers[2] = t9 ^ t11;
            _registers[1] = (a ^ t3) ^ (t10 & _registers[2]);
        }

        /// <summary>
        /// InvS4 - { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 } - 15 terms
        /// </summary>
        private void Ib4(int a, int b, int c, int d)
        {
            int t1 = c | d;
            int t2 = a & t1;
            int t3 = b ^ t2;
            int t4 = a & t3;
            int t5 = c ^ t4;
            _registers[1] = d ^ t5;
            int t7 = ~a;
            int t8 = t5 & _registers[1];
            _registers[3] = t3 ^ t8;
            int t10 = _registers[1] | t7;
            int t11 = d ^ t10;
            _registers[0] = _registers[3] ^ t11;
            _registers[2] = (t3 & t11) ^ (_registers[1] ^ t7);
        }

        /// <summary>
        /// S5 - {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 } - 16 terms
        /// </summary>
        private void Sb5(int a, int b, int c, int d)
        {
            int t1 = ~a;
            int t2 = a ^ b;
            int t3 = a ^ d;
            int t4 = c ^ t1;
            int t5 = t2 | t3;
            _registers[0] = t4 ^ t5;
            int t7 = d & _registers[0];
            int t8 = t2 ^ _registers[0];
            _registers[1] = t7 ^ t8;
            int t10 = t1 | _registers[0];
            int t11 = t2 | t7;
            int t12 = t3 ^ t10;
            _registers[2] = t11 ^ t12;
            _registers[3] = (b ^ t7) ^ (_registers[1] & t12);
        }

        /// <summary>
        /// InvS5 - { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 } - 16 terms
        /// </summary>
        private void Ib5(int a, int b, int c, int d)
        {
            int t1 = ~c;
            int t2 = b & t1;
            int t3 = d ^ t2;
            int t4 = a & t3;
            int t5 = b ^ t1;
            _registers[3] = t4 ^ t5;
            int t7 = b | _registers[3];
            int t8 = a & t7;
            _registers[1] = t3 ^ t8;
            int t10 = a | d;
            int t11 = t1 ^ t7;
            _registers[0] = t10 ^ t11;
            _registers[2] = (b & t10) ^ (t4 | (a ^ c));
        }

        /// <summary>
        /// S6 - { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 } - 15 terms
        /// </summary>
        private void Sb6(int a, int b, int c, int d)
        {
            int t1 = ~a;
            int t2 = a ^ d;
            int t3 = b ^ t2;
            int t4 = t1 | t2;
            int t5 = c ^ t4;
            _registers[1] = b ^ t5;
            int t7 = t2 | _registers[1];
            int t8 = d ^ t7;
            int t9 = t5 & t8;
            _registers[2] = t3 ^ t9;
            int t11 = t5 ^ t8;
            _registers[0] = _registers[2] ^ t11;
            _registers[3] = (~t5) ^ (t3 & t11);
        }

        /// <summary>
        /// InvS6 - {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 } - 15 terms
        /// </summary>
        private void Ib6(int a, int b, int c, int d)
        {
            int t1 = ~a;
            int t2 = a ^ b;
            int t3 = c ^ t2;
            int t4 = c | t1;
            int t5 = d ^ t4;
            _registers[1] = t3 ^ t5;
            int t7 = t3 & t5;
            int t8 = t2 ^ t7;
            int t9 = b | t8;
            _registers[3] = t5 ^ t9;
            int t11 = b | _registers[3];
            _registers[0] = t8 ^ t11;
            _registers[2] = (d & t1) ^ (t3 ^ t11);
        }

        /// <summary>
        /// S7 - { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } - 16 terms
        /// </summary>
        private void Sb7(int a, int b, int c, int d)
        {
            int t1 = b ^ c;
            int t2 = c & t1;
            int t3 = d ^ t2;
            int t4 = a ^ t3;
            int t5 = d | t1;
            int t6 = t4 & t5;
            _registers[1] = b ^ t6;
            int t8 = t3 | _registers[1];
            int t9 = a & t4;
            _registers[3] = t1 ^ t9;
            int t11 = t4 ^ t8;
            int t12 = _registers[3] & t11;
            _registers[2] = t3 ^ t12;
            _registers[0] = (~t11) ^ (_registers[3] & _registers[2]);
        }

        /// <summary>
        /// InvS7 - { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 } - 17 terms
        /// </summary>
        private void Ib7(int a, int b, int c, int d)
        {
            int t3 = c | (a & b);
            int t4 = d & (a | b);
            _registers[3] = t3 ^ t4;
            int t6 = ~d;
            int t7 = b ^ t4;
            int t9 = t7 | (_registers[3] ^ t6);
            _registers[1] = a ^ t9;
            _registers[0] = (c ^ t7) ^ (d | _registers[1]);
            _registers[2] = (t3 ^ _registers[1]) ^ (_registers[0] ^ (a & _registers[3]));
        }

        /// <summary>
        /// Apply the linear transformation to the register set
        /// </summary>
        private void LT()
        {
            int x0 = RotateLeft(_registers[0], 13);
            int x2 = RotateLeft(_registers[2], 3);
            int x1 = _registers[1] ^ x0 ^ x2;
            int x3 = _registers[3] ^ x2 ^ x0 << 3;

            _registers[1] = RotateLeft(x1, 1);
            _registers[3] = RotateLeft(x3, 7);
            _registers[0] = RotateLeft(x0 ^ _registers[1] ^ _registers[3], 5);
            _registers[2] = RotateLeft(x2 ^ _registers[3] ^ (_registers[1] << 7), 22);
        }

        /// <summary>
        /// Apply the inverse of the linear transformation to the register set
        /// </summary>
        private void InverseLT()
        {
            int x2 = RotateRight(_registers[2], 22) ^ _registers[3] ^ (_registers[1] << 7);
            int x0 = RotateRight(_registers[0], 5) ^ _registers[1] ^ _registers[3];
            int x3 = RotateRight(_registers[3], 7);
            int x1 = RotateRight(_registers[1], 1);
            _registers[3] = x3 ^ x2 ^ x0 << 3;
            _registers[1] = x1 ^ x0 ^ x2;
            _registers[2] = RotateRight(x2, 3);
            _registers[0] = RotateRight(x0, 13);
        }
        #endregion

        #region IDispose
        public void Dispose()
        {
            Dispose(true);
        }

        void IDisposable.Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    if (_expandedKey != null)
                        Array.Clear(_expandedKey, 0, _expandedKey.Length);
                    if (_registers != null)
                        Array.Clear(_registers, 0, _registers.Length);
                }
                _isDisposed = true;
            }
        }
        #endregion
    }
}
