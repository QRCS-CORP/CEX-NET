using System;
using System.Security.Cryptography;
using VTDev.Projects.CEX.CryptoGraphic.Helpers;

namespace VTDev.Projects.CEX.Tests
{
    /// <summary>
    /// Serpent implementation key equivelncy test.
    /// My version vs Bouncy Castle.
    /// </summary>
    class KeyTest
    {
        internal bool Test()
        {
            try
            {
                TestKeys();

                return true;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                Console.WriteLine("KeyTest Failed! " + message);

                return false;
            }
        }

        private void TestKeys()
        {
            for (int i = 0; i < 10; i++)
                CompareKeys();
        }

        private void CompareKeys()
        {
            byte[] key = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                rng.GetBytes(key);

            SerpentA a = new SerpentA();
            int[] key1 = a.GetKey(key);
            SerpentB b = new SerpentB();
            int[] key2 = b.GetKey(key);

            if (Compare.AreEqual(key1, key2) == false)
                throw new Exception("Key test failure: Keys are not equal!");
        }
    }

    class SerpentA
    {
        private Int32[] _registers = new Int32[4];
        private readonly int ROUNDS = 32;
        private readonly int PHI = unchecked((int)0x9E3779B9);

        public int[] GetKey(byte[] Key)
        {
            return ExpandKey(Key);
        }

        private int RotateLeft(int x, int bits)
        {
            return ((x << bits) | (int)((uint)x >> (32 - bits)));
        }

        private int BytesToWord(byte[] src, int srcOff)
        {
            return (((src[srcOff] & 0xff) << 24) | ((src[srcOff + 1] & 0xff) << 16) |
            ((src[srcOff + 2] & 0xff) << 8) | ((src[srcOff + 3] & 0xff)));
        }

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

        #region Serpent SBox Calculations
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
        #endregion

    }

    class SerpentB
    {
        public int[] GetKey(byte[] Key)
        {
            return MakeWorkingKey(Key);
        }

        #region Bouncy Castle
        private int X0, X1, X2, X3;
        private readonly int ROUNDS = 32;
        private readonly int PHI = unchecked((int)0x9E3779B9);       // (Sqrt(5) - 1) * 2**31

        private int RotateLeft(int x, int bits)
        {
            return ((x << bits) | (int)((uint)x >> (32 - bits)));
        }

        private int BytesToWord(byte[] src, int srcOff)
        {
            return (((src[srcOff] & 0xff) << 24) | ((src[srcOff + 1] & 0xff) << 16) |
            ((src[srcOff + 2] & 0xff) << 8) | ((src[srcOff + 3] & 0xff)));
        }

        private int[] MakeWorkingKey(byte[] key)
        {
            //
            // pad key to 256 bits
            //
            int[] kPad = new int[16];
            int off = 0;
            int length = 0;

            for (off = key.Length - 4; off > 0; off -= 4)
            {
                kPad[length++] = BytesToWord(key, off);
            }

            if (off == 0)
            {
                kPad[length++] = BytesToWord(key, 0);
                if (length < 8)
                {
                    kPad[length] = 1;
                }
            }
            else
            {
                throw new ArgumentException("key must be a multiple of 4 bytes");
            }

            //
            // expand the padded key up to 33 x 128 bits of key material
            //
            int amount = (ROUNDS + 1) * 4;
            int[] w = new int[amount];

            //
            // compute w0 to w7 from w-8 to w-1
            //
            for (int i = 8; i < 16; i++)
            {
                kPad[i] = RotateLeft(kPad[i - 8] ^ kPad[i - 5] ^ kPad[i - 3] ^ kPad[i - 1] ^ PHI ^ (i - 8), 11);
            }

            Array.Copy(kPad, 8, w, 0, 8);

            //
            // compute w8 to w136
            //
            for (int i = 8; i < amount; i++)
            {
                w[i] = RotateLeft(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i, 11);
            }

            //
            // create the working keys by processing w with the Sbox and IP
            //
            Sb3(w[0], w[1], w[2], w[3]);
            w[0] = X0; w[1] = X1; w[2] = X2; w[3] = X3;
            Sb2(w[4], w[5], w[6], w[7]);
            w[4] = X0; w[5] = X1; w[6] = X2; w[7] = X3;
            Sb1(w[8], w[9], w[10], w[11]);
            w[8] = X0; w[9] = X1; w[10] = X2; w[11] = X3;
            Sb0(w[12], w[13], w[14], w[15]);
            w[12] = X0; w[13] = X1; w[14] = X2; w[15] = X3;
            Sb7(w[16], w[17], w[18], w[19]);
            w[16] = X0; w[17] = X1; w[18] = X2; w[19] = X3;
            Sb6(w[20], w[21], w[22], w[23]);
            w[20] = X0; w[21] = X1; w[22] = X2; w[23] = X3;
            Sb5(w[24], w[25], w[26], w[27]);
            w[24] = X0; w[25] = X1; w[26] = X2; w[27] = X3;
            Sb4(w[28], w[29], w[30], w[31]);
            w[28] = X0; w[29] = X1; w[30] = X2; w[31] = X3;
            Sb3(w[32], w[33], w[34], w[35]);
            w[32] = X0; w[33] = X1; w[34] = X2; w[35] = X3;
            Sb2(w[36], w[37], w[38], w[39]);
            w[36] = X0; w[37] = X1; w[38] = X2; w[39] = X3;
            Sb1(w[40], w[41], w[42], w[43]);
            w[40] = X0; w[41] = X1; w[42] = X2; w[43] = X3;
            Sb0(w[44], w[45], w[46], w[47]);
            w[44] = X0; w[45] = X1; w[46] = X2; w[47] = X3;
            Sb7(w[48], w[49], w[50], w[51]);
            w[48] = X0; w[49] = X1; w[50] = X2; w[51] = X3;
            Sb6(w[52], w[53], w[54], w[55]);
            w[52] = X0; w[53] = X1; w[54] = X2; w[55] = X3;
            Sb5(w[56], w[57], w[58], w[59]);
            w[56] = X0; w[57] = X1; w[58] = X2; w[59] = X3;
            Sb4(w[60], w[61], w[62], w[63]);
            w[60] = X0; w[61] = X1; w[62] = X2; w[63] = X3;
            Sb3(w[64], w[65], w[66], w[67]);
            w[64] = X0; w[65] = X1; w[66] = X2; w[67] = X3;
            Sb2(w[68], w[69], w[70], w[71]);
            w[68] = X0; w[69] = X1; w[70] = X2; w[71] = X3;
            Sb1(w[72], w[73], w[74], w[75]);
            w[72] = X0; w[73] = X1; w[74] = X2; w[75] = X3;
            Sb0(w[76], w[77], w[78], w[79]);
            w[76] = X0; w[77] = X1; w[78] = X2; w[79] = X3;
            Sb7(w[80], w[81], w[82], w[83]);
            w[80] = X0; w[81] = X1; w[82] = X2; w[83] = X3;
            Sb6(w[84], w[85], w[86], w[87]);
            w[84] = X0; w[85] = X1; w[86] = X2; w[87] = X3;
            Sb5(w[88], w[89], w[90], w[91]);
            w[88] = X0; w[89] = X1; w[90] = X2; w[91] = X3;
            Sb4(w[92], w[93], w[94], w[95]);
            w[92] = X0; w[93] = X1; w[94] = X2; w[95] = X3;
            Sb3(w[96], w[97], w[98], w[99]);
            w[96] = X0; w[97] = X1; w[98] = X2; w[99] = X3;
            Sb2(w[100], w[101], w[102], w[103]);
            w[100] = X0; w[101] = X1; w[102] = X2; w[103] = X3;
            Sb1(w[104], w[105], w[106], w[107]);
            w[104] = X0; w[105] = X1; w[106] = X2; w[107] = X3;
            Sb0(w[108], w[109], w[110], w[111]);
            w[108] = X0; w[109] = X1; w[110] = X2; w[111] = X3;
            Sb7(w[112], w[113], w[114], w[115]);
            w[112] = X0; w[113] = X1; w[114] = X2; w[115] = X3;
            Sb6(w[116], w[117], w[118], w[119]);
            w[116] = X0; w[117] = X1; w[118] = X2; w[119] = X3;
            Sb5(w[120], w[121], w[122], w[123]);
            w[120] = X0; w[121] = X1; w[122] = X2; w[123] = X3;
            Sb4(w[124], w[125], w[126], w[127]);
            w[124] = X0; w[125] = X1; w[126] = X2; w[127] = X3;
            Sb3(w[128], w[129], w[130], w[131]);
            w[128] = X0; w[129] = X1; w[130] = X2; w[131] = X3;

            return w;
        }

        #region Bouncy Castle SBox
        private void Sb0(int a, int b, int c, int d)
        {
            int t1 = a ^ d;
            int t3 = c ^ t1;
            int t4 = b ^ t3;
            X3 = (a & d) ^ t4;
            int t7 = a ^ (b & t1);
            X2 = t4 ^ (c | t7);
            int t12 = X3 & (t3 ^ t7);
            X1 = (~t3) ^ t12;
            X0 = t12 ^ (~t7);
        }

        private void Sb1(int a, int b, int c, int d)
        {
            int t2 = b ^ (~a);
            int t5 = c ^ (a | t2);
            X2 = d ^ t5;
            int t7 = b ^ (d | t2);
            int t8 = t2 ^ X2;
            X3 = t8 ^ (t5 & t7);
            int t11 = t5 ^ t7;
            X1 = X3 ^ t11;
            X0 = t5 ^ (t8 & t11);
        }

        /**
        * S2 - { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 } - 16 terms.
        */
        private void Sb2(int a, int b, int c, int d)
        {
            int t1 = ~a;
            int t2 = b ^ d;
            int t3 = c & t1;
            X0 = t2 ^ t3;
            int t5 = c ^ t1;
            int t6 = c ^ X0;
            int t7 = b & t6;
            X3 = t5 ^ t7;
            X2 = a ^ ((d | t7) & (X0 | t5));
            X1 = (t2 ^ X3) ^ (X2 ^ (d | t1));
        }

        /**
        * S3 - { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 } - 16 terms.
        */
        private void Sb3(int a, int b, int c, int d)
        {
            int t1 = a ^ b;
            int t2 = a & c;
            int t3 = a | d;
            int t4 = c ^ d;
            int t5 = t1 & t3;
            int t6 = t2 | t5;
            X2 = t4 ^ t6;
            int t8 = b ^ t3;
            int t9 = t6 ^ t8;
            int t10 = t4 & t9;
            X0 = t1 ^ t10;
            int t12 = X2 & X0;
            X1 = t9 ^ t12;
            X3 = (b | d) ^ (t4 ^ t12);
        }

        /**
        * S4 - { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 } - 15 terms.
        */
        private void Sb4(int a, int b, int c, int d)
        {
            int t1 = a ^ d;
            int t2 = d & t1;
            int t3 = c ^ t2;
            int t4 = b | t3;
            X3 = t1 ^ t4;
            int t6 = ~b;
            int t7 = t1 | t6;
            X0 = t3 ^ t7;
            int t9 = a & X0;
            int t10 = t1 ^ t6;
            int t11 = t4 & t10;
            X2 = t9 ^ t11;
            X1 = (a ^ t3) ^ (t10 & X2);
        }

        /**
        * S5 - {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 } - 16 terms.
        */
        private void Sb5(int a, int b, int c, int d)
        {
            int t1 = ~a;
            int t2 = a ^ b;
            int t3 = a ^ d;
            int t4 = c ^ t1;
            int t5 = t2 | t3;
            X0 = t4 ^ t5;
            int t7 = d & X0;
            int t8 = t2 ^ X0;
            X1 = t7 ^ t8;
            int t10 = t1 | X0;
            int t11 = t2 | t7;
            int t12 = t3 ^ t10;
            X2 = t11 ^ t12;
            X3 = (b ^ t7) ^ (X1 & t12);
        }

        /**
        * S6 - { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 } - 15 terms.
        */
        private void Sb6(int a, int b, int c, int d)
        {
            int t1 = ~a;
            int t2 = a ^ d;
            int t3 = b ^ t2;
            int t4 = t1 | t2;
            int t5 = c ^ t4;
            X1 = b ^ t5;
            int t7 = t2 | X1;
            int t8 = d ^ t7;
            int t9 = t5 & t8;
            X2 = t3 ^ t9;
            int t11 = t5 ^ t8;
            X0 = X2 ^ t11;
            X3 = (~t5) ^ (t3 & t11);
        }

        /**
        * S7 - { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } - 16 terms.
        */
        private void Sb7(int a, int b, int c, int d)
        {
            int t1 = b ^ c;
            int t2 = c & t1;
            int t3 = d ^ t2;
            int t4 = a ^ t3;
            int t5 = d | t1;
            int t6 = t4 & t5;
            X1 = b ^ t6;
            int t8 = t3 | X1;
            int t9 = a & t4;
            X3 = t1 ^ t9;
            int t11 = t4 ^ t8;
            int t12 = X3 & t11;
            X2 = t3 ^ t12;
            X0 = (~t11) ^ (X3 & X2);
        }
        #endregion
        #endregion
    }
}
