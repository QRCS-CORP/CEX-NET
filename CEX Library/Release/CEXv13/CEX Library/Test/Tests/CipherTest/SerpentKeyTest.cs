using System;
using VTDev.Libraries.CEXEngine.Utility;

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// Compares Bouncy Castle Serpent key schedule output with RSX.
    /// </summary>
    public class SerpentKeyTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Compares Bouncy Castle Serpent key schedule with RSX.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Serpent key comparison has executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// Compares Bouncy Castle Serpent key scheduler output with RSX.
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                // equality comparison with Bouncy Castle version
                for (int i = 0; i < 10; i++)
                    KeyTest();

                OnProgress(new TestEventArgs("Passed 10 cycles of byte level comparison.."));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Private
        private void KeyTest()
        {
            byte[] key = new byte[32];

            using (System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                rng.GetBytes(key);

            uint[] ruk = RsxKey(key);        // rsx
            int[] sik = MakeWorkingKey(key); // bouncy serpentengine

            int btLen = ruk.Length * 4;
            byte[] rkey = new byte[btLen];
            byte[] skey = new byte[btLen];

            Buffer.BlockCopy(ruk, 0, rkey, 0, btLen);
            Buffer.BlockCopy(sik, 0, skey, 0, btLen);

            if (Compare.AreEqual(rkey, skey) == false)
                throw new Exception("SerpentKey: Key values are not equal!");
        }
        #endregion

        #region Bouncy Castles Serpent Key Scheduler
        static readonly int ROUNDS = 32;
        static readonly int PHI = unchecked((int)0x9E3779B9);
        private int X0, X1, X2, X3;

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
                kPad[length++] = bBytesToWord(key, off);
            }

            if (off == 0)
            {
                kPad[length++] = bBytesToWord(key, 0);
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
                kPad[i] = bRotateLeft(kPad[i - 8] ^ kPad[i - 5] ^ kPad[i - 3] ^ kPad[i - 1] ^ PHI ^ (i - 8), 11);
            }

            Array.Copy(kPad, 8, w, 0, 8);

            //
            // compute w8 to w136
            //
            for (int i = 8; i < amount; i++)
            {
                w[i] = bRotateLeft(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i, 11);
            }

            //
            // create the working keys by processing w with the Sbox and IP
            //
            bSb3(w[0], w[1], w[2], w[3]);
            w[0] = X0; w[1] = X1; w[2] = X2; w[3] = X3;
            bSb2(w[4], w[5], w[6], w[7]);
            w[4] = X0; w[5] = X1; w[6] = X2; w[7] = X3;
            bSb1(w[8], w[9], w[10], w[11]);
            w[8] = X0; w[9] = X1; w[10] = X2; w[11] = X3;
            bSb0(w[12], w[13], w[14], w[15]);
            w[12] = X0; w[13] = X1; w[14] = X2; w[15] = X3;
            bSb7(w[16], w[17], w[18], w[19]);
            w[16] = X0; w[17] = X1; w[18] = X2; w[19] = X3;
            bSb6(w[20], w[21], w[22], w[23]);
            w[20] = X0; w[21] = X1; w[22] = X2; w[23] = X3;
            bSb5(w[24], w[25], w[26], w[27]);
            w[24] = X0; w[25] = X1; w[26] = X2; w[27] = X3;
            bSb4(w[28], w[29], w[30], w[31]);
            w[28] = X0; w[29] = X1; w[30] = X2; w[31] = X3;
            bSb3(w[32], w[33], w[34], w[35]);
            w[32] = X0; w[33] = X1; w[34] = X2; w[35] = X3;
            bSb2(w[36], w[37], w[38], w[39]);
            w[36] = X0; w[37] = X1; w[38] = X2; w[39] = X3;
            bSb1(w[40], w[41], w[42], w[43]);
            w[40] = X0; w[41] = X1; w[42] = X2; w[43] = X3;
            bSb0(w[44], w[45], w[46], w[47]);
            w[44] = X0; w[45] = X1; w[46] = X2; w[47] = X3;
            bSb7(w[48], w[49], w[50], w[51]);
            w[48] = X0; w[49] = X1; w[50] = X2; w[51] = X3;
            bSb6(w[52], w[53], w[54], w[55]);
            w[52] = X0; w[53] = X1; w[54] = X2; w[55] = X3;
            bSb5(w[56], w[57], w[58], w[59]);
            w[56] = X0; w[57] = X1; w[58] = X2; w[59] = X3;
            bSb4(w[60], w[61], w[62], w[63]);
            w[60] = X0; w[61] = X1; w[62] = X2; w[63] = X3;
            bSb3(w[64], w[65], w[66], w[67]);
            w[64] = X0; w[65] = X1; w[66] = X2; w[67] = X3;
            bSb2(w[68], w[69], w[70], w[71]);
            w[68] = X0; w[69] = X1; w[70] = X2; w[71] = X3;
            bSb1(w[72], w[73], w[74], w[75]);
            w[72] = X0; w[73] = X1; w[74] = X2; w[75] = X3;
            bSb0(w[76], w[77], w[78], w[79]);
            w[76] = X0; w[77] = X1; w[78] = X2; w[79] = X3;
            bSb7(w[80], w[81], w[82], w[83]);
            w[80] = X0; w[81] = X1; w[82] = X2; w[83] = X3;
            bSb6(w[84], w[85], w[86], w[87]);
            w[84] = X0; w[85] = X1; w[86] = X2; w[87] = X3;
            bSb5(w[88], w[89], w[90], w[91]);
            w[88] = X0; w[89] = X1; w[90] = X2; w[91] = X3;
            bSb4(w[92], w[93], w[94], w[95]);
            w[92] = X0; w[93] = X1; w[94] = X2; w[95] = X3;
            bSb3(w[96], w[97], w[98], w[99]);
            w[96] = X0; w[97] = X1; w[98] = X2; w[99] = X3;
            bSb2(w[100], w[101], w[102], w[103]);
            w[100] = X0; w[101] = X1; w[102] = X2; w[103] = X3;
            bSb1(w[104], w[105], w[106], w[107]);
            w[104] = X0; w[105] = X1; w[106] = X2; w[107] = X3;
            bSb0(w[108], w[109], w[110], w[111]);
            w[108] = X0; w[109] = X1; w[110] = X2; w[111] = X3;
            bSb7(w[112], w[113], w[114], w[115]);
            w[112] = X0; w[113] = X1; w[114] = X2; w[115] = X3;
            bSb6(w[116], w[117], w[118], w[119]);
            w[116] = X0; w[117] = X1; w[118] = X2; w[119] = X3;
            bSb5(w[120], w[121], w[122], w[123]);
            w[120] = X0; w[121] = X1; w[122] = X2; w[123] = X3;
            bSb4(w[124], w[125], w[126], w[127]);
            w[124] = X0; w[125] = X1; w[126] = X2; w[127] = X3;
            bSb3(w[128], w[129], w[130], w[131]);
            w[128] = X0; w[129] = X1; w[130] = X2; w[131] = X3;

            return w;
        }

        private int bBytesToWord(byte[] src, int srcOff)
        {
            return (((src[srcOff] & 0xff) << 24) | ((src[srcOff + 1] & 0xff) << 16) |
            ((src[srcOff + 2] & 0xff) << 8) | ((src[srcOff + 3] & 0xff)));
        }

        private int bRotateLeft(int x, int bits)
        {
            return ((x << bits) | (int)((uint)x >> (32 - bits)));
        }

        private void bSb0(int a, int b, int c, int d)
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

        private void bSb1(int a, int b, int c, int d)
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

        private void bSb2(int a, int b, int c, int d)
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

        private void bSb3(int a, int b, int c, int d)
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

        private void bSb4(int a, int b, int c, int d)
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

        private void bSb5(int a, int b, int c, int d)
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

        private void bSb6(int a, int b, int c, int d)
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

        private void bSb7(int a, int b, int c, int d)
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

        #region RSX Key Scheduler
        private UInt32[] _registers = new UInt32[4];
        private int BlockSize = 32; // creates 120 keys

        private uint[] RsxKey(byte[] Key)
        {
            int ct = 0;
            int index = 0;
            int padSize = Key.Length / 2;
            uint[] Wp = new uint[padSize];
            int keySize = Key.Length == 64 ? 92 : 60;

            // rijndael uses 2x keys on 32 block
            if (this.BlockSize == 32)
                keySize *= 2;

            // step 1: reverse copy key to temp array
            for (int offset = Key.Length; offset > 0; offset -= 4)
                Wp[index++] = BytesToWord(Key, offset - 4);

            // initialize the key
            uint[] Wk = new uint[keySize];

            if (padSize == 16)
            {
                // 32 byte key
                // step 2: rotate k into w(k) ints
                for (int i = 8; i < 16; i++)
                    Wp[i] = RotateLeft((uint)(Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 8)), 11);

                // copy to expanded key
                Array.Copy(Wp, 8, Wk, 0, 8);

                // step 3: calculate remainder of rounds with rotating primitive
                for (int i = 8; i < keySize; i++)
                    Wk[i] = RotateLeft((uint)(Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
            }
            else
            {
                // *extended*: 64 byte key
                // step 3: rotate k into w(k) ints, with extended polynomial primitive
                // Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
                for (int i = 16; i < 32; i++)
                    Wp[i] = RotateLeft((uint)(Wp[i - 16] ^ Wp[i - 13] ^ Wp[i - 11] ^ Wp[i - 10] ^ Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 8)), 11);

                // copy to expanded key
                Array.Copy(Wp, 16, Wk, 0, 16);

                // step 3: calculate remainder of rounds
                for (int i = 16; i < keySize; i++)
                    Wk[i] = RotateLeft((uint)(Wk[i - 16] ^ Wk[i - 13] ^ Wk[i - 11] ^ Wk[i - 10] ^ Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
            }

            // step 4: create the working keys by processing with the Sbox and IP
            while (ct < keySize - 32)
            {
                Sb3(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
                Sb2(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
                Sb1(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
                Sb0(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
                Sb7(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
                Sb6(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
                Sb5(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
                Sb4(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
            }

            // last rounds
            Sb3(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
            Sb2(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
            Sb1(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
            Sb0(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
            Sb7(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);
            Sb6(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct++]);

            // different offset on 16 block
            if (this.BlockSize != 32)
                Sb5(ref Wk[ct++], ref Wk[ct++], ref Wk[ct++], ref Wk[ct]);

            return Wk;
        }

        private uint BytesToWord(byte[] Src, int SrcOff)
        {
            return ((uint)((Src[SrcOff] & 0xff) << 24) |
                    (uint)((Src[SrcOff + 1] & 0xff) << 16) |
                    (uint)((Src[SrcOff + 2] & 0xff) << 8) |
                    (uint)((Src[SrcOff + 3] & 0xff)));
        }

        private uint RotateLeft(uint X, int Bits)
        {
            return ((X << Bits) | X >> (32 - Bits));
        }

        private void Sb0(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R0 ^ R3;
            UInt32 t2 = R2 ^ t1;
            UInt32 t3 = R1 ^ t2;
            R3 = (R0 & R3) ^ t3;
            UInt32 t4 = R0 ^ (R1 & t1);
            R2 = t3 ^ (R2 | t4);
            R0 = R3 & (t2 ^ t4);
            R1 = (~t2) ^ R0;
            R0 ^= (~t4);
        }

        /// <summary>
        /// S1 - {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 } - 14 terms
        /// </summary>
        private void Sb1(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ (~R0);
            UInt32 t2 = R2 ^ (R0 | t1);
            R2 = R3 ^ t2;
            UInt32 t3 = R1 ^ (R3 | t1);
            UInt32 t4 = t1 ^ R2;
            R3 = t4 ^ (t2 & t3);
            UInt32 t5 = t2 ^ t3;
            R1 = R3 ^ t5;
            R0 = t2 ^ (t4 & t5);
        }

        /// <summary>
        /// S2 - { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 } - 16 terms
        /// </summary>
        private void Sb2(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R0;
            UInt32 t2 = R1 ^ R3;
            UInt32 t3 = t2 ^ (R2 & t1);
            UInt32 t4 = R2 ^ t1;
            UInt32 t5 = R1 & (R2 ^ t3);
            UInt32 t6 = t4 ^ t5;
            R2 = R0 ^ ((R3 | t5) & (t3 | t4));
            R1 = (t2 ^ t6) ^ (R2 ^ (R3 | t1));
            R0 = t3;
            R3 = t6;
        }

        /// <summary>
        /// S3 - { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 } - 16 terms
        /// </summary>
        private void Sb3(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R0 ^ R1;
            UInt32 t2 = R0 | R3;
            UInt32 t3 = R2 ^ R3;
            UInt32 t4 = (R0 & R2) | (t1 & t2);
            R2 = t3 ^ t4;
            UInt32 t5 = t4 ^ (R1 ^ t2);
            R0 = t1 ^ (t3 & t5);
            UInt32 t6 = R2 & R0;
            R3 = (R1 | R3) ^ (t3 ^ t6);
            R1 = t5 ^ t6;
        }

        /// <summary>
        /// S4 - { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 } - 15 terms
        /// </summary>
        private void Sb4(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R0 ^ R3;
            UInt32 t2 = R2 ^ (R3 & t1);
            UInt32 t3 = R1 | t2;
            R3 = t1 ^ t3;
            UInt32 t4 = ~R1;
            UInt32 t5 = t2 ^ (t1 | t4);
            UInt32 t6 = t1 ^ t4;
            UInt32 t7 = (R0 & t5) ^ (t3 & t6);
            R1 = (R0 ^ t2) ^ (t6 & t7);
            R0 = t5;
            R2 = t7;
        }

        /// <summary>
        /// S5 - {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 } - 16 terms
        /// </summary>
        private void Sb5(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R0;
            UInt32 t2 = R0 ^ R1;
            UInt32 t3 = R0 ^ R3;
            UInt32 t4 = (R2 ^ t1) ^ (t2 | t3);
            UInt32 t5 = R3 & t4;
            UInt32 t6 = t5 ^ (t2 ^ t4);
            UInt32 t7 = t3 ^ (t1 | t4);
            R2 = (t2 | t5) ^ t7;
            R3 = (R1 ^ t5) ^ (t6 & t7);
            R0 = t4;
            R1 = t6;
        }

        /// <summary>
        /// S6 - { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 } - 15 terms
        /// </summary>
        private void Sb6(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R0 ^ R3;
            UInt32 t2 = R1 ^ t1;
            UInt32 t3 = R2 ^ (~R0 | t1);
            R1 ^= t3;
            UInt32 t4 = t1 | R1;
            UInt32 t5 = R3 ^ (t1 | R1);
            R2 = t2 ^ (t3 & t5);
            UInt32 t6 = t3 ^ t5;
            R0 = R2 ^ t6;
            R3 = (~t3) ^ (t2 & t6);
        }

        /// <summary>
        /// S7 - { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } - 16 terms
        /// </summary>
        private void Sb7(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ R2;
            UInt32 t2 = R3 ^ (R2 & t1);
            UInt32 t3 = R0 ^ t2;
            R1 ^= (t3 & (R3 | t1));
            UInt32 t4 = t1 ^ (R0 & t3);
            UInt32 t5 = t3 ^ (t2 | R1);
            R2 = t2 ^ (t4 & t5);
            R0 = (~t5) ^ (t4 & R2);
            R3 = t4;
        }
        #endregion
    }
}
