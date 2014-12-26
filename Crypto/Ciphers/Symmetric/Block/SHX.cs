using System;
using VTDev.Libraries.CEXEngine.Crypto.Generators;
using VTDev.Libraries.CEXEngine.Crypto.Macs;

#region About
/// Permission is hereby granted, free of charge, to any person obtaining
/// a copy of this software and associated documentation files (the
/// "Software"), to deal in the Software without restriction, including
/// without limitation the rights to use, copy, modify, merge, publish,
/// distribute, sublicense, and/or sell copies of the Software, and to
/// permit persons to whom the Software is furnished to do so, subject to
/// the following conditions:
/// 
/// The copyright notice and this permission notice shall be
/// included in all copies or substantial portions of the Software.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
/// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
/// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
/// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
/// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
/// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
/// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
///
/// Based on the Serpent block cipher designed by Ross Anderson, Eli Biham and Lars Knudsen
/// Serpent white paper: http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf
/// 
/// The sboxes are based on the work of Brian Gladman and Sam Simpson.
/// http://fp.gladman.plus.com/cryptography_technology/serpent/
/// Copyright: Dr B. R Gladman (gladman@seven77.demon.co.uk) and 
/// Sam Simpson (s.simpson@mia.co.uk), 17th December 1998.
///
/// Portions of this code based on Bouncy Castle Java release 1.51:
/// http://bouncycastle.org/latest_releases.html
/// 
/// An implementation based on the Serpent block cipher,
/// using HKDF with a SHA512 HMAC for expanded key generation.
/// Serpent HKDF Extended (SHX)
/// Minimum key size is 192 bytes.
/// Valid Key sizes are 64 + multiples of 128 bytes (IKm + Salt).
/// Valid block size is 16 byte wide.
/// The number of Diffusion Rounds are configuarable.
/// Valid Rounds assignments are 32, 40, 48, 56, 64, 80, 96 and 128, default is 64.
/// Written by John Underhill, November 15, 2014
/// contact: steppenwolfe_2000@yahoo.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Ciphers
{
    /// SHX: Serpent HKDF Extended
    /// Minimum key size is 192 bytes.
    /// Valid Key sizes are 64 + multiples of 128 bytes (IKm + Salt).
    /// Valid block sizes is 16 byte wide.
    /// The number of Diffusion Rounds are configuarable.
    /// Valid Rounds assignments are 32, 40, 48, 56, 64, 80, 96 and 128, default is 64.
    public sealed class SHX : IBlockCipher, IDisposable
    {
        #region Constants
        private const Int32 BLOCK_SIZE = 16;
        private const Int32 DEFAULT_ROUNDS = 64;
        private const Int32 IKM_SIZE = 64;
        private const Int32 MIN_KEYSIZE = 192;
        private const Int32 MAX_ROUNDS = 128;
        private const Int32 MIN_ROUNDS = 32;
        private const Int32 PHI = unchecked((Int32)0x9E3779B9);
        private const Int32 SALT_SIZE = 128;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private bool _isEncryption;
        private Int32[] _exKey;
        private bool _isInitialized = false;
        private Int32 Rounds = 64;
        // configurable nonce can create a unique distribution, can be byte(0)
        private byte[] _hkdfInfo = System.Text.Encoding.ASCII.GetBytes("SHX version 1 information string");
        #endregion

        #region Properties
        /// <summary>
        /// Unit block size of internal cipher.
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
            set { ; }
        }

        /// <summary>
        /// Get: Key has been expanded
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
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
        /// Get: Available Encryption Key Sizes in bits (192, 320, 448, 576 bytes)
        /// </summary>
        public static Int32[] KeySizes
        {
            get { return new Int32[] { 1536, 2560, 3584, 4608 }; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return "SHX"; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public static Int32[] LegalRounds
        {
            get { return new Int32[] { 32, 40, 48, 56, 64, 80, 96, 128 }; }
        }
        #endregion

        #region Constructor
        public SHX(int Rounds = DEFAULT_ROUNDS)
        {
            if (Rounds != 32 && Rounds != 40 && Rounds != 48 && Rounds != 56 && Rounds != 64 && Rounds != 80 && Rounds != 96 && Rounds != 128)
                throw new ArgumentOutOfRangeException("Invalid rounds size! Sizes supported are 32, 40, 48, 56, 64, 80, 96 and 128.");

            this.Rounds = Rounds;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a single block of bytes.
        /// Init must be called with the Encryption flag set to false before this method can be used.
        /// Input and Output must be at least BlockSize in length.
        /// </summary>
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        public void DecryptBlock(byte[] Input, byte[] Output)
        {
            Decrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Decrypt a block of bytes within an array.
        /// Init must be called with the Encryption flag set to false before this method can be used.
        /// Input and Output + Offsets must be at least BlockSize in length.
        /// </summary>
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
        public void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            Decrypt16(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Encrypt a block of bytes.
        /// Init must be called with the Encryption flag set to true before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        public void EncryptBlock(byte[] Input, byte[] Output)
        {
            Encrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Encrypt a block of bytes within an array.
        /// Init must be called with the Encryption flag set to true before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
        public void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            Encrypt16(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// <param name="Encryptor">Using Encryption or Decryption mode</param>
        /// <param name="KeyParam">Cipher key, valid sizes are: 256 and 512 bytes</param>
        public void Init(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new ArgumentOutOfRangeException("Invalid key! Key can not be null.");
            if (KeyParam.Key.Length < MIN_KEYSIZE)
                throw new ArgumentOutOfRangeException("Invalid key size! Key must be at least " + MIN_KEYSIZE + " bytes (" + MIN_KEYSIZE * 8 + " bit).");
            if ((KeyParam.Key.Length - IKM_SIZE) % SALT_SIZE != 0)
                throw new ArgumentOutOfRangeException("Invalid key size! Key must be (length - IKm length: " + IKM_SIZE + " bytes) + divisible of SHA512 block size (128 bytes).");

            this.IsEncryption = Encryption;
            _exKey = ExpandKey(KeyParam.Key);
        }

        /// <summary>
        /// Transform a block of bytes.
        /// Init must be called before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            if (this.IsEncryption)
                Encrypt16(Input, 0, Output, 0);
            else
                Decrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Transform a block of bytes within an array.
        /// Init must be called before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            if (this.IsEncryption)
                Encrypt16(Input, InOffset, Output, OutOffset);
            else
                Decrypt16(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Transform
        private void Decrypt16(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            // cr = 4 * 8 : 4cr = 132, 5cr = 164, 6cr = 196, 7cr = 228, 8cr = 260
            int keyCtr = _exKey.Length - 1;

            // input round
            Int32 R3 = _exKey[keyCtr--] ^ BytesToWord(Input, InOffset);
            Int32 R2 = _exKey[keyCtr--] ^ BytesToWord(Input, InOffset + 4);
            Int32 R1 = _exKey[keyCtr--] ^ BytesToWord(Input, InOffset + 8);
            Int32 R0 = _exKey[keyCtr--] ^ BytesToWord(Input, InOffset + 12);

            // process 8 round blocks
            while (keyCtr > 4)
            {
                Ib7(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _exKey[keyCtr--];
                R2 ^= _exKey[keyCtr--];
                R1 ^= _exKey[keyCtr--];
                R0 ^= _exKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib6(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _exKey[keyCtr--];
                R2 ^= _exKey[keyCtr--];
                R1 ^= _exKey[keyCtr--];
                R0 ^= _exKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib5(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _exKey[keyCtr--];
                R2 ^= _exKey[keyCtr--];
                R1 ^= _exKey[keyCtr--];
                R0 ^= _exKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib4(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _exKey[keyCtr--];
                R2 ^= _exKey[keyCtr--];
                R1 ^= _exKey[keyCtr--];
                R0 ^= _exKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib3(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _exKey[keyCtr--];
                R2 ^= _exKey[keyCtr--];
                R1 ^= _exKey[keyCtr--];
                R0 ^= _exKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib2(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _exKey[keyCtr--];
                R2 ^= _exKey[keyCtr--];
                R1 ^= _exKey[keyCtr--];
                R0 ^= _exKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib1(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _exKey[keyCtr--];
                R2 ^= _exKey[keyCtr--];
                R1 ^= _exKey[keyCtr--];
                R0 ^= _exKey[keyCtr--];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib0(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr > 4)
                {
                    R3 ^= _exKey[keyCtr--];
                    R2 ^= _exKey[keyCtr--];
                    R1 ^= _exKey[keyCtr--];
                    R0 ^= _exKey[keyCtr--];
                    InverseTransform(ref R0, ref R1, ref R2, ref R3);
                }
            }

            // last round
            WordToBytes(R3 ^ _exKey[keyCtr--], Output, OutOffset);
            WordToBytes(R2 ^ _exKey[keyCtr--], Output, OutOffset + 4);
            WordToBytes(R1 ^ _exKey[keyCtr--], Output, OutOffset + 8);
            WordToBytes(R0 ^ _exKey[keyCtr], Output, OutOffset + 12);
        }

        private void Encrypt16(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            int keyCtr = 0;

            // input round
            Int32 R0 = BytesToWord(Input, InOffset + 12);
            Int32 R1 = BytesToWord(Input, InOffset + 8);
            Int32 R2 = BytesToWord(Input, InOffset + 4);
            Int32 R3 = BytesToWord(Input, InOffset);

            // process 8 round blocks
            while (keyCtr < _exKey.Length - 4)
            {
                R0 ^= _exKey[keyCtr++];
                R1 ^= _exKey[keyCtr++];
                R2 ^= _exKey[keyCtr++];
                R3 ^= _exKey[keyCtr++];
                Sb0(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _exKey[keyCtr++];
                R1 ^= _exKey[keyCtr++];
                R2 ^= _exKey[keyCtr++];
                R3 ^= _exKey[keyCtr++];
                Sb1(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _exKey[keyCtr++];
                R1 ^= _exKey[keyCtr++];
                R2 ^= _exKey[keyCtr++];
                R3 ^= _exKey[keyCtr++];
                Sb2(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3); ;

                R0 ^= _exKey[keyCtr++];
                R1 ^= _exKey[keyCtr++];
                R2 ^= _exKey[keyCtr++];
                R3 ^= _exKey[keyCtr++];
                Sb3(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _exKey[keyCtr++];
                R1 ^= _exKey[keyCtr++];
                R2 ^= _exKey[keyCtr++];
                R3 ^= _exKey[keyCtr++];
                Sb4(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _exKey[keyCtr++];
                R1 ^= _exKey[keyCtr++];
                R2 ^= _exKey[keyCtr++];
                R3 ^= _exKey[keyCtr++];
                Sb5(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _exKey[keyCtr++];
                R1 ^= _exKey[keyCtr++];
                R2 ^= _exKey[keyCtr++];
                R3 ^= _exKey[keyCtr++];
                Sb6(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _exKey[keyCtr++];
                R1 ^= _exKey[keyCtr++];
                R2 ^= _exKey[keyCtr++];
                R3 ^= _exKey[keyCtr++];
                Sb7(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr < _exKey.Length - 4)
                    LinearTransform(ref R0, ref R1, ref R2, ref R3);
            }

            // last round
            WordToBytes(_exKey[keyCtr++] ^ R0, Output, OutOffset + 12);
            WordToBytes(_exKey[keyCtr++] ^ R1, Output, OutOffset + 8);
            WordToBytes(_exKey[keyCtr++] ^ R2, Output, OutOffset + 4);
            WordToBytes(_exKey[keyCtr] ^ R3, Output, OutOffset);
        }
        #endregion

        #region Helpers
        private Int32 BytesToWord(byte[] Src, Int32 SrcOff)
        {
            return (((byte)(Src[SrcOff]) << 24) |
                ((byte)(Src[SrcOff + 1]) << 16) |
                ((byte)(Src[SrcOff + 2]) << 8) |
                ((byte)(Src[SrcOff + 3])));
        }

        private Int32[] ExpandKey(byte[] Key)
        {
            // expanded key size
            int keySize = 4 * (this.Rounds + 1);

            // hkdf return array
            int keyBytes = keySize * 4;
            byte[] rawKey = new byte[keyBytes];
            int saltSize = Key.Length - IKM_SIZE;

            // salt must be divisble of hash blocksize
            if (saltSize % SALT_SIZE != 0)
                saltSize = saltSize - saltSize % SALT_SIZE;

            // hkdf input
            byte[] hkdfKey = new byte[IKM_SIZE];
            byte[] hkdfSalt = new byte[saltSize];

            // copy hkdf key and salt from user key
            Buffer.BlockCopy(Key, 0, hkdfKey, 0, IKM_SIZE);
            Buffer.BlockCopy(Key, IKM_SIZE, hkdfSalt, 0, saltSize);

            // HKDF generator expands array using an SHA512 HMAC
            using (HKDF gen = new HKDF(new SHA512HMAC()))
            {
                gen.Init(hkdfSalt, hkdfKey, _hkdfInfo);
                gen.Generate(keyBytes, rawKey, 0);
            }

            // initialize working key
            Int32[] wK = new Int32[keySize];
            // copy bytes to working key
            Buffer.BlockCopy(rawKey, 0, wK, 0, keyBytes);
            // key processed
            this.IsInitialized = true;

            return wK;
        }

        private Int32 RotateLeft(Int32 X, Int32 Bits)
        {
            return ((X << Bits) | (Int32)((UInt32)X >> (32 - Bits)));
        }

        private Int32 RotateRight(Int32 X, Int32 Bits)
        {
            return ((Int32)((UInt32)X >> Bits) | (X << (32 - Bits)));
        }

        private void WordToBytes(Int32 Word, byte[] Dst, Int32 DstOff)
        {
            Dst[DstOff + 3] = (byte)(Word);
            Dst[DstOff + 2] = (byte)(Word >> 8);
            Dst[DstOff + 1] = (byte)(Word >> 16);
            Dst[DstOff] = (byte)(Word >> 24);
        }
        #endregion

        #region SBox Calculations
        private void Sb0(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R0 ^ R3;
            Int32 t2 = R2 ^ t1;
            Int32 t3 = R1 ^ t2;
            R3 = (R0 & R3) ^ t3;
            Int32 t4 = R0 ^ (R1 & t1);
            R2 = t3 ^ (R2 | t4);
            R0 = R3 & (t2 ^ t4);
            R1 = (~t2) ^ R0;
            R0 ^= (~t4);
        }

        /// <summary>
        /// InvSO - {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 } - 15 terms.
        /// </summary>
        private void Ib0(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R0;
            Int32 t2 = R0 ^ R1;
            Int32 t3 = R3 ^ (t1 | t2);
            Int32 t4 = R2 ^ t3;
            R2 = t2 ^ t4;
            Int32 t5 = t1 ^ (R3 & t2);
            R1 = t3 ^ (R2 & t5);
            R3 = (R0 & t3) ^ (t4 | R1);
            R0 = R3 ^ (t4 ^ t5);
        }

        /// <summary>
        /// S1 - {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 } - 14 terms
        /// </summary>
        private void Sb1(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ (~R0);
            Int32 t2 = R2 ^ (R0 | t1);
            R2 = R3 ^ t2;
            Int32 t3 = R1 ^ (R3 | t1);
            Int32 t4 = t1 ^ R2;
            R3 = t4 ^ (t2 & t3);
            Int32 t5 = t2 ^ t3;
            R1 = R3 ^ t5;
            R0 = t2 ^ (t4 & t5);
        }

        /// <summary>
        /// InvS1 - { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 } - 14 steps
        /// </summary>
        private void Ib1(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ R3;
            Int32 t2 = R0 ^ (R1 & t1);
            Int32 t3 = t1 ^ t2;
            R3 = R2 ^ t3;
            Int32 t4 = R1 ^ (t1 & t2);
            R1 = t2 ^ (R3 | t4);
            Int32 t5 = ~R1;
            Int32 t6 = R3 ^ t4;
            R0 = t5 ^ t6;
            R2 = t3 ^ (t5 | t6);
        }

        /// <summary>
        /// S2 - { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 } - 16 terms
        /// </summary>
        private void Sb2(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R0;
            Int32 t2 = R1 ^ R3;
            Int32 t3 = t2 ^ (R2 & t1);
            Int32 t4 = R2 ^ t1;
            Int32 t5 = R1 & (R2 ^ t3);
            Int32 t6 = t4 ^ t5;
            R2 = R0 ^ ((R3 | t5) & (t3 | t4));
            R1 = (t2 ^ t6) ^ (R2 ^ (R3 | t1));
            R0 = t3;
            R3 = t6;
        }

        /// <summary>
        /// InvS2 - {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 } - 16 steps
        /// </summary>
        private void Ib2(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ R3;
            Int32 t2 = R0 ^ R2;
            Int32 t3 = R2 ^ t1;
            Int32 t4 = R0 | ~t1;
            R0 = t2 ^ (R1 & t3);
            Int32 t5 = t1 ^ (t2 | (R3 ^ t4));
            Int32 t6 = ~t3;
            Int32 t7 = R0 | t5;
            R1 = t6 ^ t7;
            R2 = (R3 & t6) ^ (t2 ^ t7);
            R3 = t5;
        }

        /// <summary>
        /// S3 - { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 } - 16 terms
        /// </summary>
        private void Sb3(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R0 ^ R1;
            Int32 t2 = R0 | R3;
            Int32 t3 = R2 ^ R3;
            Int32 t4 = (R0 & R2) | (t1 & t2);
            R2 = t3 ^ t4;
            Int32 t5 = t4 ^ (R1 ^ t2);
            R0 = t1 ^ (t3 & t5);
            Int32 t6 = R2 & R0;
            R3 = (R1 | R3) ^ (t3 ^ t6);
            R1 = t5 ^ t6;
        }

        /// <summary>
        /// InvS3 - { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 } - 15 terms
        /// </summary>
        private void Ib3(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ R2;
            Int32 t2 = R0 ^ (R1 & t1);
            Int32 t3 = R3 | t2;
            Int32 t4 = R3 ^ (t1 | t3);
            R2 = (R2 ^ t2) ^ t4;
            Int32 t5 = (R0 | R1) ^ t4;
            R0 = t1 ^ t3;
            R3 = t2 ^ (R0 & t5);
            R1 = R3 ^ (R0 ^ t5);
        }

        /// <summary>
        /// S4 - { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 } - 15 terms
        /// </summary>
        private void Sb4(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R0 ^ R3;
            Int32 t2 = R2 ^ (R3 & t1);
            Int32 t3 = R1 | t2;
            R3 = t1 ^ t3;
            Int32 t4 = ~R1;
            Int32 t5 = t2 ^ (t1 | t4);
            Int32 t6 = t1 ^ t4;
            Int32 t7 = (R0 & t5) ^ (t3 & t6);
            R1 = (R0 ^ t2) ^ (t6 & t7);
            R0 = t5;
            R2 = t7;
        }

        /// <summary>
        /// InvS4 - { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 } - 15 terms
        /// </summary>
        private void Ib4(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ (R0 & (R2 | R3));
            Int32 t2 = R2 ^ (R0 & t1);
            Int32 t3 = R3 ^ t2;
            Int32 t4 = ~R0;
            Int32 t5 = t1 ^ (t2 & t3);
            Int32 t6 = R3 ^ (t3 | t4);
            R1 = t3;
            R0 = t5 ^ t6;
            R2 = (t1 & t6) ^ (t3 ^ t4);
            R3 = t5;
        }

        /// <summary>
        /// S5 - {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 } - 16 terms
        /// </summary>
        private void Sb5(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R0;
            Int32 t2 = R0 ^ R1;
            Int32 t3 = R0 ^ R3;
            Int32 t4 = (R2 ^ t1) ^ (t2 | t3);
            Int32 t5 = R3 & t4;
            Int32 t6 = t5 ^ (t2 ^ t4);
            Int32 t7 = t3 ^ (t1 | t4);
            R2 = (t2 | t5) ^ t7;
            R3 = (R1 ^ t5) ^ (t6 & t7);
            R0 = t4;
            R1 = t6;
        }

        /// <summary>
        /// InvS5 - { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 } - 16 terms
        /// </summary>
        private void Ib5(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R2;
            Int32 t2 = R3 ^ (R1 & t1);
            Int32 t3 = R0 & t2;
            Int32 t4 = t3 ^ (R1 ^ t1);
            Int32 t5 = R1 | t4;
            Int32 t6 = t2 ^ (R0 & t5);
            Int32 t7 = R0 | R3;
            R2 = (R1 & t7) ^ (t3 | (R0 ^ R2));
            R0 = t7 ^ (t1 ^ t5);
            R1 = t6;
            R3 = t4;
        }

        /// <summary>
        /// S6 - { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 } - 15 terms
        /// </summary>
        private void Sb6(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R0 ^ R3;
            Int32 t2 = R1 ^ t1;
            Int32 t3 = R2 ^ (~R0 | t1);
            R1 ^= t3;
            Int32 t4 = t1 | R1;
            Int32 t5 = R3 ^ (t1 | R1);
            R2 = t2 ^ (t3 & t5);
            Int32 t6 = t3 ^ t5;
            R0 = R2 ^ t6;
            R3 = (~t3) ^ (t2 & t6);
        }

        /// <summary>
        /// InvS6 - {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 } - 15 terms
        /// </summary>
        private void Ib6(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = ~R0;
            Int32 t2 = R0 ^ R1;
            Int32 t3 = R2 ^ t2;
            Int32 t4 = R3 ^ (R2 | t1);
            Int32 t5 = t3 ^ t4;
            Int32 t6 = t2 ^ (t3 & t4);
            Int32 t7 = t4 ^ (R1 | t6);
            Int32 t8 = R1 | t7;
            R0 = t6 ^ t8;
            R2 = (R3 & t1) ^ (t3 ^ t8);
            R1 = t5;
            R3 = t7;
        }

        /// <summary>
        /// S7 - { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } - 16 terms
        /// </summary>
        private void Sb7(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R1 ^ R2;
            Int32 t2 = R3 ^ (R2 & t1);
            Int32 t3 = R0 ^ t2;
            R1 ^= (t3 & (R3 | t1));
            Int32 t4 = t1 ^ (R0 & t3);
            Int32 t5 = t3 ^ (t2 | R1);
            R2 = t2 ^ (t4 & t5);
            R0 = (~t5) ^ (t4 & R2);
            R3 = t4;
        }

        /// <summary>
        /// InvS7 - { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 } - 17 terms
        /// </summary>
        private void Ib7(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 t1 = R2 | (R0 & R1);
            Int32 t2 = R3 & (R0 | R1);
            Int32 t3 = t1 ^ t2;
            Int32 t4 = R1 ^ t2;
            R1 = R0 ^ (t4 | (t3 ^ ~R3));
            Int32 t8 = (R2 ^ t4) ^ (R3 | R1);
            R2 = (t1 ^ R1) ^ (t8 ^ (R0 & t3));
            R0 = t8;
            R3 = t3;
        }

        /// <summary>
        /// Apply the linear transformation to the register set
        /// </summary>
        private void LinearTransform(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 x0 = RotateLeft(R0, 13);
            Int32 x2 = RotateLeft(R2, 3);
            Int32 x1 = R1 ^ x0 ^ x2;
            Int32 x3 = R3 ^ x2 ^ x0 << 3;

            R1 = RotateLeft(x1, 1);
            R3 = RotateLeft(x3, 7);
            R0 = RotateLeft(x0 ^ R1 ^ R3, 5);
            R2 = RotateLeft(x2 ^ R3 ^ (R1 << 7), 22);
        }

        /// <summary>
        /// Apply the inverse of the linear transformation to the register set
        /// </summary>
        private void InverseTransform(ref Int32 R0, ref Int32 R1, ref Int32 R2, ref Int32 R3)
        {
            Int32 x2 = RotateRight(R2, 22) ^ R3 ^ (R1 << 7);
            Int32 x0 = RotateRight(R0, 5) ^ R1 ^ R3;
            Int32 x3 = RotateRight(R3, 7);
            Int32 x1 = RotateRight(R1, 1);

            R3 = x3 ^ x2 ^ x0 << 3;
            R1 = x1 ^ x0 ^ x2;
            R2 = RotateRight(x2, 3);
            R0 = RotateRight(x0, 13);
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
                    if (_exKey != null)
                    {
                        Array.Clear(_exKey, 0, _exKey.Length);
                        _exKey = null;
                    }
                    if (_hkdfInfo != null)
                    {
                        Array.Clear(_hkdfInfo, 0, _hkdfInfo.Length);
                        _hkdfInfo = null;
                    }
                }
                _isDisposed = true;
            }
        }
        #endregion
    }
}
