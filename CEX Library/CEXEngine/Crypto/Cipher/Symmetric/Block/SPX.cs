#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
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
// Portions of this cipher based on Serpent written by Ross Anderson, Eli Biham and Lars Knudsen:
// Serpent <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification
// 
// The sboxes are based on the work of Brian Gladman and Sam Simpson.
// <see href="http://fp.gladman.plus.com/cryptography_technology/serpent/">Specification</see>.
// Copyright: Dr B. R Gladman (gladman@seven77.demon.co.uk) and 
// Sam Simpson (s.simpson@mia.co.uk), 17th December 1998.
// 
// Implementation Details:
// An implementation of the Serpent block cipher,
// extended to 512 bit keys and up to 64 rounds.
// Serpent Extended (SPX)
// Written by John Underhill, November 14, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block
{
    /// <summary>
    /// <h3>SPX: An extended implementation of the Serpent encryption cipher.</h3>
    /// <para>SPX is an implementation of the Serpent<cite>Serpent</cite> block cipher, extended to use a 512 bit key.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode cipher = new CTR(new SPX()))
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(true, new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2014/11/14" version="1.2.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Secondary release; updates to layout and documentation</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode Interface</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Valid Key sizes are 128, 192, 256 and 512 bits (16, 24, 32 and 64 bytes).</description></item>
    /// <item><description>Block size is 16 bytes wide.</description></item>
    /// <item><description>Valid Rounds assignments are 32, 40, 48, 56, and 64, default is 32.</description></item>
    /// </list>
    /// 
    /// <para>The Key Schedule has been written so that it can both accept a larger key size of 512 bits, 
    /// and produce the required number of working keys with a variable number of diffusion rounds.</para>
    /// 
    /// <para>The diffusion rounds, (the portion of the cipher that does the actual mixing of plaintext into ciphertext),
    /// is exactly the same with every key length, only it can now process an increased number of rounds, from 32; 
    /// the standard, up to 64 rounds. 
    /// This increase in the ciphers diffusion cycles makes linear and differential analysis more difficult, 
    /// and the larger key size ensures that it can not be brute forced.</para>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Serpent: <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired in part by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class SPX : IBlockCipher
    {
        #region Constants
        private const string ALG_NAME = "SPX";
        private const int ROUNDS32 = 32;
        private const int BLOCK_SIZE = 16;
        private const int MAX_ROUNDS = 64;
        private const int MIN_ROUNDS = 32;
        private const UInt32 PHI = 0x9E3779B9;
        #endregion

        #region Fields
        private int _dfnRounds = MIN_ROUNDS;
        private UInt32[] _expKey;
        private bool _isDisposed = false;
        private bool _isEncryption;
        private bool _isInitialized = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Unit block size of internal cipher.
        /// <para>Block size is 16 bytes wide.</para>
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Get: Initialized for encryption, false for decryption.
        /// <para>Value set in <see cref="Initialize(bool, KeyParams)"/>.</para>
        /// </summary>
        public bool IsEncryption
        {
            get { return _isEncryption; }
            private set { _isEncryption = value; }
        }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get: Available block sizes for this cipher
        /// </summary>
        public int[] LegalBlockSizes
        {
            get { return new int[] { 16 }; }
        }

        /// <summary>
        /// Available Encryption Key Sizes in bytes
        /// </summary>
        public int[] LegalKeySizes
        {
            get { return new int[] { 16, 24, 32, 64 }; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public int[] LegalRounds
        {
            get { return new int[] { 32, 40, 48, 56, 64 }; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: The number of diffusion rounds processed by the transform
        /// </summary>
        public int Rounds
        {
            get { return _dfnRounds; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes.  Default is 32 rounds.</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid rounds count is chosen</exception>
        public SPX(int Rounds = ROUNDS32)
        {
            if (Rounds != 32 && Rounds != 40 && Rounds != 48 && Rounds != 56 && Rounds != 64 && Rounds != 80 && Rounds != 96 && Rounds != 128)
                throw new CryptoSymmetricException("SPX:CTor", "Invalid rounds size! Sizes supported are 32, 40, 48, 56, 64, 80, 96 and 128.", new ArgumentOutOfRangeException());

            _dfnRounds = Rounds;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SPX()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a single block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
        /// Input and Output arrays must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        public void DecryptBlock(byte[] Input, byte[] Output)
        {
            Decrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Decrypt a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
        /// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            Decrypt16(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Encrypt a block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
        /// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        public void EncryptBlock(byte[] Input, byte[] Output)
        {
            Encrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Encrypt a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
        /// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            Encrypt16(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// 
        /// <param name="Encryption">Using Encryption or Decryption mode</param>
        /// <param name="KeyParam">Cipher key container. <para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null or invalid key is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("SPX:Initialize", "Invalid key! Key can not be null.", new ArgumentNullException());
            if (KeyParam.Key.Length != 16 && KeyParam.Key.Length != 24 && KeyParam.Key.Length != 32 && KeyParam.Key.Length != 64)
                throw new CryptoSymmetricException("SPX:Initialize", "Invalid key size! Valid sizes are 16, 24, 32 and 64 bytes.", new ArgumentOutOfRangeException());

            _isEncryption = Encryption;
            _expKey = ExpandKey(KeyParam.Key);
        }

        /// <summary>
        /// Transform a block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
        /// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt or Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            if (_isEncryption)
                Encrypt16(Input, 0, Output, 0);
            else
                Decrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Transform a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
        /// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            if (_isEncryption)
                Encrypt16(Input, InOffset, Output, OutOffset);
            else
                Decrypt16(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Key Schedule
        private UInt32[] ExpandKey(byte[] Key)
        {
            int cnt = 0;
            int index = 0;
            int padSize = Key.Length < 32 ? 16 : Key.Length / 2;
            UInt32[] Wp = new UInt32[padSize];
            int offset = 0;

            // less than 512 is default rounds
            if (Key.Length < 64)
                _dfnRounds = ROUNDS32;

            int keySize = 4 * (_dfnRounds + 1);

            // step 1: reverse copy key to temp array
            for (offset = Key.Length; offset > 0; offset -= 4)
                Wp[index++] = IntUtils.BytesToBe32(Key, offset - 4);

            // pad small key
            if (index < 8)
                Wp[index] = 1;

            // initialize the key
            UInt32[] Wk = new UInt32[keySize];

            if (padSize == 16)
            {
                // 32 byte key
                // step 2: rotate k into w(k) ints
                for (int i = 8; i < 16; i++)
                    Wp[i] = IntUtils.RotateLeft((UInt32)(Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 8)), 11);

                // copy to expanded key
                Array.Copy(Wp, 8, Wk, 0, 8);

                // step 3: calculate remainder of rounds with rotating primitive
                for (int i = 8; i < keySize; i++)
                    Wk[i] = IntUtils.RotateLeft((UInt32)(Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
            }
            else
            {
                // *extended*: 64 byte key
                // step 3: rotate k into w(k) ints, with extended polynominal
                // Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
                for (int i = 16; i < 32; i++)
                    Wp[i] = IntUtils.RotateLeft((UInt32)(Wp[i - 16] ^ Wp[i - 13] ^ Wp[i - 11] ^ Wp[i - 10] ^ Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 16)), 11);

                // copy to expanded key
                Array.Copy(Wp, 16, Wk, 0, 16);

                // step 3: calculate remainder of rounds with rotating primitive
                for (int i = 16; i < keySize; i++)
                    Wk[i] = IntUtils.RotateLeft((UInt32)(Wk[i - 16] ^ Wk[i - 13] ^ Wk[i - 11] ^ Wk[i - 10] ^ Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
            }

            // step 4: create the working keys by processing with the Sbox and IP
            while (cnt < keySize - 4)
            {
                Sb3(ref Wk[cnt], ref Wk[cnt + 1], ref Wk[cnt + 2], ref Wk[cnt + 3]); cnt += 4;
                Sb2(ref Wk[cnt], ref Wk[cnt + 1], ref Wk[cnt + 2], ref Wk[cnt + 3]); cnt += 4;
                Sb1(ref Wk[cnt], ref Wk[cnt + 1], ref Wk[cnt + 2], ref Wk[cnt + 3]); cnt += 4;
                Sb0(ref Wk[cnt], ref Wk[cnt + 1], ref Wk[cnt + 2], ref Wk[cnt + 3]); cnt += 4;
                Sb7(ref Wk[cnt], ref Wk[cnt + 1], ref Wk[cnt + 2], ref Wk[cnt + 3]); cnt += 4;
                Sb6(ref Wk[cnt], ref Wk[cnt + 1], ref Wk[cnt + 2], ref Wk[cnt + 3]); cnt += 4;
                Sb5(ref Wk[cnt], ref Wk[cnt + 1], ref Wk[cnt + 2], ref Wk[cnt + 3]); cnt += 4;
                Sb4(ref Wk[cnt], ref Wk[cnt + 1], ref Wk[cnt + 2], ref Wk[cnt + 3]); cnt += 4;
            }

            // last round
            Sb3(ref Wk[cnt], ref Wk[cnt + 1], ref Wk[cnt + 2], ref Wk[cnt + 3]);

            return Wk;
        }
        #endregion

        #region Rounds Processing
        private void Decrypt16(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int LRD = 4;
            int keyCtr = _expKey.Length;

            // input round
	        uint R3 = _expKey[--keyCtr] ^ IntUtils.BytesToBe32(Input, InOffset);
	        uint R2 = _expKey[--keyCtr] ^ IntUtils.BytesToBe32(Input, InOffset + 4);
	        uint R1 = _expKey[--keyCtr] ^ IntUtils.BytesToBe32(Input, InOffset + 8);
	        uint R0 = _expKey[--keyCtr] ^ IntUtils.BytesToBe32(Input, InOffset + 12);

            // process 8 round blocks
            do
            {
                Ib7(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib6(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib5(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib4(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib3(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib2(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib1(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib0(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr != LRD)
                {
                    R3 ^= _expKey[--keyCtr];
                    R2 ^= _expKey[--keyCtr];
                    R1 ^= _expKey[--keyCtr];
                    R0 ^= _expKey[--keyCtr];
                    InverseTransform(ref R0, ref R1, ref R2, ref R3);
                }
            } 
            while (keyCtr != LRD);

            // last round
	        IntUtils.Be32ToBytes(R3 ^ _expKey[--keyCtr], Output, OutOffset);
	        IntUtils.Be32ToBytes(R2 ^ _expKey[--keyCtr], Output, OutOffset + 4);
	        IntUtils.Be32ToBytes(R1 ^ _expKey[--keyCtr], Output, OutOffset + 8);
	        IntUtils.Be32ToBytes(R0 ^ _expKey[--keyCtr], Output, OutOffset + 12);
        }

        private void Encrypt16(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int LRD = _expKey.Length - 5;
            int keyCtr = -1;

            // input round
	        uint R0 = IntUtils.BytesToBe32(Input, InOffset + 12);
	        uint R1 = IntUtils.BytesToBe32(Input, InOffset + 8);
	        uint R2 = IntUtils.BytesToBe32(Input, InOffset + 4);
	        uint R3 = IntUtils.BytesToBe32(Input, InOffset);

            // process 8 round blocks
            do
            {
                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb0(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb1(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb2(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3); ;

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb3(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb4(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb5(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb6(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb7(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr != LRD)
                    LinearTransform(ref R0, ref R1, ref R2, ref R3);
            } 
            while (keyCtr != LRD);

            // last round
	        IntUtils.Be32ToBytes(_expKey[++keyCtr] ^ R0, Output, OutOffset + 12);
	        IntUtils.Be32ToBytes(_expKey[++keyCtr] ^ R1, Output, OutOffset + 8);
	        IntUtils.Be32ToBytes(_expKey[++keyCtr] ^ R2, Output, OutOffset + 4);
	        IntUtils.Be32ToBytes(_expKey[++keyCtr] ^ R3, Output, OutOffset);
        }
        #endregion

        #region SBox Calculations
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

        private void Ib0(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R0;
            UInt32 t2 = R0 ^ R1;
            UInt32 t3 = R3 ^ (t1 | t2);
            UInt32 t4 = R2 ^ t3;
            R2 = t2 ^ t4;
            UInt32 t5 = t1 ^ (R3 & t2);
            R1 = t3 ^ (R2 & t5);
            R3 = (R0 & t3) ^ (t4 | R1);
            R0 = R3 ^ (t4 ^ t5);
        }

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

        private void Ib1(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ R3;
            UInt32 t2 = R0 ^ (R1 & t1);
            UInt32 t3 = t1 ^ t2;
            R3 = R2 ^ t3;
            UInt32 t4 = R1 ^ (t1 & t2);
            R1 = t2 ^ (R3 | t4);
            UInt32 t5 = ~R1;
            UInt32 t6 = R3 ^ t4;
            R0 = t5 ^ t6;
            R2 = t3 ^ (t5 | t6);
        }

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

        private void Ib2(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ R3;
            UInt32 t2 = R0 ^ R2;
            UInt32 t3 = R2 ^ t1;
            UInt32 t4 = R0 | ~t1;
            R0 = t2 ^ (R1 & t3);
            UInt32 t5 = t1 ^ (t2 | (R3 ^ t4));
            UInt32 t6 = ~t3;
            UInt32 t7 = R0 | t5;
            R1 = t6 ^ t7;
            R2 = (R3 & t6) ^ (t2 ^ t7);
            R3 = t5;
        }

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

        private void Ib3(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ R2;
            UInt32 t2 = R0 ^ (R1 & t1);
            UInt32 t3 = R3 | t2;
            UInt32 t4 = R3 ^ (t1 | t3);
            R2 = (R2 ^ t2) ^ t4;
            UInt32 t5 = (R0 | R1) ^ t4;
            R0 = t1 ^ t3;
            R3 = t2 ^ (R0 & t5);
            R1 = R3 ^ (R0 ^ t5);
        }

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

        private void Ib4(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ (R0 & (R2 | R3));
            UInt32 t2 = R2 ^ (R0 & t1);
            UInt32 t3 = R3 ^ t2;
            UInt32 t4 = ~R0;
            UInt32 t5 = t1 ^ (t2 & t3);
            UInt32 t6 = R3 ^ (t3 | t4);
            R1 = t3;
            R0 = t5 ^ t6;
            R2 = (t1 & t6) ^ (t3 ^ t4);
            R3 = t5;
        }

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

        private void Ib5(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R2;
            UInt32 t2 = R3 ^ (R1 & t1);
            UInt32 t3 = R0 & t2;
            UInt32 t4 = t3 ^ (R1 ^ t1);
            UInt32 t5 = R1 | t4;
            UInt32 t6 = t2 ^ (R0 & t5);
            UInt32 t7 = R0 | R3;
            R2 = (R1 & t7) ^ (t3 | (R0 ^ R2));
            R0 = t7 ^ (t1 ^ t5); 
            R1 = t6; 
            R3 = t4;
        }

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

        private void Ib6(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R0;
            UInt32 t2 = R0 ^ R1;
            UInt32 t3 = R2 ^ t2;
            UInt32 t4 = R3 ^ (R2 | t1);
            UInt32 t5 = t3 ^ t4;
            UInt32 t6 = t2 ^ (t3 & t4);
            UInt32 t7 = t4 ^ (R1 | t6);
            UInt32 t8 = R1 | t7;
            R0 = t6 ^ t8;
            R2 = (R3 & t1) ^ (t3 ^ t8);
            R1 = t5;
            R3 = t7;
        }

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

        private void Ib7(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R2 | (R0 & R1);
            UInt32 t2 = R3 & (R0 | R1);
            UInt32 t3 = t1 ^ t2;
            UInt32 t4 = R1 ^ t2;
            R1 = R0 ^ (t4 | (t3 ^ ~R3));
            UInt32 t8 = (R2 ^ t4) ^ (R3 | R1);
            R2 = (t1 ^ R1) ^ (t8 ^ (R0 & t3));
            R0 = t8; 
            R3 = t3;
        }

        /// <remarks>
        /// Apply the linear transformation to the register set
        /// </remarks>
        private void LinearTransform(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 x0 = IntUtils.RotateLeft(R0, 13);
            UInt32 x2 = IntUtils.RotateLeft(R2, 3);
            UInt32 x1 = R1 ^ x0 ^ x2;
            UInt32 x3 = R3 ^ x2 ^ x0 << 3;

            R1 = IntUtils.RotateLeft(x1, 1);
            R3 = IntUtils.RotateLeft(x3, 7);
            R0 = IntUtils.RotateLeft(x0 ^ R1 ^ R3, 5);
            R2 = IntUtils.RotateLeft(x2 ^ R3 ^ (R1 << 7), 22);
        }

        /// <remarks>
        /// Apply the inverse of the linear transformation to the register set
        /// </remarks>
        private void InverseTransform(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 x2 = IntUtils.RotateRight(R2, 22) ^ R3 ^ (R1 << 7);
            UInt32 x0 = IntUtils.RotateRight(R0, 5) ^ R1 ^ R3;
            UInt32 x3 = IntUtils.RotateRight(R3, 7);
            UInt32 x1 = IntUtils.RotateRight(R1, 1);

            R3 = x3 ^ x2 ^ x0 << 3;
            R1 = x1 ^ x0 ^ x2;
            R2 = IntUtils.RotateRight(x2, 3);
            R0 = IntUtils.RotateRight(x0, 13);
        }
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

        private void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                try
                {
                    if (disposing)
                    {
                        if (_expKey != null)
                        {
                            Array.Clear(_expKey, 0, _expKey.Length);
                            _expKey = null;
                        }
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
