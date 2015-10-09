#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
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
// Portions of this cipher partially based on the Twofish block cipher designed by Bruce Schneier, John Kelsey, 
// Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson.
// Twofish: <see href="https://www.schneier.com/paper-twofish-paper.pdf">Specification</see>.
// 
// Implementation Details:
// An implementation of the Twofish block cipher,
// extended to 512 bit keys and up to 32 rounds.
// TwoFish Extended (TFX)
// Written by John Underhill, December 3, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block
{
    /// <summary>
    /// <h3>TFX: An extended implementation of the Twofish encryption cipher.</h3>
    /// <para>TFX is an implementation of the Twofish<cite>Twofish</cite> block cipher, extended to use a 512 bit key.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode cipher = new CTR(new TFX()))
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
    /// <item><description>Valid Rounds assignments are 16, 18, 20, 22, 24, 26, 28, 30 and 32, default is 16.</description></item>
    /// </list>
    /// 
    /// <para>TFX extends the original design allowing it to accept the longer key length (512 bits).</para>
    /// 
    /// <para>The number of diffusion rounds processed in the ciphers transformation method has also been extended, and is user configurable; 
    /// from the original 16 rounds, to a full 32 rounds of transformation. 
    /// This increase in key size eliminates brute force attacks, and the increase in the number of diffusion rounds makes cryptanalysis far more difficult.</para>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Twofish: <see href="https://www.schneier.com/paper-twofish-paper.pdf">A 128-Bit Block Cipher</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired in part by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class TFX : IBlockCipher
    {
        #region Constants
        private const string ALG_NAME = "TFX";
        private const Int32 BLOCK_SIZE = 16;
        private const Int32 ROUNDS16 = 16;
        private const Int32 DEFAULT_SUBKEYS = 40;
        private const Int32 GF256_FDBK = 0x169; // primitive polynomial for GF(256)
        private const Int32 GF256_FDBK_2 = GF256_FDBK / 2;
        private const Int32 GF256_FDBK_4 = GF256_FDBK / 4;
        private const Int32 KEY_BITS = 256;
        private const Int32 RS_GF_FDBK = 0x14D; // field generator
        private const Int32 SK_STEP = 0x02020202;
        private const Int32 SK_BUMP = 0x01010101;
        private const Int32 SK_ROTL = 9;
        private const Int32 SBOX_SIZE = 1024;
        #endregion

        #region Fields
        private Int32 _dfnRounds = ROUNDS16;
        private Int32[] _expKey;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isInitialized = false;
        private Int32[] _sprBox = new Int32[SBOX_SIZE];
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
        public static int[] LegalBlockSizes
        {
            get { return new int[] { 16 }; }
        }

        /// <summary>
        /// Get: Available Encryption Key Sizes in bytes
        /// </summary>
        public static Int32[] LegalKeySizes
        {
            get { return new Int32[] { 16, 24, 32, 64 }; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public static int[] LegalRounds
        {
            get { return new int[] { 16, 18, 20, 22, 24, 26, 28, 30, 32 }; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 16 rounds.</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid rounds count is chosen</exception>
        public TFX(int Rounds = ROUNDS16)
        {
            //MDS0X
            if (Rounds != 16 && Rounds != 18 && Rounds != 20 && Rounds != 22 && Rounds != 24 && Rounds != 26 && Rounds != 28 && Rounds != 30 && Rounds != 32)
                throw new CryptoSymmetricException("TFX:CTor", "Invalid rounds size! Sizes supported are 16, 18, 20, 22, 24, 26, 28, 30 and 32.", new ArgumentOutOfRangeException());

            _dfnRounds = Rounds;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~TFX()
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
                throw new CryptoSymmetricException("TFX:Initialize", "Invalid key! Key can not be null.", new ArgumentNullException());
            if (KeyParam.Key.Length != 16 && KeyParam.Key.Length != 24 && KeyParam.Key.Length != 32 && KeyParam.Key.Length != 64)
                throw new CryptoSymmetricException("TFX:Initialize", "Invalid key size! Valid sizes are 16, 24, 32 and 64 bytes.", new ArgumentOutOfRangeException());

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
                EncryptBlock(Input, Output);
            else
                DecryptBlock(Input, Output);
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
                EncryptBlock(Input, InOffset, Output, OutOffset);
            else
                DecryptBlock(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Key Schedule
        private Int32[] ExpandKey(byte[] Key)
        {
            int k64Cnt = Key.Length / 8;
            int kmLen = k64Cnt > 4 ? 8 : 4;
            int keyCtr = 0;
            Int32 A, B, Q;
            Int32 Y0, Y1, Y2, Y3;
            Int32[] eKm = new Int32[kmLen];
            Int32[] oKm = new Int32[kmLen];
            byte[] sbKey = new byte[Key.Length == 64 ? 32 : 16];
            Int32[] wK = new Int32[_dfnRounds * 2 + 8];

            for (int i = 0; i < k64Cnt; i++)
            {
                // round key material
                eKm[i] = BytesToInt32(Key, keyCtr);
                keyCtr += 4;
                oKm[i] = BytesToInt32(Key, keyCtr);
                keyCtr += 4;
                // sbox key material
                Int32ToBytes(MDSEncode(eKm[i], oKm[i]), sbKey, ((k64Cnt * 4) - 4) - (i * 4));
            }

            keyCtr = 0;

            while (keyCtr < KEY_BITS)
            {
                // create the expanded key
                if (keyCtr < (wK.Length / 2))
                {
                    Q = keyCtr * SK_STEP;
                    A = F32(Q, eKm, k64Cnt);
                    B = F32(Q + SK_BUMP, oKm, k64Cnt);
                    B = B << 8 | (Int32)((UInt32)B >> 24);
                    A += B;
                    wK[keyCtr * 2] = A;
                    A += B;
                    wK[keyCtr * 2 + 1] = A << SK_ROTL | (int)((UInt32)A >> (32 - SK_ROTL));
                }

                Y0 = Y1 = Y2 = Y3 = keyCtr;

                // 512 key
                if (Key.Length == 64)
                {
                    Y0 = (byte)Q1[Y0] ^ sbKey[28];
                    Y1 = (byte)Q0[Y1] ^ sbKey[29];
                    Y2 = (byte)Q0[Y2] ^ sbKey[30];
                    Y3 = (byte)Q1[Y3] ^ sbKey[31];

                    Y0 = (byte)Q1[Y0] ^ sbKey[24];
                    Y1 = (byte)Q1[Y1] ^ sbKey[25];
                    Y2 = (byte)Q0[Y2] ^ sbKey[26];
                    Y3 = (byte)Q0[Y3] ^ sbKey[27];

                    Y0 = (byte)Q0[Y0] ^ sbKey[20];
                    Y1 = (byte)Q1[Y1] ^ sbKey[21];
                    Y2 = (byte)Q1[Y2] ^ sbKey[22];
                    Y3 = (byte)Q0[Y3] ^ sbKey[23];

                    Y0 = (byte)Q0[Y0] ^ sbKey[16];
                    Y1 = (byte)Q0[Y1] ^ sbKey[17];
                    Y2 = (byte)Q1[Y2] ^ sbKey[18];
                    Y3 = (byte)Q1[Y3] ^ sbKey[19];
                }
                // 256 key
                if (Key.Length > 24)
                {
                    Y0 = (byte)Q1[Y0] ^ sbKey[12];
                    Y1 = (byte)Q0[Y1] ^ sbKey[13];
                    Y2 = (byte)Q0[Y2] ^ sbKey[14];
                    Y3 = (byte)Q1[Y3] ^ sbKey[15];
                }
                // 192 key
                if (Key.Length > 16)
                {
                    Y0 = (byte)Q1[Y0] ^ sbKey[8];
                    Y1 = (byte)Q1[Y1] ^ sbKey[9];
                    Y2 = (byte)Q0[Y2] ^ sbKey[10];
                    Y3 = (byte)Q0[Y3] ^ sbKey[11];
                }

                // sbox members as MDS matrix multiplies 
                _sprBox[keyCtr * 2] = MDS0[(byte)Q0[(byte)Q0[Y0] ^ sbKey[4]] ^ sbKey[0]];
                _sprBox[keyCtr * 2 + 1] = MDS1[(byte)Q0[Q1[Y1] ^ sbKey[5]] ^ sbKey[1]];
                _sprBox[(keyCtr * 2) + 0x200] = MDS2[(byte)Q1[(byte)Q0[Y2] ^ sbKey[6]] ^ sbKey[2]];
                _sprBox[keyCtr++ * 2 + 0x201] = MDS3[(byte)Q1[(byte)Q1[Y3] ^ sbKey[7]] ^ sbKey[3]];
            }

            // key processed
            _isInitialized = true;
            return wK;
        }
        #endregion

        #region Rounds Processing
        private void Decrypt16(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            Int32 keyCtr = 4;
            Int32 X2 = BytesToInt32(Input, InOffset) ^ _expKey[keyCtr++];
            Int32 X3 = BytesToInt32(Input, InOffset + 4) ^ _expKey[keyCtr++];
            Int32 X0 = BytesToInt32(Input, InOffset + 8) ^ _expKey[keyCtr++];
            Int32 X1 = BytesToInt32(Input, InOffset + 12) ^ _expKey[keyCtr];
            Int32 T0, T1;
            keyCtr = _expKey.Length - 1;

            while (keyCtr > 8)
            {
                T0 = Fe0(X2);
                T1 = Fe3(X3);
                X1 ^= T0 + 2 * T1 + _expKey[keyCtr--];
                X0 = (X0 << 1 | (Int32)((UInt32)X0 >> 31)) ^ (T0 + T1 + _expKey[keyCtr--]);
                X1 = (Int32)((UInt32)X1 >> 1) | X1 << 31;

                T0 = Fe0(X0);
                T1 = Fe3(X1);
                X3 ^= T0 + 2 * T1 + _expKey[keyCtr--];
                X2 = (X2 << 1 | (Int32)((UInt32)X2 >> 31)) ^ (T0 + T1 + _expKey[keyCtr--]);
                X3 = (Int32)((UInt32)X3 >> 1) | X3 << 31;
            }

            keyCtr = 0;
            Int32ToBytes(X0 ^ _expKey[keyCtr++], Output, OutOffset);
            Int32ToBytes(X1 ^ _expKey[keyCtr++], Output, OutOffset + 4);
            Int32ToBytes(X2 ^ _expKey[keyCtr++], Output, OutOffset + 8);
            Int32ToBytes(X3 ^ _expKey[keyCtr], Output, OutOffset + 12);
        }

        private void Encrypt16(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            Int32 keyCtr = 0;
            Int32 X0 = BytesToInt32(Input, InOffset) ^ _expKey[keyCtr++];
            Int32 X1 = BytesToInt32(Input, InOffset + 4) ^ _expKey[keyCtr++];
            Int32 X2 = BytesToInt32(Input, InOffset + 8) ^ _expKey[keyCtr++];
            Int32 X3 = BytesToInt32(Input, InOffset + 12) ^ _expKey[keyCtr];
            Int32 T0, T1;
            keyCtr = 8;

            while (keyCtr < _expKey.Length)
            {
                T0 = Fe0(X0);
                T1 = Fe3(X1);
                X2 ^= T0 + T1 + _expKey[keyCtr++];
                X2 = (Int32)((UInt32)X2 >> 1) | X2 << 31;
                X3 = (X3 << 1 | (Int32)((UInt32)X3 >> 31)) ^ (T0 + 2 * T1 + _expKey[keyCtr++]);

                T0 = Fe0(X2);
                T1 = Fe3(X3);
                X0 ^= T0 + T1 + _expKey[keyCtr++];
                X0 = (Int32)((UInt32)X0 >> 1) | X0 << 31;
                X1 = (X1 << 1 | (Int32)((UInt32)X1 >> 31)) ^ (T0 + 2 * T1 + _expKey[keyCtr++]);
            }

            keyCtr = 4;
            Int32ToBytes(X2 ^ _expKey[keyCtr++], Output, OutOffset);
            Int32ToBytes(X3 ^ _expKey[keyCtr++], Output, OutOffset + 4);
            Int32ToBytes(X0 ^ _expKey[keyCtr++], Output, OutOffset + 8);
            Int32ToBytes(X1 ^ _expKey[keyCtr], Output, OutOffset + 12);
        }
        #endregion

        #region Helpers
        private Int32 BytesToInt32(byte[] Input, Int32 InOffset)
        {
            return (((byte)(Input[InOffset])) |
                ((byte)(Input[InOffset + 1]) << 8) |
                ((byte)(Input[InOffset + 2]) << 16) |
                ((byte)(Input[InOffset + 3]) << 24));
        }

        private void Int32ToBytes(Int32 Dword, byte[] Output, Int32 OutOffset)
        {
            Output[OutOffset] = (byte)Dword;
            Output[OutOffset + 1] = (byte)(Dword >> 8);
            Output[OutOffset + 2] = (byte)(Dword >> 16);
            Output[OutOffset + 3] = (byte)(Dword >> 24);
        }

        private Int32 F32(Int32 X, Int32[] Key, Int32 Count)
        {
            Int32 Y0 = (byte)X;
            Int32 Y1 = (byte)(X >> 8);
            Int32 Y2 = (byte)(X >> 16);
            Int32 Y3 = (byte)(X >> 24);

            // 512 key
            if (Count == 8)
            {
                Y0 = (byte)Q1[Y0] ^ (byte)Key[7];
                Y1 = (byte)Q0[Y1] ^ (byte)(Key[7] >> 8);
                Y2 = (byte)Q0[Y2] ^ (byte)(Key[7] >> 16);
                Y3 = (byte)Q1[Y3] ^ (byte)(Key[7] >> 24);

                Y0 = (byte)Q1[Y0] ^ (byte)Key[6];
                Y1 = (byte)Q1[Y1] ^ (byte)(Key[6] >> 8);
                Y2 = (byte)Q0[Y2] ^ (byte)(Key[6] >> 16);
                Y3 = (byte)Q0[Y3] ^ (byte)(Key[6] >> 24);

                Y0 = (byte)Q0[Y0] ^ (byte)Key[5];
                Y1 = (byte)Q1[Y1] ^ (byte)(Key[5] >> 8);
                Y2 = (byte)Q1[Y2] ^ (byte)(Key[5] >> 16);
                Y3 = (byte)Q0[Y3] ^ (byte)(Key[5] >> 24);

                Y0 = (byte)Q0[Y0] ^ (byte)Key[4];
                Y1 = (byte)Q0[Y1] ^ (byte)(Key[4] >> 8);
                Y2 = (byte)Q1[Y2] ^ (byte)(Key[4] >> 16);
                Y3 = (byte)Q1[Y3] ^ (byte)(Key[4] >> 24);
            }
            // 256 bit key
            if (Count > 3)
            {
                Y0 = (byte)Q1[Y0] ^ (byte)Key[3];
                Y1 = (byte)Q0[Y1] ^ (byte)(Key[3] >> 8);
                Y2 = (byte)Q0[Y2] ^ (byte)(Key[3] >> 16);
                Y3 = (byte)Q1[Y3] ^ (byte)(Key[3] >> 24);
            }
            // 192 bit key
            if (Count > 2)
            {
                Y0 = (byte)Q1[Y0] ^ (byte)Key[2];
                Y1 = (byte)Q1[Y1] ^ (byte)(Key[2] >> 8);
                Y2 = (byte)Q0[Y2] ^ (byte)(Key[2] >> 16);
                Y3 = (byte)Q0[Y3] ^ (byte)(Key[2] >> 24);
            }

            // return the MDS matrix multiply
            return MDS0[(byte)Q0[(byte)Q0[Y0] ^ (byte)Key[1]] ^ (byte)Key[0]] ^
                MDS1[(byte)Q0[(byte)Q1[Y1] ^ (byte)(Key[1] >> 8)] ^ (byte)(Key[0] >> 8)] ^
                MDS2[(byte)Q1[(byte)Q0[Y2] ^ (byte)(Key[1] >> 16)] ^ (byte)(Key[0] >> 16)] ^
                MDS3[(byte)Q1[(byte)Q1[Y3] ^ (byte)(Key[1] >> 24)] ^ (byte)(Key[0] >> 24)];
        }

        private Int32 Fe0(Int32 X)
        {
            return _sprBox[2 * (byte)X] ^
                _sprBox[2 * (byte)(X >> 8) + 0x001] ^
                _sprBox[2 * (byte)(X >> 16) + 0x200] ^
                _sprBox[2 * (byte)(X >> 24) + 0x201];
        }

        private Int32 Fe3(Int32 X)
        {
            return _sprBox[2 * (byte)(X >> 24)] ^
                _sprBox[2 * (byte)X + 0x001] ^
                _sprBox[2 * (byte)(X >> 8) + 0x200] ^
                _sprBox[2 * (byte)(X >> 16) + 0x201];
        }

        private Int32 LFSR1(Int32 X)
        {
            return (X >> 1) ^ (((X & 0x01) != 0) ? GF256_FDBK_2 : 0);
        }

        private Int32 LFSR2(Int32 X)
        {
            return (X >> 2) ^ (((X & 0x02) != 0) ? GF256_FDBK_2 : 0) ^
                (((X & 0x01) != 0) ? GF256_FDBK_4 : 0);
        }

        private Int32 MDSEncode(Int32 K0, Int32 K1)
        {
            Int32 ret = K1;
            for (int i = 0; i < 4; i++)
                ret = RSRem(ret);

            ret ^= K0;

            for (int i = 0; i < 4; i++)
                ret = RSRem(ret);

            return ret;
        }

        private Int32 MX(Int32 X)
        {
            return X ^ LFSR2(X);
        }

        private Int32 MXY(Int32 X)
        {
            return X ^ LFSR1(X) ^ LFSR2(X);
        }

        private Int32 RSRem(Int32 X)
        {
            Int32 b = (Int32)(((UInt32)X >> 24) & 0xff);
            Int32 g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
            Int32 g3 = ((Int32)((UInt32)b >> 1) ^ ((b & 0x01) != 0 ? (Int32)((UInt32)RS_GF_FDBK >> 1) : 0)) ^ g2;

            return ((X << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
        }
        #endregion

        #region Constant Tables
        private static readonly byte[] Q0 = 
        {
            0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
            0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
            0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
            0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
            0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
            0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
            0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
            0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
            0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
            0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
            0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
            0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
            0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
            0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
            0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
            0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0 
        };

        private static readonly byte[] Q1 = 
        { 
            0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
            0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
            0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
            0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
            0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
            0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
            0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
            0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
            0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
            0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
            0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
            0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
            0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
            0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
            0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
            0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91 
        };

        private static readonly Int32[] MDS0 = 
        {
            -1128517003, -320069133, 538985414, -1280062988, -623246373, 33721211, -488494085, -1633748280, 
            -909513654, -724301357, 404253670, 505323371, -1734865339, -1296942979, -1499016472, 640071499, 
            1010587606, -1819047374, -2105348392, 1381144829, 2071712823, -1145358479, 1532729329, 1195869153, 
            606354480, 1364320783, -1162164488, 1246425883, -1077983097, 218984698, -1330597114, 1970658879, 
            -757924514, 2105352378, 1717973422, 976921435, 1499012234, 0, -842165316, 437969053, 
            -1364317075, 2139073473, 724289457, -1094797042, -522149760, -1970663331, 993743570, 1684323029, 
            -656897888, -404249212, 1600120839, 454758676, 741130933, -50547568, 825304876, -2139069021, 
            1936927410, 202146163, 2037997388, 1802191188, 1263207058, 1397975412, -1802203338, -2088558767, 
            707409464, -993747792, 572704957, -707397542, -1111636996, 1212708960, -12702, 1280051094, 
            1094809452, -943200702, -336911113, 471602192, 1566401404, 909517352, 1734852647, -370561140, 
            1145370899, 336915093, -168445028, -808511289, 1061104932, -1061100730, 1920129851, 1414818928, 
            690572490, -252693021, 134807173, -960096309, -202158319, -1936923440, -1532733037, -892692808, 
            1751661478, -1195881085, 943204384, -437965057, -1381149025, 185304183, -926409277, -1717960756, 
            1482222851, 421108335, 235801096, -1785364801, 1886408768, -134795033, 1852755755, 522153698, 
            -1246413447, 151588620, 1633760426, 1465325186, -1616966847, -1650622406, 286352618, 623234489, 
            -1347428892, 1162152090, -538997340, -1549575017, -353708674, 892688602, -303181702, 1128528919, 
            -117912730, -67391084, 926405537, -84262883, -1027446723, -1263219472, 842161630, -1667468877, 
            1448535819, -471606670, -2021171033, 353704732, -101106961, 1667481553, 875866451, -1701149378, 
            -1313783153, 2088554803, -2004313306, 1027450463, -1583228948, -454762634, -2122214358, -1852767927, 
            252705665, -286348664, 370565614, -673746143, -1751648828, -1515870182, -16891925, 1835906521, 
            2021174981, -976917191, 488498585, 1987486925, 1044307117, -875862223, -1229568117, -269526271, 
            303177240, 1616954659, 1785376989, 1296954911, -825300658, -555844563, 1431674361, 2122209864, 
            555856463, 50559730, -1600117147, 1583225230, 1515873912, 1701137244, 1650609752, -33733351, 
            101119117, 1077970661, -218972520, 859024471, 387420263, 84250239, -387424763, 1330609508, 
            -1987482961, 269522275, 1953771446, 168457726, 1549570805, -1684310857, 757936956, 808507045, 
            774785486, 1229556201, 1179021928, 2004309316, -1465329440, -1768553395, 673758531, -1448531607, 
            -640059095, -2038001362, -774797396, -185316843, -1920133799, -690584920, -1179010038, 1111625118, 
            -151600786, 791656519, -572717345, 589510964, -859020747, -235813782, -1044311345, -2054820900, 
            -1886413278, 1903272393, -1869549376, -1431678053, 16904585, -1953766956, 1313770733, -1903267925, 
            -1414815214, 1869561506, -421112819, -606342574, -1835893829, -1212697086, 1768540719, 960092585, 
            -741143337, -1482218655, -1566397154, -1010591308, 1819034704, 117900548, 67403766, 656885442, 
            -1397971178, -791644635, 1347425158, -589498538, -2071717291, -505327351, 2054825406, 320073617
        };

        private static readonly Int32[] MDS1 = 
        {
            -1445381831, 1737496343, -1284399972, -388847962, 67438343, -40349102, -1553629056, 1994384612, 
            -1710734011, -1845343413, -2136940320, 2019973722, -455233617, -575640982, -775986333, 943073834, 
            223667942, -968679392, 895667404, -1732316430, 404623890, -148575253, -321412703, 1819754817, 
            1136470056, 1966259388, 936672123, 647727240, -93319923, 335103044, -1800274949, 1213890174, 
            -226884861, -790328180, -1958234442, 809247780, -2069501977, 1413573483, -553198115, 600137824, 
            424017405, 1537423930, 1030275778, 1494584717, -215880468, -1372494234, -1572966545, -2112465065, 
            1670713360, 22802415, -2092058440, 781289094, -642421395, 1361019779, -1689015638, 2086886749, 
            -1506056088, -348127490, -1512689616, -1104840070, 380087468, 202311945, -483004176, 1629726631, 
            -1057976176, -1934628375, 981507485, -174957476, 1937837068, 740766001, 628543696, 199710294, 
            -1149529454, 1323945678, -1980694271, 1805590046, 1403597876, 1791291889, -1264991293, -241738917, 
            -511490233, -429189096, -1110957534, 1158584472, -496099553, -188107853, -1238403980, 1724643576, 
            -855664231, -1779821548, 65886296, 1459084508, -723416181, 471536917, 514695842, -687025197, 
            -81009950, -1021458232, -1910940066, -1245565908, -376878775, -820854335, -1082223211, -1172275843, 
            -362540783, 2005142283, 963495365, -1351972471, 869366908, -912166543, 1657733119, 1899477947, 
            -2114253041, 2034087349, 156361185, -1378075074, 606945087, -844859786, -107129515, -655457662, 
            -444186560, -978421640, -1177737947, 1292146326, 1146451831, 134876686, -2045554608, -416221193, 
            -1579993289, 490797818, -1439407775, -309572018, 112439472, 1886147668, -1305840781, -766362821, 
            1091280799, 2072707586, -1601644328, 290452467, 828885963, -1035589849, 666920807, -1867186948, 
            539506744, -159448060, 1618495560, -13703707, -1777906612, 1548445029, -1312347349, -1418752370, 
            -1643298238, -1665403403, 1391647707, 468929098, 1604730173, -1822841692, 180140473, -281347591, 
            -1846602989, -2046949368, 1224839569, -295627242, 763158238, 1337073953, -1891454543, 1004237426, 
            1203253039, -2025275457, 1831644846, 1189331136, -698926020, 1048943258, 1764338089, 1685933903, 
            714375553, -834064850, -887634234, 801794409, -54280771, -1755536477, 90106088, 2060512749, 
            -1400385071, 2140013829, -709204892, 447260069, 1270294054, 247054014, -1486846073, 1526257109, 
            673330742, 336665371, 1071543669, 695851481, -2002063634, 1009986861, 1281325433, 45529015, 
            -1198077238, -631753419, -1331903292, 402408259, 1427801220, 536235341, -1977853607, 2100867762, 
            1470903091, -954675249, -1913387514, 1953059667, -1217094757, -990537833, -1621709395, 1926947811, 
            2127948522, 357233908, 580816783, 312650667, 1481532002, 132669279, -1713038051, 876159779, 
            1858205430, 1346661484, -564317646, 1752319558, 1697030304, -1131164211, -620504358, -121193798, 
            -923099490, -1467820330, 735014510, 1079013488, -588544635, -25884150, 847942547, -1534205985, 
            -900978391, 269753372, 561240023, -255019852, -754330412, 1561365130, 266490193, 0, 
            1872369945, -1646257638, 915379348, 1122420679, 1257032137, 1593692882, -1045725313, -522671960
        };

        private static readonly Int32[] MDS2 = 
        {
            -1133134798, -319558623, 549855299, -1275808823, -623126013, 41616011, -486809045, -1631019270, 
            -917845524, -724315127, 417732715, 510336671, -1740269554, -1300385224, -1494702382, 642459319, 
            1020673111, -1825401974, -2099739922, 1392333464, 2067233748, -1150174409, 1542544279, 1205946243, 
            607134780, 1359958498, -1158104378, 1243302643, -1081622712, 234491248, -1341738829, 1967093214, 
            -765537539, 2109373728, 1722705457, 979057315, 1502239004, 0, -843264621, 446503648, 
            -1368543700, 2143387563, 733031367, -1106329927, -528424800, -1973581296, 1003633490, 1691706554, 
            -660547448, -410720347, 1594318824, 454302481, 750070978, -57606988, 824979751, -2136768411, 
            1941074730, 208866433, 2035054943, 1800694593, 1267878658, 1400132457, -1808362353, -2091810017, 
            708323894, -995048292, 582820552, -715467272, -1107509821, 1214269560, -10289202, 1284918279, 
            1097613687, -951924762, -336073948, 470817812, 1568431459, 908604962, 1730635712, -376641105, 
            1142113529, 345314538, -174262853, -808988904, 1059340077, -1069104925, 1916498651, 1416647788, 
            701114700, -253497291, 142936318, -959724009, -216927409, -1932489500, -1533828007, -893859178, 
            1755736123, -1199327155, 941635624, -436214482, -1382044330, 192351108, -926693347, -1714644481, 
            1476614381, 426711450, 235408906, -1782606466, 1883271248, -135792848, 1848340175, 534912878, 
            -1250314947, 151783695, 1638555956, 1468159766, -1623089397, -1657102976, 300552548, 632890829, 
            -1343967267, 1167738120, -542842995, -1550343332, -360781099, 903492952, -310710832, 1125598204, 
            -127469365, -74122319, 933312467, -98698688, -1036139928, -1259293492, 853422685, -1665950607, 
            1443583719, -479009830, -2019063968, 354161947, -101713606, 1674666943, 877868201, -1707173243, 
            -1315983038, 2083749073, -2010740581, 1029651878, -1578327593, -461970209, -2127920748, -1857449727, 
            260116475, -293015894, 384702049, -685648013, -1748723723, -1524980312, -18088385, 1842965941, 
            2026207406, -986069651, 496573925, 1993176740, 1051541212, -885929113, -1232357817, -285085861, 
            303567390, 1612931269, 1792895664, 1293897206, -833696023, -567419268, 1442403741, 2118680154, 
            558834098, 66192250, -1603952602, 1586388505, 1517836902, 1700554059, 1649959502, -48628411, 
            109905652, 1088766086, -224857410, 861352876, 392632208, 92210574, -402266018, 1331974013, 
            -1984984726, 274927765, 1958114351, 184420981, 1559583890, -1682465932, 758918451, 816132310, 
            785264201, 1240025481, 1181238898, 2000975701, -1461671720, -1773300220, 675489981, -1452693207, 
            -651568775, -2043771247, -777203321, -199887798, -1923511019, -693578110, -1190479428, 1117667853, 
            -160500031, 793194424, -572531450, 590619449, -868889502, -244649532, -1043349230, -2049145365, 
            -1893560418, 1909027233, -1866428176, -1432638893, 25756145, -1949004831, 1324174988, -1901359505, 
            -1424839774, 1872916286, -435296684, -615326734, -1833201029, -1224558666, 1764714954, 967391705, 
            -740830452, -1486772445, -1575050579, -1011563623, 1817209924, 117704453, 83231871, 667035462, 
            -1407800153, -802828170, 1350979603, -598287113, -2074770406, -519446191, 2059303461, 328274927
        };

        private static readonly Int32[] MDS3 = 
        {
            -650532391, -1877514352, 1906094961, -760813358, 84345861, -1739391592, 1702929253, -538675489, 
            138779144, 38507010, -1595899744, 1717205094, -575675171, -1335173712, -1083977281, 908736566, 
            1424362836, 1126221379, 1657550178, -1091397442, 504502302, 619444004, -677253929, 2000776311, 
            -1121434691, 851211570, -730122284, -1685576037, 1879964272, -112978951, -1308912463, 1518225498, 
            2047079034, -460533532, 1203145543, 1009004604, -1511553883, 1097552961, 115203846, -983555131, 
            1174214981, -1556456541, 1757560168, 361584917, 569176865, 828812849, 1047503422, 374833686, 
            -1794088043, 1542390107, 1303937869, -1853477231, -1251092043, 528699679, 1403689811, 1667071075, 
            996714043, 1073670975, -701454890, 628801061, -1481894233, 252251151, 904979253, 598171939, 
            -258948880, -1343648593, -2137179520, -1839401582, -2129890431, 657533991, 1993352566, -413791257, 
            2073213819, -372355351, -251557391, -1625396321, -1456188503, -990811452, -1715227495, -1755582057, 
            -2092441213, 1796793963, -937247288, 244860174, 1847583342, -910953271, 796177967, -872913205, 
            -6697729, -367749654, -312998931, -136554761, -510929695, 454368283, -1381884243, 215209740, 
            736295723, 499696413, 425627161, -1037257278, -1991644791, 314691346, 2123743102, 545110560, 
            1678895716, -2079623292, 1841641837, 1787408234, -780389423, -1586378335, -822123826, 935031095, 
            -82869765, 1035303229, 1373702481, -599872036, 759112749, -1535717980, -1655309923, -293414674, 
            -2042567290, -1367816786, -853165619, 76958980, 1433879637, 168691722, 324044307, 821552944, 
            -751328813, 1090133312, 878815796, -1940984436, -1280309581, 1817473132, 712225322, 1379652178, 
            194986251, -1962771573, -1999069048, 1341329743, 1741369703, 1177010758, -1066981440, -1258516300, 
            674766888, 2131031679, 2018009208, 786825006, 122459655, 1264933963, -953437753, 1871620975, 
            222469645, -1141531461, -220507406, -213246989, -1505927258, 1503957849, -1128723780, 989458234, 
            -283930129, -32995842, 26298625, 1628892769, 2094935420, -1306439758, 1118932802, -613270565, 
            -1204861000, 1220511560, 749628716, -473938205, 1463604823, -2053489019, 698968361, 2102355069, 
            -1803474284, 1227804233, 398904087, -899076150, -1010959165, 1554224988, 1592264030, -789742896, 
            -2016301945, -1912242290, -1167796806, -1465574744, -1222227017, -1178726727, 1619502944, -120235272, 
            573974562, 286987281, -562741282, 2044275065, -1427208022, 858602547, 1601784927, -1229520202, 
            -1765099370, 1479924312, -1664831332, -62711812, 444880154, -162717706, 475630108, 951221560, 
            -1405921364, 416270104, -200897036, 1767076969, 1956362100, -174603019, 1454219094, -622628134, 
            -706052395, 1257510218, -1634786658, -1565846878, 1315067982, -396425240, -451044891, 958608441, 
            -1040814399, 1147949124, 1563614813, 1917216882, 648045862, -1815233389, 64674563, -960825146, 
            -90257158, -2099861374, -814863409, 1349533776, -343548693, 1963654773, -1970064758, -1914723187, 
            1277807180, 337383444, 1943478643, -860557108, 164942601, 277503248, -498003998, 0, 
            -1709609062, -535126560, -1886112113, -423148826, -322352404, -36544771, -1417690709, -660021032
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
                    if (_expKey != null)
                    {
                        Array.Clear(_expKey, 0, _expKey.Length);
                        _expKey = null;
                    }
                    if (_sprBox != null)
                    {
                        Array.Clear(_sprBox, 0, _sprBox.Length);
                        _sprBox = null;
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion

        #region Saved
        /*// move cipher to long?..
        private void PrintTable(int[] table)
        {
            string hex = "";
            for (int i = 0, j = 1; i < table.Length; i++, j++)
            {
                hex += String.Format("0x{0:X}", table[i]) + ", ";
                if (j % 8 == 0)
                {
                    System.Diagnostics.Debug.WriteLine(hex);
                    hex = "";
                }
            }
        }

        // is this faster as a long? test it
        private static readonly Int64[] MDS0X = 
        {
            0xBCBC3275, 0xECEC21F3, 0x202043C6, 0xB3B3C9F4, 0xDADA03DB, 0x2028B7B, 0xE2E22BFB, 0x9E9EFAC8, 
            0xC9C9EC4A, 0xD4D409D3, 0x18186BE6, 0x1E1E9F6B, 0x98980E45, 0xB2B2387D, 0xA6A6D2E8, 0x2626B74B, 
            0x3C3C57D6, 0x93938A32, 0x8282EED8, 0x525298FD, 0x7B7BD437, 0xBBBB3771, 0x5B5B97F1, 0x474783E1, 
            0x24243C30, 0x5151E20F, 0xBABAC6F8, 0x4A4AF31B, 0xBFBF4887, 0xD0D70FA, 0xB0B0B306, 0x7575DE3F, 
            0xD2D2FD5E, 0x7D7D20BA, 0x666631AE, 0x3A3AA35B, 0x59591C8A, 0x0, 0xCDCD93BC, 0x1A1AE09D, 
            0xAEAE2C6D, 0x7F7FABC1, 0x2B2BC7B1, 0xBEBEB90E, 0xE0E0A080, 0x8A8A105D, 0x3B3B52D2, 0x6464BAD5, 
            0xD8D888A0, 0xE7E7A584, 0x5F5FE807, 0x1B1B1114, 0x2C2CC2B5, 0xFCFCB490, 0x3131272C, 0x808065A3, 
            0x73732AB2, 0xC0C8173, 0x79795F4C, 0x6B6B4154, 0x4B4B0292, 0x53536974, 0x94948F36, 0x83831F51, 
            0x2A2A3638, 0xC4C49CB0, 0x2222C8BD, 0xD5D5F85A, 0xBDBDC3FC, 0x48487860, 0xFFFFCE62, 0x4C4C0796, 
            0x4141776C, 0xC7C7E642, 0xEBEB24F7, 0x1C1C1410, 0x5D5D637C, 0x36362228, 0x6767C027, 0xE9E9AF8C, 
            0x4444F913, 0x1414EA95, 0xF5F5BB9C, 0xCFCF18C7, 0x3F3F2D24, 0xC0C0E346, 0x7272DB3B, 0x54546C70, 
            0x29294CCA, 0xF0F035E3, 0x808FE85, 0xC6C617CB, 0xF3F34F11, 0x8C8CE4D0, 0xA4A45993, 0xCACA96B8, 
            0x68683BA6, 0xB8B84D83, 0x38382820, 0xE5E52EFF, 0xADAD569F, 0xB0B8477, 0xC8C81DC3, 0x9999FFCC, 
            0x5858ED03, 0x19199A6F, 0xE0E0A08, 0x95957EBF, 0x70705040, 0xF7F730E7, 0x6E6ECF2B, 0x1F1F6EE2, 
            0xB5B53D79, 0x9090F0C, 0x616134AA, 0x57571682, 0x9F9F0B41, 0x9D9D803A, 0x111164EA, 0x2525CDB9, 
            0xAFAFDDE4, 0x4545089A, 0xDFDF8DA4, 0xA3A35C97, 0xEAEAD57E, 0x353558DA, 0xEDEDD07A, 0x4343FC17, 
            0xF8F8CB66, 0xFBFBB194, 0x3737D3A1, 0xFAFA401D, 0xC2C2683D, 0xB4B4CCF0, 0x32325DDE, 0x9C9C71B3, 
            0x5656E70B, 0xE3E3DA72, 0x878760A7, 0x15151B1C, 0xF9F93AEF, 0x6363BFD1, 0x3434A953, 0x9A9A853E, 
            0xB1B1428F, 0x7C7CD133, 0x88889B26, 0x3D3DA65F, 0xA1A1D7EC, 0xE4E4DF76, 0x8181942A, 0x91910149, 
            0xF0FFB81, 0xEEEEAA88, 0x161661EE, 0xD7D77321, 0x9797F5C4, 0xA5A5A81A, 0xFEFE3FEB, 0x6D6DB5D9, 
            0x7878AEC5, 0xC5C56D39, 0x1D1DE599, 0x7676A4CD, 0x3E3EDCAD, 0xCBCB6731, 0xB6B6478B, 0xEFEF5B01, 
            0x12121E18, 0x6060C523, 0x6A6AB0DD, 0x4D4DF61F, 0xCECEE94E, 0xDEDE7C2D, 0x55559DF9, 0x7E7E5A48, 
            0x2121B24F, 0x3037AF2, 0xA0A02665, 0x5E5E198E, 0x5A5A6678, 0x65654B5C, 0x62624E58, 0xFDFD4519, 
            0x606F48D, 0x404086E5, 0xF2F2BE98, 0x3333AC57, 0x17179067, 0x5058E7F, 0xE8E85E05, 0x4F4F7D64, 
            0x89896AAF, 0x10109563, 0x74742FB6, 0xA0A75FE, 0x5C5C92F5, 0x9B9B74B7, 0x2D2D333C, 0x3030D6A5, 
            0x2E2E49CE, 0x494989E9, 0x46467268, 0x77775544, 0xA8A8D8E0, 0x9696044D, 0x2828BD43, 0xA9A92969, 
            0xD9D97929, 0x8686912E, 0xD1D187AC, 0xF4F44A15, 0x8D8D1559, 0xD6D682A8, 0xB9B9BC0A, 0x42420D9E, 
            0xF6F6C16E, 0x2F2FB847, 0xDDDD06DF, 0x23233934, 0xCCCC6235, 0xF1F1C46A, 0xC1C112CF, 0x8585EBDC, 
            0x8F8F9E22, 0x7171A1C9, 0x9090F0C0, 0xAAAA539B, 0x101F189, 0x8B8BE1D4, 0x4E4E8CED, 0x8E8E6FAB, 
            0xABABA212, 0x6F6F3EA2, 0xE6E6540D, 0xDBDBF252, 0x92927BBB, 0xB7B7B602, 0x6969CA2F, 0x3939D9A9, 
            0xD3D30CD7, 0xA7A72361, 0xA2A2AD1E, 0xC3C399B4, 0x6C6C4450, 0x7070504, 0x4047FF6, 0x272746C2, 
            0xACACA716, 0xD0D07625, 0x50501386, 0xDCDCF756, 0x84841A55, 0xE1E15109, 0x7A7A25BE, 0x1313EF91
        };

        private static readonly Int64[] MDS1X = 
        {
            0xA9D93939, 0x67901717, 0xB3719C9C, 0xE8D2A6A6, 0x4050707, 0xFD985252, 0xA3658080, 0x76DFE4E4, 
            0x9A084545, 0x92024B4B, 0x80A0E0E0, 0x78665A5A, 0xE4DDAFAF, 0xDDB06A6A, 0xD1BF6363, 0x38362A2A, 
            0xD54E6E6, 0xC6432020, 0x3562CCCC, 0x98BEF2F2, 0x181E1212, 0xF724EBEB, 0xECD7A1A1, 0x6C774141, 
            0x43BD2828, 0x7532BCBC, 0x37D47B7B, 0x269B8888, 0xFA700D0D, 0x13F94444, 0x94B1FBFB, 0x485A7E7E, 
            0xF27A0303, 0xD0E48C8C, 0x8B47B6B6, 0x303C2424, 0x84A5E7E7, 0x54416B6B, 0xDF06DDDD, 0x23C56060, 
            0x1945FDFD, 0x5BA33A3A, 0x3D68C2C2, 0x59158D8D, 0xF321ECEC, 0xAE316666, 0xA23E6F6F, 0x82165757, 
            0x63951010, 0x15BEFEF, 0x834DB8B8, 0x2E918686, 0xD9B56D6D, 0x511F8383, 0x9B53AAAA, 0x7C635D5D, 
            0xA63B6868, 0xEB3FFEFE, 0xA5D63030, 0xBE257A7A, 0x16A7ACAC, 0xC0F0909, 0xE335F0F0, 0x6123A7A7, 
            0xC0F09090, 0x8CAFE9E9, 0x3A809D9D, 0xF5925C5C, 0x73810C0C, 0x2C273131, 0x2576D0D0, 0xBE75656, 
            0xBB7B9292, 0x4EE9CECE, 0x89F10101, 0x6B9F1E1E, 0x53A93434, 0x6AC4F1F1, 0xB499C3C3, 0xF1975B5B, 
            0xE1834747, 0xE66B1818, 0xBDC82222, 0x450E9898, 0xE26E1F1F, 0xF4C9B3B3, 0xB62F7474, 0x66CBF8F8, 
            0xCCFF9999, 0x95EA1414, 0x3ED5858, 0x56F7DCDC, 0xD4E18B8B, 0x1C1B1515, 0x1EADA2A2, 0xD70CD3D3, 
            0xFB2BE2E2, 0xC31DC8C8, 0x8E195E5E, 0xB5C22C2C, 0xE9894949, 0xCF12C1C1, 0xBF7E9595, 0xBA207D7D, 
            0xEA641111, 0x77840B0B, 0x396DC5C5, 0xAF6A8989, 0x33D17C7C, 0xC9A17171, 0x62CEFFFF, 0x7137BBBB, 
            0x81FB0F0F, 0x793DB5B5, 0x951E1E1, 0xADDC3E3E, 0x242D3F3F, 0xCDA47676, 0xF99D5555, 0xD8EE8282, 
            0xE5864040, 0xC5AE7878, 0xB9CD2525, 0x4D049696, 0x44557777, 0x80A0E0E, 0x86135050, 0xE730F7F7, 
            0xA1D33737, 0x1D40FAFA, 0xAA346161, 0xED8C4E4E, 0x6B3B0B0, 0x706C5454, 0xB22A7373, 0xD2523B3B, 
            0x410B9F9F, 0x7B8B0202, 0xA088D8D8, 0x114FF3F3, 0x3167CBCB, 0xC2462727, 0x27C06767, 0x90B4FCFC, 
            0x20283838, 0xF67F0404, 0x60784848, 0xFF2EE5E5, 0x96074C4C, 0x5C4B6565, 0xB1C72B2B, 0xAB6F8E8E, 
            0x9E0D4242, 0x9CBBF5F5, 0x52F2DBDB, 0x1BF34A4A, 0x5FA63D3D, 0x9359A4A4, 0xABCB9B9, 0xEF3AF9F9, 
            0x91EF1313, 0x85FE0808, 0x49019191, 0xEE611616, 0x2D7CDEDE, 0x4FB22121, 0x8F42B1B1, 0x3BDB7272, 
            0x47B82F2F, 0x8748BFBF, 0x6D2CAEAE, 0x46E3C0C0, 0xD6573C3C, 0x3E859A9A, 0x6929A9A9, 0x647D4F4F, 
            0x2A948181, 0xCE492E2E, 0xCB17C6C6, 0x2FCA6969, 0xFCC3BDBD, 0x975CA3A3, 0x55EE8E8, 0x7AD0EDED, 
            0xAC87D1D1, 0x7F8E0505, 0xD5BA6464, 0x1AA8A5A5, 0x4BB72626, 0xEB9BEBE, 0xA7608787, 0x5AF8D5D5, 
            0x28223636, 0x14111B1B, 0x3FDE7575, 0x2979D9D9, 0x88AAEEEE, 0x3C332D2D, 0x4C5F7979, 0x2B6B7B7, 
            0xB896CACA, 0xDA583535, 0xB09CC4C4, 0x17FC4343, 0x551A8484, 0x1FF64D4D, 0x8A1C5959, 0x7D38B2B2, 
            0x57AC3333, 0xC718CFCF, 0x8DF40606, 0x74695353, 0xB7749B9B, 0xC4F59797, 0x9F56ADAD, 0x72DAE3E3, 
            0x7ED5EAEA, 0x154AF4F4, 0x229E8F8F, 0x12A2ABAB, 0x584E6262, 0x7E85F5F, 0x99E51D1D, 0x34392323, 
            0x6EC1F6F6, 0x50446C6C, 0xDE5D3232, 0x68724646, 0x6526A0A0, 0xBC93CDCD, 0xDB03DADA, 0xF8C6BABA, 
            0xC8FA9E9E, 0xA882D6D6, 0x2BCF6E6E, 0x40507070, 0xDCEB8585, 0xFE750A0A, 0x328A9393, 0xA48DDFDF, 
            0xCA4C2929, 0x10141C1C, 0x2173D7D7, 0xF0CCB4B4, 0xD309D4D4, 0x5D108A8A, 0xFE25151, 0x0, 
            0x6F9A1919, 0x9DE01A1A, 0x368F9494, 0x42E6C7C7, 0x4AECC9C9, 0x5EFDD2D2, 0xC1AB7F7F, 0xE0D8A8A8
        };

        private static readonly Int64[] MDS2X = 
        {
            0xBC75BC32, 0xECF3EC21, 0x20C62043, 0xB3F4B3C9, 0xDADBDA03, 0x27B028B, 0xE2FBE22B, 0x9EC89EFA, 
            0xC94AC9EC, 0xD4D3D409, 0x18E6186B, 0x1E6B1E9F, 0x9845980E, 0xB27DB238, 0xA6E8A6D2, 0x264B26B7, 
            0x3CD63C57, 0x9332938A, 0x82D882EE, 0x52FD5298, 0x7B377BD4, 0xBB71BB37, 0x5BF15B97, 0x47E14783, 
            0x2430243C, 0x510F51E2, 0xBAF8BAC6, 0x4A1B4AF3, 0xBF87BF48, 0xDFA0D70, 0xB006B0B3, 0x753F75DE, 
            0xD25ED2FD, 0x7DBA7D20, 0x66AE6631, 0x3A5B3AA3, 0x598A591C, 0x0, 0xCDBCCD93, 0x1A9D1AE0, 
            0xAE6DAE2C, 0x7FC17FAB, 0x2BB12BC7, 0xBE0EBEB9, 0xE080E0A0, 0x8A5D8A10, 0x3BD23B52, 0x64D564BA, 
            0xD8A0D888, 0xE784E7A5, 0x5F075FE8, 0x1B141B11, 0x2CB52CC2, 0xFC90FCB4, 0x312C3127, 0x80A38065, 
            0x73B2732A, 0xC730C81, 0x794C795F, 0x6B546B41, 0x4B924B02, 0x53745369, 0x9436948F, 0x8351831F, 
            0x2A382A36, 0xC4B0C49C, 0x22BD22C8, 0xD55AD5F8, 0xBDFCBDC3, 0x48604878, 0xFF62FFCE, 0x4C964C07, 
            0x416C4177, 0xC742C7E6, 0xEBF7EB24, 0x1C101C14, 0x5D7C5D63, 0x36283622, 0x672767C0, 0xE98CE9AF, 
            0x441344F9, 0x149514EA, 0xF59CF5BB, 0xCFC7CF18, 0x3F243F2D, 0xC046C0E3, 0x723B72DB, 0x5470546C, 
            0x29CA294C, 0xF0E3F035, 0x88508FE, 0xC6CBC617, 0xF311F34F, 0x8CD08CE4, 0xA493A459, 0xCAB8CA96, 
            0x68A6683B, 0xB883B84D, 0x38203828, 0xE5FFE52E, 0xAD9FAD56, 0xB770B84, 0xC8C3C81D, 0x99CC99FF, 
            0x580358ED, 0x196F199A, 0xE080E0A, 0x95BF957E, 0x70407050, 0xF7E7F730, 0x6E2B6ECF, 0x1FE21F6E, 
            0xB579B53D, 0x90C090F, 0x61AA6134, 0x57825716, 0x9F419F0B, 0x9D3A9D80, 0x11EA1164, 0x25B925CD, 
            0xAFE4AFDD, 0x459A4508, 0xDFA4DF8D, 0xA397A35C, 0xEA7EEAD5, 0x35DA3558, 0xED7AEDD0, 0x431743FC, 
            0xF866F8CB, 0xFB94FBB1, 0x37A137D3, 0xFA1DFA40, 0xC23DC268, 0xB4F0B4CC, 0x32DE325D, 0x9CB39C71, 
            0x560B56E7, 0xE372E3DA, 0x87A78760, 0x151C151B, 0xF9EFF93A, 0x63D163BF, 0x345334A9, 0x9A3E9A85, 
            0xB18FB142, 0x7C337CD1, 0x8826889B, 0x3D5F3DA6, 0xA1ECA1D7, 0xE476E4DF, 0x812A8194, 0x91499101, 
            0xF810FFB, 0xEE88EEAA, 0x16EE1661, 0xD721D773, 0x97C497F5, 0xA51AA5A8, 0xFEEBFE3F, 0x6DD96DB5, 
            0x78C578AE, 0xC539C56D, 0x1D991DE5, 0x76CD76A4, 0x3EAD3EDC, 0xCB31CB67, 0xB68BB647, 0xEF01EF5B, 
            0x1218121E, 0x602360C5, 0x6ADD6AB0, 0x4D1F4DF6, 0xCE4ECEE9, 0xDE2DDE7C, 0x55F9559D, 0x7E487E5A, 
            0x214F21B2, 0x3F2037A, 0xA065A026, 0x5E8E5E19, 0x5A785A66, 0x655C654B, 0x6258624E, 0xFD19FD45, 
            0x68D06F4, 0x40E54086, 0xF298F2BE, 0x335733AC, 0x17671790, 0x57F058E, 0xE805E85E, 0x4F644F7D, 
            0x89AF896A, 0x10631095, 0x74B6742F, 0xAFE0A75, 0x5CF55C92, 0x9BB79B74, 0x2D3C2D33, 0x30A530D6, 
            0x2ECE2E49, 0x49E94989, 0x46684672, 0x77447755, 0xA8E0A8D8, 0x964D9604, 0x284328BD, 0xA969A929, 
            0xD929D979, 0x862E8691, 0xD1ACD187, 0xF415F44A, 0x8D598D15, 0xD6A8D682, 0xB90AB9BC, 0x429E420D, 
            0xF66EF6C1, 0x2F472FB8, 0xDDDFDD06, 0x23342339, 0xCC35CC62, 0xF16AF1C4, 0xC1CFC112, 0x85DC85EB, 
            0x8F228F9E, 0x71C971A1, 0x90C090F0, 0xAA9BAA53, 0x18901F1, 0x8BD48BE1, 0x4EED4E8C, 0x8EAB8E6F, 
            0xAB12ABA2, 0x6FA26F3E, 0xE60DE654, 0xDB52DBF2, 0x92BB927B, 0xB702B7B6, 0x692F69CA, 0x39A939D9, 
            0xD3D7D30C, 0xA761A723, 0xA21EA2AD, 0xC3B4C399, 0x6C506C44, 0x7040705, 0x4F6047F, 0x27C22746, 
            0xAC16ACA7, 0xD025D076, 0x50865013, 0xDC56DCF7, 0x8455841A, 0xE109E151, 0x7ABE7A25, 0x139113EF
        };

        private static readonly Int64[] MDS3X = 
        {
            0xD939A9D9, 0x90176790, 0x719CB371, 0xD2A6E8D2, 0x5070405, 0x9852FD98, 0x6580A365, 0xDFE476DF, 
            0x8459A08, 0x24B9202, 0xA0E080A0, 0x665A7866, 0xDDAFE4DD, 0xB06ADDB0, 0xBF63D1BF, 0x362A3836, 
            0x54E60D54, 0x4320C643, 0x62CC3562, 0xBEF298BE, 0x1E12181E, 0x24EBF724, 0xD7A1ECD7, 0x77416C77, 
            0xBD2843BD, 0x32BC7532, 0xD47B37D4, 0x9B88269B, 0x700DFA70, 0xF94413F9, 0xB1FB94B1, 0x5A7E485A, 
            0x7A03F27A, 0xE48CD0E4, 0x47B68B47, 0x3C24303C, 0xA5E784A5, 0x416B5441, 0x6DDDF06, 0xC56023C5, 
            0x45FD1945, 0xA33A5BA3, 0x68C23D68, 0x158D5915, 0x21ECF321, 0x3166AE31, 0x3E6FA23E, 0x16578216, 
            0x95106395, 0x5BEF015B, 0x4DB8834D, 0x91862E91, 0xB56DD9B5, 0x1F83511F, 0x53AA9B53, 0x635D7C63, 
            0x3B68A63B, 0x3FFEEB3F, 0xD630A5D6, 0x257ABE25, 0xA7AC16A7, 0xF090C0F, 0x35F0E335, 0x23A76123, 
            0xF090C0F0, 0xAFE98CAF, 0x809D3A80, 0x925CF592, 0x810C7381, 0x27312C27, 0x76D02576, 0xE7560BE7, 
            0x7B92BB7B, 0xE9CE4EE9, 0xF10189F1, 0x9F1E6B9F, 0xA93453A9, 0xC4F16AC4, 0x99C3B499, 0x975BF197, 
            0x8347E183, 0x6B18E66B, 0xC822BDC8, 0xE98450E, 0x6E1FE26E, 0xC9B3F4C9, 0x2F74B62F, 0xCBF866CB, 
            0xFF99CCFF, 0xEA1495EA, 0xED5803ED, 0xF7DC56F7, 0xE18BD4E1, 0x1B151C1B, 0xADA21EAD, 0xCD3D70C, 
            0x2BE2FB2B, 0x1DC8C31D, 0x195E8E19, 0xC22CB5C2, 0x8949E989, 0x12C1CF12, 0x7E95BF7E, 0x207DBA20, 
            0x6411EA64, 0x840B7784, 0x6DC5396D, 0x6A89AF6A, 0xD17C33D1, 0xA171C9A1, 0xCEFF62CE, 0x37BB7137, 
            0xFB0F81FB, 0x3DB5793D, 0x51E10951, 0xDC3EADDC, 0x2D3F242D, 0xA476CDA4, 0x9D55F99D, 0xEE82D8EE, 
            0x8640E586, 0xAE78C5AE, 0xCD25B9CD, 0x4964D04, 0x55774455, 0xA0E080A, 0x13508613, 0x30F7E730, 
            0xD337A1D3, 0x40FA1D40, 0x3461AA34, 0x8C4EED8C, 0xB3B006B3, 0x6C54706C, 0x2A73B22A, 0x523BD252, 
            0xB9F410B, 0x8B027B8B, 0x88D8A088, 0x4FF3114F, 0x67CB3167, 0x4627C246, 0xC06727C0, 0xB4FC90B4, 
            0x28382028, 0x7F04F67F, 0x78486078, 0x2EE5FF2E, 0x74C9607, 0x4B655C4B, 0xC72BB1C7, 0x6F8EAB6F, 
            0xD429E0D, 0xBBF59CBB, 0xF2DB52F2, 0xF34A1BF3, 0xA63D5FA6, 0x59A49359, 0xBCB90ABC, 0x3AF9EF3A, 
            0xEF1391EF, 0xFE0885FE, 0x1914901, 0x6116EE61, 0x7CDE2D7C, 0xB2214FB2, 0x42B18F42, 0xDB723BDB, 
            0xB82F47B8, 0x48BF8748, 0x2CAE6D2C, 0xE3C046E3, 0x573CD657, 0x859A3E85, 0x29A96929, 0x7D4F647D, 
            0x94812A94, 0x492ECE49, 0x17C6CB17, 0xCA692FCA, 0xC3BDFCC3, 0x5CA3975C, 0x5EE8055E, 0xD0ED7AD0, 
            0x87D1AC87, 0x8E057F8E, 0xBA64D5BA, 0xA8A51AA8, 0xB7264BB7, 0xB9BE0EB9, 0x6087A760, 0xF8D55AF8, 
            0x22362822, 0x111B1411, 0xDE753FDE, 0x79D92979, 0xAAEE88AA, 0x332D3C33, 0x5F794C5F, 0xB6B702B6, 
            0x96CAB896, 0x5835DA58, 0x9CC4B09C, 0xFC4317FC, 0x1A84551A, 0xF64D1FF6, 0x1C598A1C, 0x38B27D38, 
            0xAC3357AC, 0x18CFC718, 0xF4068DF4, 0x69537469, 0x749BB774, 0xF597C4F5, 0x56AD9F56, 0xDAE372DA, 
            0xD5EA7ED5, 0x4AF4154A, 0x9E8F229E, 0xA2AB12A2, 0x4E62584E, 0xE85F07E8, 0xE51D99E5, 0x39233439, 
            0xC1F66EC1, 0x446C5044, 0x5D32DE5D, 0x72466872, 0x26A06526, 0x93CDBC93, 0x3DADB03, 0xC6BAF8C6, 
            0xFA9EC8FA, 0x82D6A882, 0xCF6E2BCF, 0x50704050, 0xEB85DCEB, 0x750AFE75, 0x8A93328A, 0x8DDFA48D, 
            0x4C29CA4C, 0x141C1014, 0x73D72173, 0xCCB4F0CC, 0x9D4D309, 0x108A5D10, 0xE2510FE2, 0x0, 
            0x9A196F9A, 0xE01A9DE0, 0x8F94368F, 0xE6C742E6, 0xECC94AEC, 0xFDD25EFD, 0xAB7FC1AB, 0xD8A8E0D8
        };*/
        #endregion
    }
}
