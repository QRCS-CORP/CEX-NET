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
/// Based in part on the Twofish block cipher designed by Bruce Schneier, John Kelsey, 
/// Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson.
/// Twofish white paper: https://www.schneier.com/paper-twofish-paper.pdf
/// 
/// Based in part on the Rijndael cipher written by Joan Daemen and Vincent Rijmen.
/// Rijndael Specification: http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
/// 
/// Portions of this code based on the Mono RijndaelManagedTransform class:
/// https://github.com/mono/mono/blob/effa4c07ba850bedbe1ff54b2a5df281c058ebcb/mcs/class/corlib/System.Security.Cryptography/RijndaelManagedTransform.cs
/// Portions of this code also based on Bouncy Castle Java release 1.51:
/// http://bouncycastle.org/latest_releases.html
/// 
/// A stream cipher implementation based on the Twofish and Rijndael block ciphers,
/// using HKDF with a SHA512 HMAC for expanded key generation.
/// Merges both diffusion engines during rounds processing.
/// Twofish + Rijndael Merged Cryptographic Primitives (TR-MCP or Fusion).
/// Minimum key size is 192 bytes.
/// Valid Key sizes are 64 + multiples of 128 bytes (IKm + Salt).
/// Valid block size is 16 byte wide.
/// The number of Diffusion Rounds are configuarable.
/// Valid Rounds assignments are 16, 18, 20, 22, 24, 26, 28, 30 and 32, default is 16.
/// Written by John Underhill, December 11, 2014
/// contact: steppenwolfe_2000@yahoo.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Ciphers
{
    /// Fusion: Twofish Rijndael Merged
    /// Minimum key size is 192 bytes.
    /// Valid Key sizes are 64 + multiples of 128 bytes (IKm + Salt).
    /// Valid block sizes is 16 byte wide.
    /// The number of Diffusion Rounds are configuarable.
    /// Valid Rounds assignments are 16, 18, 20, 22, 24, 26, 28, 30 and 32, default is 16.
    public class Fusion : IStreamCipher, IDisposable
    {
        #region Constants
        private const Int32 BLOCK_SIZE = 16;
        private const Int32 DEFAULT_ROUNDS = 16;
        private const Int32 DEFAULT_SUBKEYS = 40;
        private const Int32 GF256_FDBK = 0x169; // primitive polynomial for GF(256)
        private const Int32 GF256_FDBK_2 = GF256_FDBK / 2;
        private const Int32 GF256_FDBK_4 = GF256_FDBK / 4;
        private const Int32 IKM_SIZE = 64;
        private const Int32 KEY_BITS = 256;
        private const Int32 MIN_KEYSIZE = 192;
        private const Int32 RS_GF_FDBK = 0x14D; // field generator
        private const Int32 SALT_SIZE = 128;
        private const Int32 SK_STEP = 0x02020202;
        private const Int32 SK_BUMP = 0x01010101;
        private const Int32 SK_ROTL = 9;
        private const Int32 ENGINE_MAXPULL = 102400000;
        private const Int64 MAX_COUNTER = Int64.MaxValue - (ENGINE_MAXPULL + 1);
        private const Int32 MIN_PARALLEL = 1024;
        #endregion

        #region Fields
        private Int32[] _exKey;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private bool _isParallel = false;
        private Int32 Rounds = DEFAULT_ROUNDS;
        private Int32[] _sBox = new Int32[1024];
        // configurable nonce can create a unique distribution, can be byte(0)
        private byte[] _hkdfInfo = System.Text.Encoding.ASCII.GetBytes("Fusion version 1 information string");
        private byte[] _ctrVector;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Key has been expanded
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
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
        /// Get: Available Encryption Key Sizes in bits (192, 320, 448, 576 bytes)
        /// </summary>
        public static Int32[] KeySizes
        {
            get { return new Int32[] { 1536, 2560, 3584, 4608 }; }
        }

        /// <summary>
        /// Get: Minimum input size to trigger parallel processing
        /// </summary>
        public int MinParallelSize
        {
            get { return MIN_PARALLEL; }
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
            get { return "Fusion"; }
        }

        /// <summary>
        /// Processor count
        /// </summary>
        private int ProcessorCount { get; set; }
        #endregion

        #region Constructor
        public Fusion(int Rounds = DEFAULT_ROUNDS)
        {
            if (Rounds != 16 && Rounds != 18 && Rounds != 20 && Rounds != 22 && Rounds != 24 && Rounds != 26 && Rounds != 28 && Rounds != 30 && Rounds != 32)
                throw new ArgumentOutOfRangeException("Invalid rounds size! Sizes supported are 16, 18, 20, 22, 24, 26, 28, 30 and 32.");

            this.ProcessorCount = Environment.ProcessorCount;

            if (this.ProcessorCount > 1 && this.ProcessorCount % 2 != 0)
                this.ProcessorCount--;

            this.IsParallel = this.ProcessorCount > 1;
            this.Rounds = Rounds;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// <param name="Encryption">Using Encryption or Decryption mode</param>
        /// <param name="KeyParam">Contains cipher key, valid sizes are: 128, 192, 256 and 512 bytes</param>
        public void Init(KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new ArgumentOutOfRangeException("Invalid key! Key can not be null.");
            if (KeyParam.Key.Length < MIN_KEYSIZE)
                throw new ArgumentOutOfRangeException("Invalid key size! Key must be at least " + MIN_KEYSIZE + " bytes (" + MIN_KEYSIZE * 8 + " bit).");
            if ((KeyParam.Key.Length - IKM_SIZE) % SALT_SIZE != 0)
                throw new ArgumentOutOfRangeException("Invalid key size! Key must be (length - IKm length: " + IKM_SIZE + " bytes) + divisible of SHA512 block size (128 bytes).");
            if (KeyParam.IV == null)
                throw new ArgumentOutOfRangeException("Invalid IV! IV can not be null.");
            if (KeyParam.IV.Length != BLOCK_SIZE)
                throw new ArgumentOutOfRangeException("Invalid IV size! IV must be at exactly " + BLOCK_SIZE + " bytes (" + BLOCK_SIZE * 8 + " bit).");

            _exKey = ExpandKey(KeyParam.Key);
            _ctrVector = (byte[])KeyParam.IV.Clone();
        }


        /// <summary>
        /// Encrypt/Decrypt an array of bytes
        /// </summary>
        /// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
        /// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            if (Output.Length < 1)
                throw new ArgumentOutOfRangeException("Invalid output array! Size can not be less than 1 byte.");
            if (Output.Length > Input.Length)
                throw new ArgumentOutOfRangeException("Invalid input array! Input array size can not be smaller than output array size.");

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
                int alignedSize = Output.Length / BLOCK_SIZE;
                int chunkSize = (alignedSize / count) * BLOCK_SIZE;
                int roundSize = chunkSize * count;
                int subSize = (chunkSize / BLOCK_SIZE);

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
            int size = Output.Length - OutOffset;

            if (Input.Length - InOffset < size)
                throw new ArgumentOutOfRangeException("Invalid input array! Size can not be less than output array.");

            byte[] inData = new byte[size];
            byte[] outData = new byte[size];

            Buffer.BlockCopy(Input, InOffset, inData, 0, size);

            Transform(inData, outData);

            Buffer.BlockCopy(outData, 0, Output, OutOffset, size);
        }

        /// <summary>
        /// Transform a block of bytes within an array.
        /// Init must be called before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Length">Number of bytes to process</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
        public void Transform(byte[] Input, int InOffset, int Length, byte[] Output, int OutOffset)
        {
            if (Input.Length - InOffset < Length)
                throw new ArgumentOutOfRangeException("Invalid input array! Size can not be less than output array.");

            byte[] inData = new byte[Length];
            byte[] outData = new byte[Length];

            Buffer.BlockCopy(Input, InOffset, inData, 0, Length);

            Transform(inData, outData);

            Buffer.BlockCopy(outData, 0, Output, OutOffset, Length);
        }
        #endregion

        #region Random Generator
        /// <summary>
        /// Generate an array of p-rand bytes
        /// </summary>
        /// <param name="Size">Size of expected output</param>
        /// <param name="Counter">Counter 1</param>
        /// <param name="Ctr2">Counter 2</param>
        /// <returns>Random array of bytes</returns>
        private byte[] Generate(Int32 Size, byte[] Counter)
        {
            // align to upper divisible of block size
            Int32 alignedSize = (Size % BLOCK_SIZE == 0 ? Size : Size + BLOCK_SIZE - (Size % BLOCK_SIZE));
            Int32 lastBlock = alignedSize - BLOCK_SIZE;
            byte[] outputBlock = new byte[BLOCK_SIZE];
            byte[] outputData = new byte[Size];

            for (int i = 0; i < alignedSize; i += BLOCK_SIZE)
            {
                // encrypt counter
                CTransform(Counter,0, outputBlock, 0);

                // copy to output
                if (i != lastBlock)
                {
                    // copy transform to output
                    Buffer.BlockCopy(outputBlock, 0, outputData, i, BLOCK_SIZE);
                }
                else
                {
                    // copy last block
                    int finalSize = (Size % BLOCK_SIZE) == 0 ? BLOCK_SIZE : (Size % BLOCK_SIZE);
                    Buffer.BlockCopy(outputBlock, 0, outputData, i, finalSize);
                }

                // increment counter
                Increment(Counter);
            }

            return outputData;
        }

        /// <summary>
        /// Incremental counter with carry
        /// </summary>
        /// <param name="Counter">Counter</param>
        private void Increment(byte[] Counter)
        {
            int i = Counter.Length;
            while (--i >= 0 && ++Counter[i] == 0) { }
        }

        /// <summary>
        /// Increase a byte array by a numerical value
        /// </summary>
        /// <param name="Counter">Original byte array</param>
        /// <param name="Size">Number to increase by</param>
        /// <returns>Array with increased value [byte[]]</returns>
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
        #endregion

        #region Transform
        private void CTransform(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            Int32 keyCtr = 0;
            Int32 M0, M1;

            Int32 X0 = BytesToWord(Input, InOffset) ^ _exKey[keyCtr++];
            Int32 X1 = BytesToWord(Input, InOffset + 4) ^ _exKey[keyCtr++];
            Int32 X2 = BytesToWord(Input, InOffset + 8) ^ _exKey[keyCtr++];
            Int32 X3 = BytesToWord(Input, InOffset + 12) ^ _exKey[keyCtr];

            keyCtr = 8;

            Int32 X4 = (Int32)(T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3]) ^ _exKey[keyCtr++];
            Int32 X5 = (Int32)(T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X0]) ^ _exKey[keyCtr++];
            Int32 X6 = (Int32)(T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1]) ^ _exKey[keyCtr++];
            Int32 X7 = (Int32)(T0[(byte)(X3 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2]) ^ _exKey[keyCtr++];

            while (keyCtr < _exKey.Length)
            {
                // rijndael round
                X0 = (Int32)(T0[(byte)(X4 >> 24)] ^ T1[(byte)(X5 >> 16)] ^ T2[(byte)(X6 >> 8)] ^ T3[(byte)X7]) ^ _exKey[keyCtr++];
                X1 = (Int32)(T0[(byte)(X5 >> 24)] ^ T1[(byte)(X6 >> 16)] ^ T2[(byte)(X7 >> 8)] ^ T3[(byte)X4]) ^ _exKey[keyCtr++];
                X2 = (Int32)(T0[(byte)(X6 >> 24)] ^ T1[(byte)(X7 >> 16)] ^ T2[(byte)(X4 >> 8)] ^ T3[(byte)X5]) ^ _exKey[keyCtr++];
                X3 = (Int32)(T0[(byte)(X7 >> 24)] ^ T1[(byte)(X4 >> 16)] ^ T2[(byte)(X5 >> 8)] ^ T3[(byte)X6]) ^ _exKey[keyCtr++];

                // twofish round
                M0 = Fe0(X0);
                M1 = Fe3(X1);
                X2 ^= M0 + M1 + _exKey[keyCtr++];
                X2 = (Int32)((UInt32)X2 >> 1) | X2 << 31;
                X3 = (X3 << 1 | (Int32)((UInt32)X3 >> 31)) ^ (M0 + 2 * M1 + _exKey[keyCtr++]);

                X4 = (Int32)(T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3]) ^ _exKey[keyCtr++];
                X5 = (Int32)(T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X0]) ^ _exKey[keyCtr++];
                X6 = (Int32)(T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1]) ^ _exKey[keyCtr++];
                X7 = (Int32)(T0[(byte)(X3 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2]) ^ _exKey[keyCtr++];

                M0 = Fe0(X6);
                M1 = Fe3(X7);
                X4 ^= M0 + M1 + _exKey[keyCtr++];
                X4 = (Int32)((UInt32)X4 >> 1) | X4 << 31;
                X5 = (X5 << 1 | (Int32)((UInt32)X5 >> 31)) ^ (M0 + 2 * M1 + _exKey[keyCtr++]);
            }

            keyCtr = 4;
            WordToBytes(X2 ^ _exKey[keyCtr++], Output, OutOffset);
            WordToBytes(X3 ^ _exKey[keyCtr++], Output, OutOffset + 4);
            WordToBytes(X0 ^ _exKey[keyCtr++], Output, OutOffset + 8);
            WordToBytes(X1 ^ _exKey[keyCtr], Output, OutOffset + 12);
        }

        private Int32[] ExpandKey(byte[] Key)
        {
            Int32 Y0, Y1, Y2, Y3;
            int k64Cnt = 8;
            int keyCtr = 0;
            int keySize = (this.Rounds * 6) + 12;
            int kbtSize = keySize * 4;
            byte[] rawKey = new byte[kbtSize];
            byte[] sbKey = new byte[32];
            Int32[] eKm = new Int32[k64Cnt];
            Int32[] oKm = new Int32[k64Cnt];
            Int32[] wK = new Int32[keySize];

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
                gen.Generate(kbtSize, rawKey, 0);
            }

            // copy bytes to working key
            Buffer.BlockCopy(rawKey, 0, wK, 0, kbtSize);

            for (int i = 0; i < k64Cnt; i++)
            {
                // round key material
                eKm[i] = BytesToWord(rawKey, keyCtr);
                keyCtr += 4;
                oKm[i] = BytesToWord(rawKey, keyCtr);
                keyCtr += 4;
                // sbox key material
                WordToBytes(MDSEncode(eKm[i], oKm[i]), sbKey, ((4 * k64Cnt) - 4) - (i * 4));
            }

            keyCtr = 0;

            // create keyed sbox
            while (keyCtr < KEY_BITS)
            {
                Y0 = Y1 = Y2 = Y3 = keyCtr;

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

                Y0 = (byte)Q1[Y0] ^ sbKey[12];
                Y1 = (byte)Q0[Y1] ^ sbKey[13];
                Y2 = (byte)Q0[Y2] ^ sbKey[14];
                Y3 = (byte)Q1[Y3] ^ sbKey[15];

                Y0 = (byte)Q1[Y0] ^ sbKey[8];
                Y1 = (byte)Q1[Y1] ^ sbKey[9];
                Y2 = (byte)Q0[Y2] ^ sbKey[10];
                Y3 = (byte)Q0[Y3] ^ sbKey[11];

                // sbox members as MDS matrix multiplies 
                _sBox[keyCtr * 2] = MDS0[(byte)Q0[(byte)Q0[Y0] ^ sbKey[4]] ^ sbKey[0]];
                _sBox[keyCtr * 2 + 1] = MDS1[(byte)Q0[Q1[Y1] ^ sbKey[5]] ^ sbKey[1]];
                _sBox[(keyCtr * 2) + 0x200] = MDS2[(byte)Q1[(byte)Q0[Y2] ^ sbKey[6]] ^ sbKey[2]];
                _sBox[keyCtr++ * 2 + 0x201] = MDS3[(byte)Q1[(byte)Q1[Y3] ^ sbKey[7]] ^ sbKey[3]];
            }

            // key processed
            this.IsInitialized = true;
            return wK;
        }
        #endregion

        #region Helpers
        private Int32 BytesToWord(byte[] Data, Int32 Offset)
        {
            return (((byte)(Data[Offset])) |
                ((byte)(Data[Offset + 1]) << 8) |
                ((byte)(Data[Offset + 2]) << 16) |
                ((byte)(Data[Offset + 3]) << 24));
        }

        private Int32 Fe0(Int32 X)
        {
            return _sBox[2 * (byte)X] ^
                _sBox[2 * (byte)(X >> 8) + 0x001] ^
                _sBox[2 * (byte)(X >> 16) + 0x200] ^
                _sBox[2 * (byte)(X >> 24) + 0x201];
        }

        private Int32 Fe3(Int32 X)
        {
            return _sBox[2 * (byte)(X >> 24)] ^
                _sBox[2 * (byte)X + 0x001] ^
                _sBox[2 * (byte)(X >> 8) + 0x200] ^
                _sBox[2 * (byte)(X >> 16) + 0x201];
        }

        private Int32 LFSR1(Int32 X)
        {
            return (X >> 1) ^
                (((X & 0x01) != 0) ? GF256_FDBK_2 : 0);
        }

        private Int32 LFSR2(Int32 X)
        {
            return (X >> 2) ^
                (((X & 0x02) != 0) ? GF256_FDBK_2 : 0) ^
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

        private void WordToBytes(Int32 Word, byte[] Data, Int32 Offset)
        {
            Data[Offset] = (byte)Word;
            Data[Offset + 1] = (byte)(Word >> 8);
            Data[Offset + 2] = (byte)(Word >> 16);
            Data[Offset + 3] = (byte)(Word >> 24);
        }
        #endregion

        #region Rijndael
        #region Constant Tables
        private static readonly UInt32[] T0 = {
			0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d, 0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554,
			0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d, 0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a,
			0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87, 0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b,
			0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea, 0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b,
			0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a, 0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f,
			0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108, 0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f,
			0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e, 0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5,
			0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d, 0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f,
			0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e, 0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb,
			0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce, 0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497,
			0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c, 0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed,
			0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b, 0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a,
			0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16, 0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594,
			0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81, 0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3,
			0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a, 0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504,
			0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163, 0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d,
			0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f, 0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739,
			0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47, 0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395,
			0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f, 0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883,
			0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c, 0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76,
			0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e, 0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4,
			0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6, 0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b,
			0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7, 0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0,
			0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25, 0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818,
			0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72, 0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651,
			0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21, 0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85,
			0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa, 0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12,
			0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0, 0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9,
			0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133, 0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7,
			0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920, 0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a,
			0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17, 0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8,
			0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11, 0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a,
		};

        private static readonly UInt32[] T1 = {
			0xa5c66363, 0x84f87c7c, 0x99ee7777, 0x8df67b7b, 0x0dfff2f2, 0xbdd66b6b, 0xb1de6f6f, 0x5491c5c5,
			0x50603030, 0x03020101, 0xa9ce6767, 0x7d562b2b, 0x19e7fefe, 0x62b5d7d7, 0xe64dabab, 0x9aec7676,
			0x458fcaca, 0x9d1f8282, 0x4089c9c9, 0x87fa7d7d, 0x15effafa, 0xebb25959, 0xc98e4747, 0x0bfbf0f0,
			0xec41adad, 0x67b3d4d4, 0xfd5fa2a2, 0xea45afaf, 0xbf239c9c, 0xf753a4a4, 0x96e47272, 0x5b9bc0c0,
			0xc275b7b7, 0x1ce1fdfd, 0xae3d9393, 0x6a4c2626, 0x5a6c3636, 0x417e3f3f, 0x02f5f7f7, 0x4f83cccc,
			0x5c683434, 0xf451a5a5, 0x34d1e5e5, 0x08f9f1f1, 0x93e27171, 0x73abd8d8, 0x53623131, 0x3f2a1515,
			0x0c080404, 0x5295c7c7, 0x65462323, 0x5e9dc3c3, 0x28301818, 0xa1379696, 0x0f0a0505, 0xb52f9a9a,
			0x090e0707, 0x36241212, 0x9b1b8080, 0x3ddfe2e2, 0x26cdebeb, 0x694e2727, 0xcd7fb2b2, 0x9fea7575,
			0x1b120909, 0x9e1d8383, 0x74582c2c, 0x2e341a1a, 0x2d361b1b, 0xb2dc6e6e, 0xeeb45a5a, 0xfb5ba0a0,
			0xf6a45252, 0x4d763b3b, 0x61b7d6d6, 0xce7db3b3, 0x7b522929, 0x3edde3e3, 0x715e2f2f, 0x97138484,
			0xf5a65353, 0x68b9d1d1, 0x00000000, 0x2cc1eded, 0x60402020, 0x1fe3fcfc, 0xc879b1b1, 0xedb65b5b,
			0xbed46a6a, 0x468dcbcb, 0xd967bebe, 0x4b723939, 0xde944a4a, 0xd4984c4c, 0xe8b05858, 0x4a85cfcf,
			0x6bbbd0d0, 0x2ac5efef, 0xe54faaaa, 0x16edfbfb, 0xc5864343, 0xd79a4d4d, 0x55663333, 0x94118585,
			0xcf8a4545, 0x10e9f9f9, 0x06040202, 0x81fe7f7f, 0xf0a05050, 0x44783c3c, 0xba259f9f, 0xe34ba8a8,
			0xf3a25151, 0xfe5da3a3, 0xc0804040, 0x8a058f8f, 0xad3f9292, 0xbc219d9d, 0x48703838, 0x04f1f5f5,
			0xdf63bcbc, 0xc177b6b6, 0x75afdada, 0x63422121, 0x30201010, 0x1ae5ffff, 0x0efdf3f3, 0x6dbfd2d2,
			0x4c81cdcd, 0x14180c0c, 0x35261313, 0x2fc3ecec, 0xe1be5f5f, 0xa2359797, 0xcc884444, 0x392e1717,
			0x5793c4c4, 0xf255a7a7, 0x82fc7e7e, 0x477a3d3d, 0xacc86464, 0xe7ba5d5d, 0x2b321919, 0x95e67373,
			0xa0c06060, 0x98198181, 0xd19e4f4f, 0x7fa3dcdc, 0x66442222, 0x7e542a2a, 0xab3b9090, 0x830b8888,
			0xca8c4646, 0x29c7eeee, 0xd36bb8b8, 0x3c281414, 0x79a7dede, 0xe2bc5e5e, 0x1d160b0b, 0x76addbdb,
			0x3bdbe0e0, 0x56643232, 0x4e743a3a, 0x1e140a0a, 0xdb924949, 0x0a0c0606, 0x6c482424, 0xe4b85c5c,
			0x5d9fc2c2, 0x6ebdd3d3, 0xef43acac, 0xa6c46262, 0xa8399191, 0xa4319595, 0x37d3e4e4, 0x8bf27979,
			0x32d5e7e7, 0x438bc8c8, 0x596e3737, 0xb7da6d6d, 0x8c018d8d, 0x64b1d5d5, 0xd29c4e4e, 0xe049a9a9,
			0xb4d86c6c, 0xfaac5656, 0x07f3f4f4, 0x25cfeaea, 0xafca6565, 0x8ef47a7a, 0xe947aeae, 0x18100808,
			0xd56fbaba, 0x88f07878, 0x6f4a2525, 0x725c2e2e, 0x24381c1c, 0xf157a6a6, 0xc773b4b4, 0x5197c6c6,
			0x23cbe8e8, 0x7ca1dddd, 0x9ce87474, 0x213e1f1f, 0xdd964b4b, 0xdc61bdbd, 0x860d8b8b, 0x850f8a8a,
			0x90e07070, 0x427c3e3e, 0xc471b5b5, 0xaacc6666, 0xd8904848, 0x05060303, 0x01f7f6f6, 0x121c0e0e,
			0xa3c26161, 0x5f6a3535, 0xf9ae5757, 0xd069b9b9, 0x91178686, 0x5899c1c1, 0x273a1d1d, 0xb9279e9e,
			0x38d9e1e1, 0x13ebf8f8, 0xb32b9898, 0x33221111, 0xbbd26969, 0x70a9d9d9, 0x89078e8e, 0xa7339494,
			0xb62d9b9b, 0x223c1e1e, 0x92158787, 0x20c9e9e9, 0x4987cece, 0xffaa5555, 0x78502828, 0x7aa5dfdf,
			0x8f038c8c, 0xf859a1a1, 0x80098989, 0x171a0d0d, 0xda65bfbf, 0x31d7e6e6, 0xc6844242, 0xb8d06868,
			0xc3824141, 0xb0299999, 0x775a2d2d, 0x111e0f0f, 0xcb7bb0b0, 0xfca85454, 0xd66dbbbb, 0x3a2c1616,
		};

        private static readonly UInt32[] T2 = {
			0x63a5c663, 0x7c84f87c, 0x7799ee77, 0x7b8df67b, 0xf20dfff2, 0x6bbdd66b, 0x6fb1de6f, 0xc55491c5,
			0x30506030, 0x01030201, 0x67a9ce67, 0x2b7d562b, 0xfe19e7fe, 0xd762b5d7, 0xabe64dab, 0x769aec76,
			0xca458fca, 0x829d1f82, 0xc94089c9, 0x7d87fa7d, 0xfa15effa, 0x59ebb259, 0x47c98e47, 0xf00bfbf0,
			0xadec41ad, 0xd467b3d4, 0xa2fd5fa2, 0xafea45af, 0x9cbf239c, 0xa4f753a4, 0x7296e472, 0xc05b9bc0,
			0xb7c275b7, 0xfd1ce1fd, 0x93ae3d93, 0x266a4c26, 0x365a6c36, 0x3f417e3f, 0xf702f5f7, 0xcc4f83cc,
			0x345c6834, 0xa5f451a5, 0xe534d1e5, 0xf108f9f1, 0x7193e271, 0xd873abd8, 0x31536231, 0x153f2a15,
			0x040c0804, 0xc75295c7, 0x23654623, 0xc35e9dc3, 0x18283018, 0x96a13796, 0x050f0a05, 0x9ab52f9a,
			0x07090e07, 0x12362412, 0x809b1b80, 0xe23ddfe2, 0xeb26cdeb, 0x27694e27, 0xb2cd7fb2, 0x759fea75,
			0x091b1209, 0x839e1d83, 0x2c74582c, 0x1a2e341a, 0x1b2d361b, 0x6eb2dc6e, 0x5aeeb45a, 0xa0fb5ba0,
			0x52f6a452, 0x3b4d763b, 0xd661b7d6, 0xb3ce7db3, 0x297b5229, 0xe33edde3, 0x2f715e2f, 0x84971384,
			0x53f5a653, 0xd168b9d1, 0x00000000, 0xed2cc1ed, 0x20604020, 0xfc1fe3fc, 0xb1c879b1, 0x5bedb65b,
			0x6abed46a, 0xcb468dcb, 0xbed967be, 0x394b7239, 0x4ade944a, 0x4cd4984c, 0x58e8b058, 0xcf4a85cf,
			0xd06bbbd0, 0xef2ac5ef, 0xaae54faa, 0xfb16edfb, 0x43c58643, 0x4dd79a4d, 0x33556633, 0x85941185,
			0x45cf8a45, 0xf910e9f9, 0x02060402, 0x7f81fe7f, 0x50f0a050, 0x3c44783c, 0x9fba259f, 0xa8e34ba8,
			0x51f3a251, 0xa3fe5da3, 0x40c08040, 0x8f8a058f, 0x92ad3f92, 0x9dbc219d, 0x38487038, 0xf504f1f5,
			0xbcdf63bc, 0xb6c177b6, 0xda75afda, 0x21634221, 0x10302010, 0xff1ae5ff, 0xf30efdf3, 0xd26dbfd2,
			0xcd4c81cd, 0x0c14180c, 0x13352613, 0xec2fc3ec, 0x5fe1be5f, 0x97a23597, 0x44cc8844, 0x17392e17,
			0xc45793c4, 0xa7f255a7, 0x7e82fc7e, 0x3d477a3d, 0x64acc864, 0x5de7ba5d, 0x192b3219, 0x7395e673,
			0x60a0c060, 0x81981981, 0x4fd19e4f, 0xdc7fa3dc, 0x22664422, 0x2a7e542a, 0x90ab3b90, 0x88830b88,
			0x46ca8c46, 0xee29c7ee, 0xb8d36bb8, 0x143c2814, 0xde79a7de, 0x5ee2bc5e, 0x0b1d160b, 0xdb76addb,
			0xe03bdbe0, 0x32566432, 0x3a4e743a, 0x0a1e140a, 0x49db9249, 0x060a0c06, 0x246c4824, 0x5ce4b85c,
			0xc25d9fc2, 0xd36ebdd3, 0xacef43ac, 0x62a6c462, 0x91a83991, 0x95a43195, 0xe437d3e4, 0x798bf279,
			0xe732d5e7, 0xc8438bc8, 0x37596e37, 0x6db7da6d, 0x8d8c018d, 0xd564b1d5, 0x4ed29c4e, 0xa9e049a9,
			0x6cb4d86c, 0x56faac56, 0xf407f3f4, 0xea25cfea, 0x65afca65, 0x7a8ef47a, 0xaee947ae, 0x08181008,
			0xbad56fba, 0x7888f078, 0x256f4a25, 0x2e725c2e, 0x1c24381c, 0xa6f157a6, 0xb4c773b4, 0xc65197c6,
			0xe823cbe8, 0xdd7ca1dd, 0x749ce874, 0x1f213e1f, 0x4bdd964b, 0xbddc61bd, 0x8b860d8b, 0x8a850f8a,
			0x7090e070, 0x3e427c3e, 0xb5c471b5, 0x66aacc66, 0x48d89048, 0x03050603, 0xf601f7f6, 0x0e121c0e,
			0x61a3c261, 0x355f6a35, 0x57f9ae57, 0xb9d069b9, 0x86911786, 0xc15899c1, 0x1d273a1d, 0x9eb9279e,
			0xe138d9e1, 0xf813ebf8, 0x98b32b98, 0x11332211, 0x69bbd269, 0xd970a9d9, 0x8e89078e, 0x94a73394,
			0x9bb62d9b, 0x1e223c1e, 0x87921587, 0xe920c9e9, 0xce4987ce, 0x55ffaa55, 0x28785028, 0xdf7aa5df,
			0x8c8f038c, 0xa1f859a1, 0x89800989, 0x0d171a0d, 0xbfda65bf, 0xe631d7e6, 0x42c68442, 0x68b8d068,
			0x41c38241, 0x99b02999, 0x2d775a2d, 0x0f111e0f, 0xb0cb7bb0, 0x54fca854, 0xbbd66dbb, 0x163a2c16,
		};

        private static readonly UInt32[] T3 = {
			0x6363a5c6, 0x7c7c84f8, 0x777799ee, 0x7b7b8df6, 0xf2f20dff, 0x6b6bbdd6, 0x6f6fb1de, 0xc5c55491,
			0x30305060, 0x01010302, 0x6767a9ce, 0x2b2b7d56, 0xfefe19e7, 0xd7d762b5, 0xababe64d, 0x76769aec,
			0xcaca458f, 0x82829d1f, 0xc9c94089, 0x7d7d87fa, 0xfafa15ef, 0x5959ebb2, 0x4747c98e, 0xf0f00bfb,
			0xadadec41, 0xd4d467b3, 0xa2a2fd5f, 0xafafea45, 0x9c9cbf23, 0xa4a4f753, 0x727296e4, 0xc0c05b9b,
			0xb7b7c275, 0xfdfd1ce1, 0x9393ae3d, 0x26266a4c, 0x36365a6c, 0x3f3f417e, 0xf7f702f5, 0xcccc4f83,
			0x34345c68, 0xa5a5f451, 0xe5e534d1, 0xf1f108f9, 0x717193e2, 0xd8d873ab, 0x31315362, 0x15153f2a,
			0x04040c08, 0xc7c75295, 0x23236546, 0xc3c35e9d, 0x18182830, 0x9696a137, 0x05050f0a, 0x9a9ab52f,
			0x0707090e, 0x12123624, 0x80809b1b, 0xe2e23ddf, 0xebeb26cd, 0x2727694e, 0xb2b2cd7f, 0x75759fea,
			0x09091b12, 0x83839e1d, 0x2c2c7458, 0x1a1a2e34, 0x1b1b2d36, 0x6e6eb2dc, 0x5a5aeeb4, 0xa0a0fb5b,
			0x5252f6a4, 0x3b3b4d76, 0xd6d661b7, 0xb3b3ce7d, 0x29297b52, 0xe3e33edd, 0x2f2f715e, 0x84849713,
			0x5353f5a6, 0xd1d168b9, 0x00000000, 0xeded2cc1, 0x20206040, 0xfcfc1fe3, 0xb1b1c879, 0x5b5bedb6,
			0x6a6abed4, 0xcbcb468d, 0xbebed967, 0x39394b72, 0x4a4ade94, 0x4c4cd498, 0x5858e8b0, 0xcfcf4a85,
			0xd0d06bbb, 0xefef2ac5, 0xaaaae54f, 0xfbfb16ed, 0x4343c586, 0x4d4dd79a, 0x33335566, 0x85859411,
			0x4545cf8a, 0xf9f910e9, 0x02020604, 0x7f7f81fe, 0x5050f0a0, 0x3c3c4478, 0x9f9fba25, 0xa8a8e34b,
			0x5151f3a2, 0xa3a3fe5d, 0x4040c080, 0x8f8f8a05, 0x9292ad3f, 0x9d9dbc21, 0x38384870, 0xf5f504f1,
			0xbcbcdf63, 0xb6b6c177, 0xdada75af, 0x21216342, 0x10103020, 0xffff1ae5, 0xf3f30efd, 0xd2d26dbf,
			0xcdcd4c81, 0x0c0c1418, 0x13133526, 0xecec2fc3, 0x5f5fe1be, 0x9797a235, 0x4444cc88, 0x1717392e,
			0xc4c45793, 0xa7a7f255, 0x7e7e82fc, 0x3d3d477a, 0x6464acc8, 0x5d5de7ba, 0x19192b32, 0x737395e6,
			0x6060a0c0, 0x81819819, 0x4f4fd19e, 0xdcdc7fa3, 0x22226644, 0x2a2a7e54, 0x9090ab3b, 0x8888830b,
			0x4646ca8c, 0xeeee29c7, 0xb8b8d36b, 0x14143c28, 0xdede79a7, 0x5e5ee2bc, 0x0b0b1d16, 0xdbdb76ad,
			0xe0e03bdb, 0x32325664, 0x3a3a4e74, 0x0a0a1e14, 0x4949db92, 0x06060a0c, 0x24246c48, 0x5c5ce4b8,
			0xc2c25d9f, 0xd3d36ebd, 0xacacef43, 0x6262a6c4, 0x9191a839, 0x9595a431, 0xe4e437d3, 0x79798bf2,
			0xe7e732d5, 0xc8c8438b, 0x3737596e, 0x6d6db7da, 0x8d8d8c01, 0xd5d564b1, 0x4e4ed29c, 0xa9a9e049,
			0x6c6cb4d8, 0x5656faac, 0xf4f407f3, 0xeaea25cf, 0x6565afca, 0x7a7a8ef4, 0xaeaee947, 0x08081810,
			0xbabad56f, 0x787888f0, 0x25256f4a, 0x2e2e725c, 0x1c1c2438, 0xa6a6f157, 0xb4b4c773, 0xc6c65197,
			0xe8e823cb, 0xdddd7ca1, 0x74749ce8, 0x1f1f213e, 0x4b4bdd96, 0xbdbddc61, 0x8b8b860d, 0x8a8a850f,
			0x707090e0, 0x3e3e427c, 0xb5b5c471, 0x6666aacc, 0x4848d890, 0x03030506, 0xf6f601f7, 0x0e0e121c,
			0x6161a3c2, 0x35355f6a, 0x5757f9ae, 0xb9b9d069, 0x86869117, 0xc1c15899, 0x1d1d273a, 0x9e9eb927,
			0xe1e138d9, 0xf8f813eb, 0x9898b32b, 0x11113322, 0x6969bbd2, 0xd9d970a9, 0x8e8e8907, 0x9494a733,
			0x9b9bb62d, 0x1e1e223c, 0x87879215, 0xe9e920c9, 0xcece4987, 0x5555ffaa, 0x28287850, 0xdfdf7aa5,
			0x8c8c8f03, 0xa1a1f859, 0x89898009, 0x0d0d171a, 0xbfbfda65, 0xe6e631d7, 0x4242c684, 0x6868b8d0,
			0x4141c382, 0x9999b029, 0x2d2d775a, 0x0f0f111e, 0xb0b0cb7b, 0x5454fca8, 0xbbbbd66d, 0x16163a2c,
		};

        private static readonly UInt32[] IT0 = {
			0x51f4a750, 0x7e416553, 0x1a17a4c3, 0x3a275e96, 0x3bab6bcb, 0x1f9d45f1, 0xacfa58ab, 0x4be30393,
			0x2030fa55, 0xad766df6, 0x88cc7691, 0xf5024c25, 0x4fe5d7fc, 0xc52acbd7, 0x26354480, 0xb562a38f,
			0xdeb15a49, 0x25ba1b67, 0x45ea0e98, 0x5dfec0e1, 0xc32f7502, 0x814cf012, 0x8d4697a3, 0x6bd3f9c6,
			0x038f5fe7, 0x15929c95, 0xbf6d7aeb, 0x955259da, 0xd4be832d, 0x587421d3, 0x49e06929, 0x8ec9c844,
			0x75c2896a, 0xf48e7978, 0x99583e6b, 0x27b971dd, 0xbee14fb6, 0xf088ad17, 0xc920ac66, 0x7dce3ab4,
			0x63df4a18, 0xe51a3182, 0x97513360, 0x62537f45, 0xb16477e0, 0xbb6bae84, 0xfe81a01c, 0xf9082b94,
			0x70486858, 0x8f45fd19, 0x94de6c87, 0x527bf8b7, 0xab73d323, 0x724b02e2, 0xe31f8f57, 0x6655ab2a,
			0xb2eb2807, 0x2fb5c203, 0x86c57b9a, 0xd33708a5, 0x302887f2, 0x23bfa5b2, 0x02036aba, 0xed16825c,
			0x8acf1c2b, 0xa779b492, 0xf307f2f0, 0x4e69e2a1, 0x65daf4cd, 0x0605bed5, 0xd134621f, 0xc4a6fe8a,
			0x342e539d, 0xa2f355a0, 0x058ae132, 0xa4f6eb75, 0x0b83ec39, 0x4060efaa, 0x5e719f06, 0xbd6e1051,
			0x3e218af9, 0x96dd063d, 0xdd3e05ae, 0x4de6bd46, 0x91548db5, 0x71c45d05, 0x0406d46f, 0x605015ff,
			0x1998fb24, 0xd6bde997, 0x894043cc, 0x67d99e77, 0xb0e842bd, 0x07898b88, 0xe7195b38, 0x79c8eedb,
			0xa17c0a47, 0x7c420fe9, 0xf8841ec9, 0x00000000, 0x09808683, 0x322bed48, 0x1e1170ac, 0x6c5a724e,
			0xfd0efffb, 0x0f853856, 0x3daed51e, 0x362d3927, 0x0a0fd964, 0x685ca621, 0x9b5b54d1, 0x24362e3a,
			0x0c0a67b1, 0x9357e70f, 0xb4ee96d2, 0x1b9b919e, 0x80c0c54f, 0x61dc20a2, 0x5a774b69, 0x1c121a16,
			0xe293ba0a, 0xc0a02ae5, 0x3c22e043, 0x121b171d, 0x0e090d0b, 0xf28bc7ad, 0x2db6a8b9, 0x141ea9c8,
			0x57f11985, 0xaf75074c, 0xee99ddbb, 0xa37f60fd, 0xf701269f, 0x5c72f5bc, 0x44663bc5, 0x5bfb7e34,
			0x8b432976, 0xcb23c6dc, 0xb6edfc68, 0xb8e4f163, 0xd731dcca, 0x42638510, 0x13972240, 0x84c61120,
			0x854a247d, 0xd2bb3df8, 0xaef93211, 0xc729a16d, 0x1d9e2f4b, 0xdcb230f3, 0x0d8652ec, 0x77c1e3d0,
			0x2bb3166c, 0xa970b999, 0x119448fa, 0x47e96422, 0xa8fc8cc4, 0xa0f03f1a, 0x567d2cd8, 0x223390ef,
			0x87494ec7, 0xd938d1c1, 0x8ccaa2fe, 0x98d40b36, 0xa6f581cf, 0xa57ade28, 0xdab78e26, 0x3fadbfa4,
			0x2c3a9de4, 0x5078920d, 0x6a5fcc9b, 0x547e4662, 0xf68d13c2, 0x90d8b8e8, 0x2e39f75e, 0x82c3aff5,
			0x9f5d80be, 0x69d0937c, 0x6fd52da9, 0xcf2512b3, 0xc8ac993b, 0x10187da7, 0xe89c636e, 0xdb3bbb7b,
			0xcd267809, 0x6e5918f4, 0xec9ab701, 0x834f9aa8, 0xe6956e65, 0xaaffe67e, 0x21bccf08, 0xef15e8e6,
			0xbae79bd9, 0x4a6f36ce, 0xea9f09d4, 0x29b07cd6, 0x31a4b2af, 0x2a3f2331, 0xc6a59430, 0x35a266c0,
			0x744ebc37, 0xfc82caa6, 0xe090d0b0, 0x33a7d815, 0xf104984a, 0x41ecdaf7, 0x7fcd500e, 0x1791f62f,
			0x764dd68d, 0x43efb04d, 0xccaa4d54, 0xe49604df, 0x9ed1b5e3, 0x4c6a881b, 0xc12c1fb8, 0x4665517f,
			0x9d5eea04, 0x018c355d, 0xfa877473, 0xfb0b412e, 0xb3671d5a, 0x92dbd252, 0xe9105633, 0x6dd64713,
			0x9ad7618c, 0x37a10c7a, 0x59f8148e, 0xeb133c89, 0xcea927ee, 0xb761c935, 0xe11ce5ed, 0x7a47b13c,
			0x9cd2df59, 0x55f2733f, 0x1814ce79, 0x73c737bf, 0x53f7cdea, 0x5ffdaa5b, 0xdf3d6f14, 0x7844db86,
			0xcaaff381, 0xb968c43e, 0x3824342c, 0xc2a3405f, 0x161dc372, 0xbce2250c, 0x283c498b, 0xff0d9541,
			0x39a80171, 0x080cb3de, 0xd8b4e49c, 0x6456c190, 0x7bcb8461, 0xd532b670, 0x486c5c74, 0xd0b85742,
		};

        private static readonly UInt32[] IT1 = {
			0x5051f4a7, 0x537e4165, 0xc31a17a4, 0x963a275e, 0xcb3bab6b, 0xf11f9d45, 0xabacfa58, 0x934be303,
			0x552030fa, 0xf6ad766d, 0x9188cc76, 0x25f5024c, 0xfc4fe5d7, 0xd7c52acb, 0x80263544, 0x8fb562a3,
			0x49deb15a, 0x6725ba1b, 0x9845ea0e, 0xe15dfec0, 0x02c32f75, 0x12814cf0, 0xa38d4697, 0xc66bd3f9,
			0xe7038f5f, 0x9515929c, 0xebbf6d7a, 0xda955259, 0x2dd4be83, 0xd3587421, 0x2949e069, 0x448ec9c8,
			0x6a75c289, 0x78f48e79, 0x6b99583e, 0xdd27b971, 0xb6bee14f, 0x17f088ad, 0x66c920ac, 0xb47dce3a,
			0x1863df4a, 0x82e51a31, 0x60975133, 0x4562537f, 0xe0b16477, 0x84bb6bae, 0x1cfe81a0, 0x94f9082b,
			0x58704868, 0x198f45fd, 0x8794de6c, 0xb7527bf8, 0x23ab73d3, 0xe2724b02, 0x57e31f8f, 0x2a6655ab,
			0x07b2eb28, 0x032fb5c2, 0x9a86c57b, 0xa5d33708, 0xf2302887, 0xb223bfa5, 0xba02036a, 0x5ced1682,
			0x2b8acf1c, 0x92a779b4, 0xf0f307f2, 0xa14e69e2, 0xcd65daf4, 0xd50605be, 0x1fd13462, 0x8ac4a6fe,
			0x9d342e53, 0xa0a2f355, 0x32058ae1, 0x75a4f6eb, 0x390b83ec, 0xaa4060ef, 0x065e719f, 0x51bd6e10,
			0xf93e218a, 0x3d96dd06, 0xaedd3e05, 0x464de6bd, 0xb591548d, 0x0571c45d, 0x6f0406d4, 0xff605015,
			0x241998fb, 0x97d6bde9, 0xcc894043, 0x7767d99e, 0xbdb0e842, 0x8807898b, 0x38e7195b, 0xdb79c8ee,
			0x47a17c0a, 0xe97c420f, 0xc9f8841e, 0x00000000, 0x83098086, 0x48322bed, 0xac1e1170, 0x4e6c5a72,
			0xfbfd0eff, 0x560f8538, 0x1e3daed5, 0x27362d39, 0x640a0fd9, 0x21685ca6, 0xd19b5b54, 0x3a24362e,
			0xb10c0a67, 0x0f9357e7, 0xd2b4ee96, 0x9e1b9b91, 0x4f80c0c5, 0xa261dc20, 0x695a774b, 0x161c121a,
			0x0ae293ba, 0xe5c0a02a, 0x433c22e0, 0x1d121b17, 0x0b0e090d, 0xadf28bc7, 0xb92db6a8, 0xc8141ea9,
			0x8557f119, 0x4caf7507, 0xbbee99dd, 0xfda37f60, 0x9ff70126, 0xbc5c72f5, 0xc544663b, 0x345bfb7e,
			0x768b4329, 0xdccb23c6, 0x68b6edfc, 0x63b8e4f1, 0xcad731dc, 0x10426385, 0x40139722, 0x2084c611,
			0x7d854a24, 0xf8d2bb3d, 0x11aef932, 0x6dc729a1, 0x4b1d9e2f, 0xf3dcb230, 0xec0d8652, 0xd077c1e3,
			0x6c2bb316, 0x99a970b9, 0xfa119448, 0x2247e964, 0xc4a8fc8c, 0x1aa0f03f, 0xd8567d2c, 0xef223390,
			0xc787494e, 0xc1d938d1, 0xfe8ccaa2, 0x3698d40b, 0xcfa6f581, 0x28a57ade, 0x26dab78e, 0xa43fadbf,
			0xe42c3a9d, 0x0d507892, 0x9b6a5fcc, 0x62547e46, 0xc2f68d13, 0xe890d8b8, 0x5e2e39f7, 0xf582c3af,
			0xbe9f5d80, 0x7c69d093, 0xa96fd52d, 0xb3cf2512, 0x3bc8ac99, 0xa710187d, 0x6ee89c63, 0x7bdb3bbb,
			0x09cd2678, 0xf46e5918, 0x01ec9ab7, 0xa8834f9a, 0x65e6956e, 0x7eaaffe6, 0x0821bccf, 0xe6ef15e8,
			0xd9bae79b, 0xce4a6f36, 0xd4ea9f09, 0xd629b07c, 0xaf31a4b2, 0x312a3f23, 0x30c6a594, 0xc035a266,
			0x37744ebc, 0xa6fc82ca, 0xb0e090d0, 0x1533a7d8, 0x4af10498, 0xf741ecda, 0x0e7fcd50, 0x2f1791f6,
			0x8d764dd6, 0x4d43efb0, 0x54ccaa4d, 0xdfe49604, 0xe39ed1b5, 0x1b4c6a88, 0xb8c12c1f, 0x7f466551,
			0x049d5eea, 0x5d018c35, 0x73fa8774, 0x2efb0b41, 0x5ab3671d, 0x5292dbd2, 0x33e91056, 0x136dd647,
			0x8c9ad761, 0x7a37a10c, 0x8e59f814, 0x89eb133c, 0xeecea927, 0x35b761c9, 0xede11ce5, 0x3c7a47b1,
			0x599cd2df, 0x3f55f273, 0x791814ce, 0xbf73c737, 0xea53f7cd, 0x5b5ffdaa, 0x14df3d6f, 0x867844db,
			0x81caaff3, 0x3eb968c4, 0x2c382434, 0x5fc2a340, 0x72161dc3, 0x0cbce225, 0x8b283c49, 0x41ff0d95,
			0x7139a801, 0xde080cb3, 0x9cd8b4e4, 0x906456c1, 0x617bcb84, 0x70d532b6, 0x74486c5c, 0x42d0b857,
		};

        private static readonly UInt32[] IT2 = {
			0xa75051f4, 0x65537e41, 0xa4c31a17, 0x5e963a27, 0x6bcb3bab, 0x45f11f9d, 0x58abacfa, 0x03934be3,
			0xfa552030, 0x6df6ad76, 0x769188cc, 0x4c25f502, 0xd7fc4fe5, 0xcbd7c52a, 0x44802635, 0xa38fb562,
			0x5a49deb1, 0x1b6725ba, 0x0e9845ea, 0xc0e15dfe, 0x7502c32f, 0xf012814c, 0x97a38d46, 0xf9c66bd3,
			0x5fe7038f, 0x9c951592, 0x7aebbf6d, 0x59da9552, 0x832dd4be, 0x21d35874, 0x692949e0, 0xc8448ec9,
			0x896a75c2, 0x7978f48e, 0x3e6b9958, 0x71dd27b9, 0x4fb6bee1, 0xad17f088, 0xac66c920, 0x3ab47dce,
			0x4a1863df, 0x3182e51a, 0x33609751, 0x7f456253, 0x77e0b164, 0xae84bb6b, 0xa01cfe81, 0x2b94f908,
			0x68587048, 0xfd198f45, 0x6c8794de, 0xf8b7527b, 0xd323ab73, 0x02e2724b, 0x8f57e31f, 0xab2a6655,
			0x2807b2eb, 0xc2032fb5, 0x7b9a86c5, 0x08a5d337, 0x87f23028, 0xa5b223bf, 0x6aba0203, 0x825ced16,
			0x1c2b8acf, 0xb492a779, 0xf2f0f307, 0xe2a14e69, 0xf4cd65da, 0xbed50605, 0x621fd134, 0xfe8ac4a6,
			0x539d342e, 0x55a0a2f3, 0xe132058a, 0xeb75a4f6, 0xec390b83, 0xefaa4060, 0x9f065e71, 0x1051bd6e,
			0x8af93e21, 0x063d96dd, 0x05aedd3e, 0xbd464de6, 0x8db59154, 0x5d0571c4, 0xd46f0406, 0x15ff6050,
			0xfb241998, 0xe997d6bd, 0x43cc8940, 0x9e7767d9, 0x42bdb0e8, 0x8b880789, 0x5b38e719, 0xeedb79c8,
			0x0a47a17c, 0x0fe97c42, 0x1ec9f884, 0x00000000, 0x86830980, 0xed48322b, 0x70ac1e11, 0x724e6c5a,
			0xfffbfd0e, 0x38560f85, 0xd51e3dae, 0x3927362d, 0xd9640a0f, 0xa621685c, 0x54d19b5b, 0x2e3a2436,
			0x67b10c0a, 0xe70f9357, 0x96d2b4ee, 0x919e1b9b, 0xc54f80c0, 0x20a261dc, 0x4b695a77, 0x1a161c12,
			0xba0ae293, 0x2ae5c0a0, 0xe0433c22, 0x171d121b, 0x0d0b0e09, 0xc7adf28b, 0xa8b92db6, 0xa9c8141e,
			0x198557f1, 0x074caf75, 0xddbbee99, 0x60fda37f, 0x269ff701, 0xf5bc5c72, 0x3bc54466, 0x7e345bfb,
			0x29768b43, 0xc6dccb23, 0xfc68b6ed, 0xf163b8e4, 0xdccad731, 0x85104263, 0x22401397, 0x112084c6,
			0x247d854a, 0x3df8d2bb, 0x3211aef9, 0xa16dc729, 0x2f4b1d9e, 0x30f3dcb2, 0x52ec0d86, 0xe3d077c1,
			0x166c2bb3, 0xb999a970, 0x48fa1194, 0x642247e9, 0x8cc4a8fc, 0x3f1aa0f0, 0x2cd8567d, 0x90ef2233,
			0x4ec78749, 0xd1c1d938, 0xa2fe8cca, 0x0b3698d4, 0x81cfa6f5, 0xde28a57a, 0x8e26dab7, 0xbfa43fad,
			0x9de42c3a, 0x920d5078, 0xcc9b6a5f, 0x4662547e, 0x13c2f68d, 0xb8e890d8, 0xf75e2e39, 0xaff582c3,
			0x80be9f5d, 0x937c69d0, 0x2da96fd5, 0x12b3cf25, 0x993bc8ac, 0x7da71018, 0x636ee89c, 0xbb7bdb3b,
			0x7809cd26, 0x18f46e59, 0xb701ec9a, 0x9aa8834f, 0x6e65e695, 0xe67eaaff, 0xcf0821bc, 0xe8e6ef15,
			0x9bd9bae7, 0x36ce4a6f, 0x09d4ea9f, 0x7cd629b0, 0xb2af31a4, 0x23312a3f, 0x9430c6a5, 0x66c035a2,
			0xbc37744e, 0xcaa6fc82, 0xd0b0e090, 0xd81533a7, 0x984af104, 0xdaf741ec, 0x500e7fcd, 0xf62f1791,
			0xd68d764d, 0xb04d43ef, 0x4d54ccaa, 0x04dfe496, 0xb5e39ed1, 0x881b4c6a, 0x1fb8c12c, 0x517f4665,
			0xea049d5e, 0x355d018c, 0x7473fa87, 0x412efb0b, 0x1d5ab367, 0xd25292db, 0x5633e910, 0x47136dd6,
			0x618c9ad7, 0x0c7a37a1, 0x148e59f8, 0x3c89eb13, 0x27eecea9, 0xc935b761, 0xe5ede11c, 0xb13c7a47,
			0xdf599cd2, 0x733f55f2, 0xce791814, 0x37bf73c7, 0xcdea53f7, 0xaa5b5ffd, 0x6f14df3d, 0xdb867844,
			0xf381caaf, 0xc43eb968, 0x342c3824, 0x405fc2a3, 0xc372161d, 0x250cbce2, 0x498b283c, 0x9541ff0d,
			0x017139a8, 0xb3de080c, 0xe49cd8b4, 0xc1906456, 0x84617bcb, 0xb670d532, 0x5c74486c, 0x5742d0b8,
		};

        private static readonly UInt32[] IT3 = {
			0xf4a75051, 0x4165537e, 0x17a4c31a, 0x275e963a, 0xab6bcb3b, 0x9d45f11f, 0xfa58abac, 0xe303934b,
			0x30fa5520, 0x766df6ad, 0xcc769188, 0x024c25f5, 0xe5d7fc4f, 0x2acbd7c5, 0x35448026, 0x62a38fb5,
			0xb15a49de, 0xba1b6725, 0xea0e9845, 0xfec0e15d, 0x2f7502c3, 0x4cf01281, 0x4697a38d, 0xd3f9c66b,
			0x8f5fe703, 0x929c9515, 0x6d7aebbf, 0x5259da95, 0xbe832dd4, 0x7421d358, 0xe0692949, 0xc9c8448e,
			0xc2896a75, 0x8e7978f4, 0x583e6b99, 0xb971dd27, 0xe14fb6be, 0x88ad17f0, 0x20ac66c9, 0xce3ab47d,
			0xdf4a1863, 0x1a3182e5, 0x51336097, 0x537f4562, 0x6477e0b1, 0x6bae84bb, 0x81a01cfe, 0x082b94f9,
			0x48685870, 0x45fd198f, 0xde6c8794, 0x7bf8b752, 0x73d323ab, 0x4b02e272, 0x1f8f57e3, 0x55ab2a66,
			0xeb2807b2, 0xb5c2032f, 0xc57b9a86, 0x3708a5d3, 0x2887f230, 0xbfa5b223, 0x036aba02, 0x16825ced,
			0xcf1c2b8a, 0x79b492a7, 0x07f2f0f3, 0x69e2a14e, 0xdaf4cd65, 0x05bed506, 0x34621fd1, 0xa6fe8ac4,
			0x2e539d34, 0xf355a0a2, 0x8ae13205, 0xf6eb75a4, 0x83ec390b, 0x60efaa40, 0x719f065e, 0x6e1051bd,
			0x218af93e, 0xdd063d96, 0x3e05aedd, 0xe6bd464d, 0x548db591, 0xc45d0571, 0x06d46f04, 0x5015ff60,
			0x98fb2419, 0xbde997d6, 0x4043cc89, 0xd99e7767, 0xe842bdb0, 0x898b8807, 0x195b38e7, 0xc8eedb79,
			0x7c0a47a1, 0x420fe97c, 0x841ec9f8, 0x00000000, 0x80868309, 0x2bed4832, 0x1170ac1e, 0x5a724e6c,
			0x0efffbfd, 0x8538560f, 0xaed51e3d, 0x2d392736, 0x0fd9640a, 0x5ca62168, 0x5b54d19b, 0x362e3a24,
			0x0a67b10c, 0x57e70f93, 0xee96d2b4, 0x9b919e1b, 0xc0c54f80, 0xdc20a261, 0x774b695a, 0x121a161c,
			0x93ba0ae2, 0xa02ae5c0, 0x22e0433c, 0x1b171d12, 0x090d0b0e, 0x8bc7adf2, 0xb6a8b92d, 0x1ea9c814,
			0xf1198557, 0x75074caf, 0x99ddbbee, 0x7f60fda3, 0x01269ff7, 0x72f5bc5c, 0x663bc544, 0xfb7e345b,
			0x4329768b, 0x23c6dccb, 0xedfc68b6, 0xe4f163b8, 0x31dccad7, 0x63851042, 0x97224013, 0xc6112084,
			0x4a247d85, 0xbb3df8d2, 0xf93211ae, 0x29a16dc7, 0x9e2f4b1d, 0xb230f3dc, 0x8652ec0d, 0xc1e3d077,
			0xb3166c2b, 0x70b999a9, 0x9448fa11, 0xe9642247, 0xfc8cc4a8, 0xf03f1aa0, 0x7d2cd856, 0x3390ef22,
			0x494ec787, 0x38d1c1d9, 0xcaa2fe8c, 0xd40b3698, 0xf581cfa6, 0x7ade28a5, 0xb78e26da, 0xadbfa43f,
			0x3a9de42c, 0x78920d50, 0x5fcc9b6a, 0x7e466254, 0x8d13c2f6, 0xd8b8e890, 0x39f75e2e, 0xc3aff582,
			0x5d80be9f, 0xd0937c69, 0xd52da96f, 0x2512b3cf, 0xac993bc8, 0x187da710, 0x9c636ee8, 0x3bbb7bdb,
			0x267809cd, 0x5918f46e, 0x9ab701ec, 0x4f9aa883, 0x956e65e6, 0xffe67eaa, 0xbccf0821, 0x15e8e6ef,
			0xe79bd9ba, 0x6f36ce4a, 0x9f09d4ea, 0xb07cd629, 0xa4b2af31, 0x3f23312a, 0xa59430c6, 0xa266c035,
			0x4ebc3774, 0x82caa6fc, 0x90d0b0e0, 0xa7d81533, 0x04984af1, 0xecdaf741, 0xcd500e7f, 0x91f62f17,
			0x4dd68d76, 0xefb04d43, 0xaa4d54cc, 0x9604dfe4, 0xd1b5e39e, 0x6a881b4c, 0x2c1fb8c1, 0x65517f46,
			0x5eea049d, 0x8c355d01, 0x877473fa, 0x0b412efb, 0x671d5ab3, 0xdbd25292, 0x105633e9, 0xd647136d,
			0xd7618c9a, 0xa10c7a37, 0xf8148e59, 0x133c89eb, 0xa927eece, 0x61c935b7, 0x1ce5ede1, 0x47b13c7a,
			0xd2df599c, 0xf2733f55, 0x14ce7918, 0xc737bf73, 0xf7cdea53, 0xfdaa5b5f, 0x3d6f14df, 0x44db8678,
			0xaff381ca, 0x68c43eb9, 0x24342c38, 0xa3405fc2, 0x1dc37216, 0xe2250cbc, 0x3c498b28, 0x0d9541ff,
			0xa8017139, 0x0cb3de08, 0xb4e49cd8, 0x56c19064, 0xcb84617b, 0x32b670d5, 0x6c5c7448, 0xb85742d0,
		};
        #endregion
        #endregion

        #region Twofish Constant Tables
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
                if (_exKey != null)
                {
                    Array.Clear(_exKey, 0, _exKey.Length);
                    _exKey = null;
                }
                if (_sBox != null)
                {
                    Array.Clear(_sBox, 0, _sBox.Length);
                    _sBox = null;
                }
                if (_ctrVector != null)
                {
                    Array.Clear(_ctrVector, 0, _ctrVector.Length);
                    _ctrVector = null;
                }
                _isDisposed = true;
            }
        }
        #endregion
    }
}
