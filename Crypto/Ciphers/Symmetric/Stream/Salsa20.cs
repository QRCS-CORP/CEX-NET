using System;

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
/// Based on the Salsa20 stream cipher designed by Daniel J. Bernstein
/// eStream: http://www.ecrypt.eu.org/stream/salsa20pf.html
/// Salsa20 security: http://cr.yp.to/snuffle/security.pdf
/// 
/// Portions of this code based on Bouncy Castle Java release 1.51:
/// http://bouncycastle.org/latest_releases.html
/// Based on the Bouncy Castle version with changes made to improve speed, flexibility, a Dispose method added, and formatting changes
/// http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/engines/ChaChaEngine.java
/// 
/// Salsa20+
/// An implementation based on the Salsa20 stream cipher,
/// using an extended key size, and higher variable rounds assignment.
/// Valid Key sizes are 128, 256 and 384 and 448 (16, 32 48 and 56 bytes).
/// Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.
/// Written by John Underhill, October 17, 2014
/// contact: steppenwolfe_2000@yahoo.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Ciphers
{
    /// Salsa20+
    /// Valid Key sizes are 128, 256 and 384 (16, 32 and 48 bytes).
    /// Block size is 64 bytes wide.
    /// Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.
    public sealed class Salsa20 : IStreamCipher, IDisposable
    {
        #region Constants
        private const int DEFAULT_ROUNDS = 20;
        private const int MAX_ROUNDS = 30;
        private const int MIN_ROUNDS = 8;
        private const int STATE_SIZE = 16;
        private const int VECTOR_SIZE = 8;
        #endregion

        #region Fields
        private Int32 _Index = 0;
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private bool _isInitialized = false;
        private byte[] _keyBuffer;
        private byte[] _keyStream = new byte[STATE_SIZE * 4];
        private Int32 _Rounds = DEFAULT_ROUNDS;
        private byte[] _Sigma = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k");
        private Int32[] _State = new Int32[STATE_SIZE];
        private byte[] _Tau = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");
        private Int32[] _workBuffer = new Int32[STATE_SIZE];
        #endregion

        #region Constructor
        public Salsa20()
        {
            this._Rounds = DEFAULT_ROUNDS;
        }

        public Salsa20(Int32 Rounds)
        {
            if (Rounds <= 0 || (Rounds & 1) != 0)
                throw new ArgumentOutOfRangeException("Rounds must be a positive, even number!");
            if (Rounds < MIN_ROUNDS || Rounds > MAX_ROUNDS)
                throw new ArgumentOutOfRangeException("Rounds must be between " + MIN_ROUNDS + " and " + MAX_ROUNDS + "!");
            
            this.Rounds = Rounds;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Used as encryptor, false for decryption. 
        /// </summary>
        public bool IsEncryption
        {
            get { return _isEncryption; }
            set { _isEncryption = value; }
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
        /// Get: Cipher key
        /// </summary>
        public byte[] Key
        {
            get { return _keyBuffer; }
            private set { _keyBuffer = value; }
        }

        /// <summary>
        /// Get: Available Encryption Key Sizes in bits
        /// </summary>
        public static Int32[] KeySizes
        {
            get { return new Int32[] { 128, 256, 384, 448 }; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return "Salsa20"; }
        }

        /// <summary>
        /// Get: Number of rounds
        /// </summary>
        public int Rounds
        {
            get { return _Rounds; }
            private set { _Rounds = value; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public static int[] LegalRounds
        {
            get { return new int[] { 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 }; }
        }

        /// <summary>
        /// Get: Initialization vector size
        /// </summary>
        public int VectorSize
        {
            get { return VECTOR_SIZE; }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Increment the internal counter by 1
        /// </summary>
        private void AdvanceCounter()
        {
            if (++_State[8] == 0)
                ++_State[9];
        }

        /// <summary>
        /// Get the current counter value
        /// </summary>
        /// <returns></returns>
        public long GetCounter()
        {
            return ((long)_State[9] << 32) | (_State[8] & 0xffffffffL);
        }

        /// <summary>
        /// Initialise the cipher
        /// </summary>
        /// <param name="Seed">Cipher key and vector</param>
        public void Init(byte[] Seed)
        {
            if (Seed == null)
                throw new ArgumentException("Key can not be null!");
            if (Seed.Length != 24 && Seed.Length != 40 && Seed.Length != 56 && Seed.Length != 64)
                throw new ArgumentOutOfRangeException("Seed must be 24, 40, 56 or 64 bytes!");

            int len = Seed.Length;
            byte[] key = new byte[len - 8];
            byte[] iv = new byte[8];

            Buffer.BlockCopy(Seed, 0, key, 0, len - 8);
            Buffer.BlockCopy(Seed, len - 8, key, 0, 8);

            Init(new KeyParams(key, iv));
        }

        /// <summary>
        /// Initialise the cipher
        /// </summary>
        /// <param name="Key">Cipher key</param>
        /// <param name="Vector">Cipher IV</param>
        public void Init(KeyParams KeyParam)
        {
            if (KeyParam.IV == null)
                throw new ArgumentException("Init parameters must include an IV!");
            if (KeyParam.IV.Length != 8)
                throw new ArgumentOutOfRangeException("Requires exactly 8 bytes of IV!");
            if (KeyParam.Key.Length != 16 && KeyParam.Key.Length != 32 && KeyParam.Key.Length != 48 && KeyParam.Key.Length != 56)
                throw new ArgumentOutOfRangeException("Key must be 16, 32, 48, or 56 bytes!");

            ResetCounter();

            if (KeyParam.Key == null)
            {
                if (!this.IsInitialized)
                    throw new ArgumentException("Key can not be null for first initialisation!");

                SetKey(null, KeyParam.IV);
            }
            else
            {
                SetKey(KeyParam.Key, KeyParam.IV);
            }

            Reset();

            this.IsInitialized = true;
        }

        /// <summary>
        /// Reset the state counter
        /// </summary>
        public void ResetCounter()
        {
            _State[8] = _State[9] = 0;
        }

        /// <summary>
        /// Set the counter back by 1
        /// </summary>
        public void RetreatCounter()
        {
            if (--_State[8] == -1)
                --_State[9];
        }

        /// <summary>
        /// Return an transformed byte
        /// </summary>
        /// <param name="Input">Input byte</param>
        /// <returns>Transformed byte</returns>
        public byte ReturnByte(byte Input)
        {
            // 2^70 is 1180 exabytes, this check is not realistic
            //if (LimitExceeded())
            //    throw new ArgumentException("2^70 byte limit per IV; Change IV!");

            byte output = (byte)(_keyStream[_Index] ^ Input);
            _Index = (_Index + 1) & 63;

            if (_Index == 0)
            {
                AdvanceCounter();
                GenerateKeyStream(_keyStream);
            }

            return output;
        }

        /// <summary>
        /// Skip a portion of the stream
        /// </summary>
        /// <param name="Length">Number of bytes to skip</param>
        /// <returns>Bytes skipped</returns>
        public long Skip(long Length)
        {
            if (Length >= 0)
            {
                for (long i = 0; i < Length; i++)
                {
                    _Index = (_Index + 1) & 63;

                    if (_Index == 0)
                        AdvanceCounter();
                }
            }
            else
            {
                for (long i = 0; i > Length; i--)
                {
                    if (_Index == 0)
                        RetreatCounter();

                    _Index = (_Index - 1) & 63;
                }
            }

            GenerateKeyStream(_keyStream);

            return Length;
        }

        /// Encrypt/Decrypt an array of bytes
        /// </summary>
        /// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
        /// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            int len = Output.Length;
            int ctr = 0;

            while (ctr < len)
            {
                Output[ctr] = (byte)(_keyStream[_Index] ^ Input[ctr]);
                _Index = (_Index + 1) & 63;

                if (_Index == 0)
                {
                    AdvanceCounter();
                    GenerateKeyStream(_keyStream);
                }

                ctr++;
            }
        }

        /// <summary>
        /// Transform a block of bytes within an array.
        /// Init must be called before this method can be used.
        /// Block size is Output - OutOffset.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Output">Transformed bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
        public void Transform(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            int len = Output.Length - OutOffset;
            int ctr = 0;

            while (ctr < len)
            {
                Output[ctr + OutOffset] = (byte)(_keyStream[_Index] ^ Input[ctr + InOffset]);
                _Index = (_Index + 1) & 63;

                if (_Index == 0)
                {
                    AdvanceCounter();
                    GenerateKeyStream(_keyStream);
                }

                ctr++;
            }
        }

        /// <summary>
        /// Transform a range of bytes
        /// </summary>
        /// <param name="Input">Bytes to transform</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Length">Number of bytes to process</param>
        /// <param name="Output">Output bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        public void Transform(byte[] Input, Int32 InOffset, Int32 Length, byte[] Output, Int32 OutOffset)
        {
            int ctr = 0;

            while (ctr < Length)
            {
                Output[ctr + OutOffset] = (byte)(_keyStream[_Index] ^ Input[ctr + InOffset]);
                _Index = (_Index + 1) & 63;

                if (_Index == 0)
                {
                    AdvanceCounter();
                    GenerateKeyStream(_keyStream);
                }

                ctr++;
            }
        }

        /// <summary>
        /// Reset the algorithm
        /// </summary>
        public void Reset()
        {
            _Index = 0;
            GenerateKeyStream(_keyStream);
        }
        #endregion

        #region Helpers
        private int ByteFrequencyMax(byte[] Seed)
        {
            int ctr = 0;
            int len = Seed.Length;
            int max = 0;

            // test for highest number of a repeating value
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < 256; j++)
                {
                    if (Seed[i] == (byte)j)
                    {
                        ctr++;

                        if (ctr > max)
                            max = ctr;
                    }
                }
            }

            return max;
        }

        private void CreateNonce()
        {
            // Process engine state to generate key
            int stateLen = _State.Length;
            Int32[] chachaOut = new Int32[stateLen];
            Int32[] stateTemp = new Int32[stateLen];

            // copy state
            Buffer.BlockCopy(_State, 0, stateTemp, 0, stateLen * 4);

            // create a new nonce with core
            SalsaCore(20, stateTemp, chachaOut);

            // copy new nonce to state
            _State[0] = chachaOut[0];
            _State[5] = chachaOut[5];
            _State[10] = chachaOut[10];
            _State[15] = chachaOut[15];

            // check for unique counter
            if (_State[8] == _State[6])
                _State[8] = chachaOut[8];
            if (_State[9] == _State[7])
                _State[9] = chachaOut[9];
        }

        private Int32 LittleEndianToInt(byte[] X, Int32 Offset)
        {
            return ((X[Offset] & 255)) |
                   ((X[Offset + 1] & 255) << 8) |
                   ((X[Offset + 2] & 255) << 16) |
                   (X[Offset + 3] << 24);
        }

        private void GenerateKeyStream(byte[] Output)
        {
            SalsaCore(this.Rounds, _State, _workBuffer);
            IntToLittleEndian(_workBuffer, Output, 0);
        }

        private byte[] IntToLittleEndian(Int32 X, byte[] Bs, Int32 Offset)
        {
            Bs[Offset] = (byte)X;
            Bs[Offset + 1] = (byte)(X >> 8);
            Bs[Offset + 2] = (byte)(X >> 16);
            Bs[Offset + 3] = (byte)(X >> 24);
            return Bs;
        }

        private void IntToLittleEndian(Int32[] Ns, byte[] Bs, Int32 Offset)
        {
            for (int i = 0; i < Ns.Length; ++i)
            {
                IntToLittleEndian(Ns[i], Bs, Offset);
                Offset += 4;
            }
        }

        private Int32 RotL(Int32 X, Int32 Y)
        {
            return (X << Y) | ((Int32)((uint)X >> -Y));
        }

        private void SalsaCore(Int32 Rounds, Int32[] Input, Int32[] Output)
        {
            int ctr = 0;

            Int32 X0 = Input[ctr++];
            Int32 X1 = Input[ctr++];
            Int32 X2 = Input[ctr++];
            Int32 X3 = Input[ctr++];
            Int32 X4 = Input[ctr++];
            Int32 X5 = Input[ctr++];
            Int32 X6 = Input[ctr++];
            Int32 X7 = Input[ctr++];
            Int32 X8 = Input[ctr++];
            Int32 X9 = Input[ctr++];
            Int32 X10 = Input[ctr++];
            Int32 X11 = Input[ctr++];
            Int32 X12 = Input[ctr++];
            Int32 X13 = Input[ctr++];
            Int32 X14 = Input[ctr++];
            Int32 X15 = Input[ctr];

            ctr = Rounds;

            while (ctr > 0)
            {
                X4 ^= RotL(X0 + X12, 7);
                X8 ^= RotL(X4 + X0, 9);
                X12 ^= RotL(X8 + X4, 13);
                X0 ^= RotL(X12 + X8, 18);
                X9 ^= RotL(X5 + X1, 7);
                X13 ^= RotL(X9 + X5, 9);
                X1 ^= RotL(X13 + X9, 13);
                X5 ^= RotL(X1 + X13, 18);
                X14 ^= RotL(X10 + X6, 7);
                X2 ^= RotL(X14 + X10, 9);
                X6 ^= RotL(X2 + X14, 13);
                X10 ^= RotL(X6 + X2, 18);
                X3 ^= RotL(X15 + X11, 7);
                X7 ^= RotL(X3 + X15, 9);
                X11 ^= RotL(X7 + X3, 13);
                X15 ^= RotL(X11 + X7, 18);

                X1 ^= RotL(X0 + X3, 7);
                X2 ^= RotL(X1 + X0, 9);
                X3 ^= RotL(X2 + X1, 13);
                X0 ^= RotL(X3 + X2, 18);
                X6 ^= RotL(X5 + X4, 7);
                X7 ^= RotL(X6 + X5, 9);
                X4 ^= RotL(X7 + X6, 13);
                X5 ^= RotL(X4 + X7, 18);
                X11 ^= RotL(X10 + X9, 7);
                X8 ^= RotL(X11 + X10, 9);
                X9 ^= RotL(X8 + X11, 13);
                X10 ^= RotL(X9 + X8, 18);
                X12 ^= RotL(X15 + X14, 7);
                X13 ^= RotL(X12 + X15, 9);
                X14 ^= RotL(X13 + X12, 13);
                X15 ^= RotL(X14 + X13, 18);

                ctr -= 2;
            }

            ctr = 0;
            Output[ctr] = X0 + Input[ctr++];
            Output[ctr] = X1 + Input[ctr++];
            Output[ctr] = X2 + Input[ctr++];
            Output[ctr] = X3 + Input[ctr++];
            Output[ctr] = X4 + Input[ctr++];
            Output[ctr] = X5 + Input[ctr++];
            Output[ctr] = X6 + Input[ctr++];
            Output[ctr] = X7 + Input[ctr++];
            Output[ctr] = X8 + Input[ctr++];
            Output[ctr] = X9 + Input[ctr++];
            Output[ctr] = X10 + Input[ctr++];
            Output[ctr] = X11 + Input[ctr++];
            Output[ctr] = X12 + Input[ctr++];
            Output[ctr] = X13 + Input[ctr++];
            Output[ctr] = X14 + Input[ctr++];
            Output[ctr] = X15 + Input[ctr];
        }

        private void SetKey(byte[] Key, byte[] Iv)
        {
            _State[6] = LittleEndianToInt(Iv, 0);
            _State[7] = LittleEndianToInt(Iv, 4);

            if (Key != null)
            {
                _State[1] = LittleEndianToInt(Key, 0);
                _State[2] = LittleEndianToInt(Key, 4);
                _State[3] = LittleEndianToInt(Key, 8);
                _State[4] = LittleEndianToInt(Key, 12);

                if (Key.Length == 56)
                {
                    _State[11] = LittleEndianToInt(Key, 16);
                    _State[12] = LittleEndianToInt(Key, 20);
                    _State[13] = LittleEndianToInt(Key, 24);
                    _State[14] = LittleEndianToInt(Key, 28);
                    // nonce
                    _State[0] = LittleEndianToInt(Key, 32);
                    _State[5] = LittleEndianToInt(Key, 36);
                    _State[10] = LittleEndianToInt(Key, 40);
                    _State[15] = LittleEndianToInt(Key, 44);
                    // counter
                    _State[8] = LittleEndianToInt(Key, 48);
                    _State[9] = LittleEndianToInt(Key, 52);
                }
                else if (Key.Length == 48)
                {
                    _State[11] = LittleEndianToInt(Key, 16);
                    _State[12] = LittleEndianToInt(Key, 20);
                    _State[13] = LittleEndianToInt(Key, 24);
                    _State[14] = LittleEndianToInt(Key, 28);
                    // nonce
                    _State[0] = LittleEndianToInt(Key, 32);
                    _State[5] = LittleEndianToInt(Key, 36);
                    _State[10] = LittleEndianToInt(Key, 40);
                    _State[15] = LittleEndianToInt(Key, 44);
                }
                else if (Key.Length == 32)
                {
                    _State[11] = LittleEndianToInt(Key, 16);
                    _State[12] = LittleEndianToInt(Key, 20);
                    _State[13] = LittleEndianToInt(Key, 24);
                    _State[14] = LittleEndianToInt(Key, 28);
                    // nonce constant
                    _State[0] = LittleEndianToInt(_Sigma, 0);
                    _State[5] = LittleEndianToInt(_Sigma, 4);
                    _State[10] = LittleEndianToInt(_Sigma, 8);
                    _State[15] = LittleEndianToInt(_Sigma, 12);
                }
                else
                {
                    _State[11] = LittleEndianToInt(Key, 0);
                    _State[12] = LittleEndianToInt(Key, 4);
                    _State[13] = LittleEndianToInt(Key, 8);
                    _State[14] = LittleEndianToInt(Key, 12);
                    // nonce constant
                    _State[0] = LittleEndianToInt(_Tau, 0);
                    _State[5] = LittleEndianToInt(_Tau, 4);
                    _State[10] = LittleEndianToInt(_Tau, 8);
                    _State[15] = LittleEndianToInt(_Tau, 12);
                }

                // if nonce portion of key is too symmetrical, pre-process
                if (Key.Length > 32 && !ValidNonce(Key, 32, 16))
                    CreateNonce();
            }
        }

        private bool ValidNonce(byte[] Key, int Offset, int Length)
        {
            int ctr = 0;
            int rep = 0;

            // test for minimum asymmetry per sigma and tau constants; 
            // max 2 repeats, 2 times, distance of more than 4
            for (int i = Offset; i < Offset + Length; i++)
            {
                ctr = 0;
                for (int j = i + 1; j < Offset + Length; j++)
                {
                    if (Key[i] == Key[j])
                    {
                        ctr++;

                        if (ctr > 1)
                            return false;
                        if (j - i < 5)
                            return false;
                    }
                }

                if (ctr == 1)
                    rep++;
                if (rep > 2)
                    return false;
            }

            return true;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of the class resources
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
                if (_keyStream != null)
                {
                    Array.Clear(_keyStream, 0, _keyStream.Length);
                    _keyStream = null;
                }
                if (_workBuffer != null)
                {
                    Array.Clear(_workBuffer, 0, _workBuffer.Length);
                    _workBuffer = null;
                }
                if (_State != null)
                {
                    Array.Clear(_State, 0, _State.Length);
                    _State = null;
                }
                if (_Tau != null)
                {
                    Array.Clear(_Tau, 0, _Tau.Length);
                    _Tau = null;
                }
                if (_Sigma != null)
                {
                    Array.Clear(_Sigma, 0, _Sigma.Length);
                    _Sigma = null;
                }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
