#region Directives
using System;
#endregion

#region License Information
/// <remarks>
/// <para>Permission is hereby granted, free of charge, to any person obtaining
/// a copy of this software and associated documentation files (the
/// "Software"), to deal in the Software without restriction, including
/// without limitation the rights to use, copy, modify, merge, publish,
/// distribute, sublicense, and/or sell copies of the Software, and to
/// permit persons to whom the Software is furnished to do so, subject to
/// the following conditions:</para>
/// 
/// <para>The copyright notice and this permission notice shall be
/// included in all copies or substantial portions of the Software.</para>
/// 
/// <para>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
/// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
/// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
/// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
/// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
/// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
/// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.</para>
#endregion

#region Class Notes
/// <para><description>Principal Algorithms:</description>
/// Portions of this cipher based on the ChaCha stream cipher designed by Daniel J. Bernstein:
/// Salsa20 <see cref="http://cr.yp.to/chacha/chacha-20080128.pdf">Specification</see>.
/// 
/// <para><description>Guiding Publications:</description>
/// Salsa <see cref="http://cr.yp.to/snuffle/design.pdf">Design</see>.</para>
/// 
/// <para><description>Code Base Guides:</description>
/// Portions of this code also based on the Bouncy Castle Java 
/// <see cref="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</para>
/// 
/// <para><description>Implementation Details:</description>
/// ChaCha20+
/// An implementation based on the ChaCha stream cipher,
/// using an extended key size, and higher variable rounds assignment.
/// Valid Key sizes are 128, 256 and 384 (16, 32 and 48 bytes).
/// Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.
/// Written by John Underhill, October 21, 2014
/// contact: steppenwolfe_2000@yahoo.com</para>
/// </remarks>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Ciphers
{
    /// <summary>
    /// ChaCha+: A ChaCha stream cipher implementation.
    /// 
    /// <list type="bullet">
    /// <item><description>Valid Key sizes are 128, 256 and 384 (16, 32 and 48 bytes).</description></item>
    /// <item><description>Block size is 64 bytes wide.</description></item>
    /// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
    /// </list>
    /// 
    /// <example>
    /// <description>Example using an <c>IStreamCipher</c> interface:</description>
    /// <code>
    /// using (IStreamCipher cipher = new ChaCha())
    /// {
    ///     // initialize for encryption
    ///     cipher.cipher(new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// </summary>
    public sealed class ChaCha : IStreamCipher, IDisposable
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
        private bool _isInitialized = false;
        private byte[] _keyStream = new byte[STATE_SIZE * 4];
        private Int32 _Rounds = DEFAULT_ROUNDS;
        private byte[] _Sigma = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k");
        private Int32[] _State = new Int32[STATE_SIZE];
        private byte[] _Tau = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");
        private Int32[] _workBuffer = new Int32[STATE_SIZE];
        #endregion

        #region Properties
        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get: Available Encryption Key Sizes in bits
        /// </summary>
        public static Int32[] LegalKeySizes
        {
            get { return new Int32[] { 128, 256, 384, 448 }; }
        }

        /// <summary>
        /// Get: Available number of rounds
        /// </summary>
        public static Int32[] LegalRounds
        {
            get { return new Int32[] { 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 }; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return "ChaCha"; }
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
        /// Get: Initialization vector size
        /// </summary>
        public static int VectorSize
        {
            get { return VECTOR_SIZE; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        public ChaCha()
        {
            this._Rounds = DEFAULT_ROUNDS;
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes.</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid rounds count is chosen.</exception>
        public ChaCha(Int32 Rounds)
        {
            if (Rounds <= 0 || (Rounds & 1) != 0)
                throw new ArgumentOutOfRangeException("Rounds must be a positive even number!");
            if (Rounds < MIN_ROUNDS || Rounds > MAX_ROUNDS)
                throw new ArgumentOutOfRangeException("Rounds must be between " + MIN_ROUNDS + " and " + MAX_ROUNDS + "!");
            
            this.Rounds = Rounds;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Increment the internal counter by 1
        /// </summary>
        public void AdvanceCounter()
        {
            if (++_State[12] == 0)
                ++_State[13];
        }

        /// <summary>
        /// Get the current counter value
        /// </summary>
        /// 
        /// <returns>Counter</returns>
        public long GetCounter()
        {
            return ((long)_State[13] << 32) | (_State[12] & 0xffffffffL);
        }

        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// 
        /// <param name="Seed">Cipher key. The <see cref="LegalKeySizes"/> property contains valid sizes.</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null key or iv is used.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid key size is used.</exception>
        public void Init(byte[] Seed)
        {
            if (Seed == null)
                throw new ArgumentException("Seed can not be null!");
            if (Seed.Length != 24 && Seed.Length != 40 && Seed.Length != 56 && Seed.Length != 64)
                throw new ArgumentOutOfRangeException("Seed must be 24, 40, 56 or 64 bytes!");

            int len = Seed.Length;
            byte[] key = new byte[len - 8];
            byte[] iv = new byte[8];

            Buffer.BlockCopy(Seed, 0, key, 0, len - 8);
            Buffer.BlockCopy(Seed, len - 8, iv, 0, 8);

            Init(new KeyParams(key, iv));
        }

        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// 
        /// <param name="KeyParam">Cipher key container. The <see cref="LegalKeySizes"/> property contains valid sizes.</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null key or iv is used.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid key or iv size is used.</exception>
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
        /// Reset the Counter
        /// </summary>
        public void ResetCounter()
        {
            _State[12] = _State[13] = 0;
        }

        /// <summary>
        /// Set the counter back by 1
        /// </summary>
        public void RetreatCounter()
        {
            if (--_State[12] == -1)
                --_State[13];
        }

        /// <summary>
        /// Return an transformed byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        /// 
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
        /// 
        /// <param name="Length">Number of bytes to skip</param>
        /// 
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

        /// <summary>
        /// Encrypt/Decrypt an array of bytes.
        /// <para><see cref="Init(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
        /// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            int ctr = 0;

            while (ctr < Output.Length)
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
        /// Encrypt/Decrypt an array of bytes.
        /// <para><see cref="Init(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
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
        /// Encrypt/Decrypt an array of bytes.
        /// <para><see cref="Init(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Length">Number of bytes to process</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
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

        private void ChaChaCore(Int32 Rounds, Int32[] Input, Int32[] Output)
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
                X0 += X4; X12 = RotL(X12 ^ X0, 16);
                X8 += X12; X4 = RotL(X4 ^ X8, 12);
                X0 += X4; X12 = RotL(X12 ^ X0, 8);
                X8 += X12; X4 = RotL(X4 ^ X8, 7);
                X1 += X5; X13 = RotL(X13 ^ X1, 16);
                X9 += X13; X5 = RotL(X5 ^ X9, 12);
                X1 += X5; X13 = RotL(X13 ^ X1, 8);
                X9 += X13; X5 = RotL(X5 ^ X9, 7);
                X2 += X6; X14 = RotL(X14 ^ X2, 16);
                X10 += X14; X6 = RotL(X6 ^ X10, 12);
                X2 += X6; X14 = RotL(X14 ^ X2, 8);
                X10 += X14; X6 = RotL(X6 ^ X10, 7);
                X3 += X7; X15 = RotL(X15 ^ X3, 16);
                X11 += X15; X7 = RotL(X7 ^ X11, 12);
                X3 += X7; X15 = RotL(X15 ^ X3, 8);
                X11 += X15; X7 = RotL(X7 ^ X11, 7);
                X0 += X5; X15 = RotL(X15 ^ X0, 16);
                X10 += X15; X5 = RotL(X5 ^ X10, 12);
                X0 += X5; X15 = RotL(X15 ^ X0, 8);
                X10 += X15; X5 = RotL(X5 ^ X10, 7);
                X1 += X6; X12 = RotL(X12 ^ X1, 16);
                X11 += X12; X6 = RotL(X6 ^ X11, 12);
                X1 += X6; X12 = RotL(X12 ^ X1, 8);
                X11 += X12; X6 = RotL(X6 ^ X11, 7);
                X2 += X7; X13 = RotL(X13 ^ X2, 16);
                X8 += X13; X7 = RotL(X7 ^ X8, 12);
                X2 += X7; X13 = RotL(X13 ^ X2, 8);
                X8 += X13; X7 = RotL(X7 ^ X8, 7);
                X3 += X4; X14 = RotL(X14 ^ X3, 16);
                X9 += X14; X4 = RotL(X4 ^ X9, 12);
                X3 += X4; X14 = RotL(X14 ^ X3, 8);
                X9 += X14; X4 = RotL(X4 ^ X9, 7);

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

        private void CreateNonce()
        {
            // Process engine state to generate key
            int stateLen = _State.Length;
            Int32[] chachaOut = new Int32[stateLen];
            Int32[] stateTemp = new Int32[stateLen];
            Buffer.BlockCopy(_State, 0, stateTemp, 0, stateLen * 4);

            // create a new nonce with core
            ChaChaCore(20, stateTemp, chachaOut);
            // copy new nonce to state
            Buffer.BlockCopy(chachaOut, 0, _State, 0, 16);

            // check for unique counter
            if (_State[12] == _State[14])
                _State[12] = chachaOut[12];
            if (_State[13] == _State[15])
                _State[13] = chachaOut[13];
        }

        private void GenerateKeyStream(byte[] Output)
        {
            ChaChaCore(this.Rounds, _State, _workBuffer);
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

        private Int32 LittleEndianToInt(byte[] X, Int32 Offset)
        {
            return ((X[Offset] & 255)) |
                   ((X[Offset + 1] & 255) << 8) |
                   ((X[Offset + 2] & 255) << 16) |
                   (X[Offset + 3] << 24);
        }

        private Int32 RotL(Int32 X, Int32 Y)
        {
            return (X << Y) | ((Int32)((uint)X >> -Y));
        }

        private void SetKey(byte[] Key, byte[] Iv)
        {
            _State[14] = LittleEndianToInt(Iv, 0);
            _State[15] = LittleEndianToInt(Iv, 4);

            if (Key != null)
            {
                _State[4] = LittleEndianToInt(Key, 0);
                _State[5] = LittleEndianToInt(Key, 4);
                _State[6] = LittleEndianToInt(Key, 8);
                _State[7] = LittleEndianToInt(Key, 12);

                if (Key.Length == 56)
                {
                    _State[8] = LittleEndianToInt(Key, 16);
                    _State[9] = LittleEndianToInt(Key, 20);
                    _State[10] = LittleEndianToInt(Key, 24);
                    _State[11] = LittleEndianToInt(Key, 28);
                    // nonce
                    _State[0] = LittleEndianToInt(Key, 32);
                    _State[1] = LittleEndianToInt(Key, 36);
                    _State[2] = LittleEndianToInt(Key, 40);
                    _State[3] = LittleEndianToInt(Key, 44);
                    // counter
                    _State[12] = LittleEndianToInt(Key, 48);
                    _State[13] = LittleEndianToInt(Key, 52);
                }
                else if (Key.Length == 48)
                {
                    _State[8] = LittleEndianToInt(Key, 16);
                    _State[9] = LittleEndianToInt(Key, 20);
                    _State[10] = LittleEndianToInt(Key, 24);
                    _State[11] = LittleEndianToInt(Key, 28);
                    // nonce
                    _State[0] = LittleEndianToInt(Key, 32);
                    _State[1] = LittleEndianToInt(Key, 36);
                    _State[2] = LittleEndianToInt(Key, 40);
                    _State[3] = LittleEndianToInt(Key, 44);
                }
                else if (Key.Length == 32)
                {
                    _State[8] = LittleEndianToInt(Key, 16);
                    _State[9] = LittleEndianToInt(Key, 20);
                    _State[10] = LittleEndianToInt(Key, 24);
                    _State[11] = LittleEndianToInt(Key, 28);
                    // nonce
                    _State[0] = LittleEndianToInt(_Sigma, 0);
                    _State[1] = LittleEndianToInt(_Sigma, 4);
                    _State[2] = LittleEndianToInt(_Sigma, 8);
                    _State[3] = LittleEndianToInt(_Sigma, 12);
                }
                else
                {
                    _State[8] = LittleEndianToInt(Key, 0);
                    _State[9] = LittleEndianToInt(Key, 4);
                    _State[10] = LittleEndianToInt(Key, 8);
                    _State[11] = LittleEndianToInt(Key, 12);
                    // nonce
                    _State[0] = LittleEndianToInt(_Tau, 0);
                    _State[1] = LittleEndianToInt(_Tau, 4);
                    _State[2] = LittleEndianToInt(_Tau, 8);
                    _State[3] = LittleEndianToInt(_Tau, 12);
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

            // test for minimum asymmetry; max 2 repeats, 2 times, distance of more than 4
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
