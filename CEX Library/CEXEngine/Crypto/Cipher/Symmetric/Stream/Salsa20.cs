#region Directives
using System;
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
// Portions of this cipher based on the Salsa20 stream cipher designed by Daniel J. Bernstein:
// Salsa20 <see href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</see>.
// 
// Implementation Details:
// Salsa20+
// An implementation based on the Salsa20 stream cipher,
// using an extended key size, and higher variable rounds assignment.
// Valid Key sizes are 128, 256 and 384 and 448 (16, 32 48 and 56 bytes).
// Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.
// Written by John Underhill, October 17, 2014
// contact: develop@vtdev.com</para>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream
{
    /// <summary>
    /// <h3>Salsa20+: A Salsa20 stream cipher implementation.</h3>
    /// <para>A Salsa20 cipher extended to use up to a 384 bit key, and up to 30 rounds of diffusion.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IStreamCipher</c> interface:</description>
    /// <code>
    /// using (IStreamCipher cipher = new Salsa20())
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2014/11/14" version="1.2.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Secondary release; updates to layout and documentation</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Valid Key sizes are 128, 256 and 384 (16, 32 and 48 bytes).</description></item>
    /// <item><description>Block size is 64 bytes wide.</description></item>
    /// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Salsa20 <see href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</see>.</description></item>
    /// <item><description>Salsa20 <see href="http://cr.yp.to/snuffle/design.pdf">Design</see>.</description></item>
    /// <item><description>Salsa20 <see href="http://cr.yp.to/snuffle/security.pdf">Security</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired in part by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class Salsa20 : IStreamCipher, IDisposable
    {
        #region Constants
        private const string ALG_NAME = "Salsa20";
        private const int DEFAULT_ROUNDS = 20;
        private const int MAX_ROUNDS = 30;
        private const int MIN_ROUNDS = 8;
        private const int STATE_SIZE = 16;
        private const int VECTOR_SIZE = 8;
        #endregion

        #region Fields
        private Int32 _dfnRounds = DEFAULT_ROUNDS;
        private byte[] _ftSigma = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k");
        private byte[] _ftTau = System.Text.Encoding.ASCII.GetBytes("expand 16-byte k");
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private byte[] _keyBuffer;
        private byte[] _keyStream = new byte[STATE_SIZE * 4];
        private Int32 _ksIndex = 0;
        private Int32[] _wrkState = new Int32[STATE_SIZE];
        private Int32[] _wrkBuffer = new Int32[STATE_SIZE];
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
        /// Get: Cipher key
        /// </summary>
        public byte[] Key
        {
            get { return _keyBuffer; }
            private set { _keyBuffer = value; }
        }

        /// <summary>
        /// Get: Available Encryption Key Sizes in bytes
        /// </summary>
        public static Int32[] LegalKeySizes
        {
            get { return new Int32[] { 16, 32, 48, 56 }; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public static int[] LegalRounds
        {
            get { return new int[] { 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 }; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Number of rounds
        /// </summary>
        public int Rounds
        {
            get { return _dfnRounds; }
            private set { _dfnRounds = value; }
        }

        /// <summary>
        /// Get: Initialization vector size
        /// </summary>
        public int VectorSize
        {
            get { return VECTOR_SIZE; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        public Salsa20()
        {
            _dfnRounds = DEFAULT_ROUNDS;
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid rounds count is chosen</exception>
        public Salsa20(Int32 Rounds = DEFAULT_ROUNDS)
        {
            if (Rounds <= 0 || (Rounds & 1) != 0)
                throw new ArgumentOutOfRangeException("Rounds must be a positive, even number!");
            if (Rounds < MIN_ROUNDS || Rounds > MAX_ROUNDS)
                throw new ArgumentOutOfRangeException("Rounds must be between " + MIN_ROUNDS + " and " + MAX_ROUNDS + "!");
            
            _dfnRounds = Rounds;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Salsa20()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Increment the internal counter by 1
        /// </summary>
        public void AdvanceCounter()
        {
            if (++_wrkState[8] == 0)
                ++_wrkState[9];
        }

        /// <summary>
        /// Get the current counter value
        /// </summary>
        /// 
        /// <returns>Counter</returns>
        public long GetCounter()
        {
            return ((long)_wrkState[9] << 32) | (_wrkState[8] & 0xffffffffL);
        }

        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// 
        /// <param name="KeyParam">Cipher key container. 
        /// <para>Uses the Key and IV fields of KeyParam. 
        /// The <see cref="LegalKeySizes"/> property contains valid Key sizes. 
        /// IV must be 8 bytes in size.</para>
        /// </param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null key or iv  is used</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid key or iv size  is used</exception>
        public void Initialize(KeyParams KeyParam)
        {
            if (KeyParam.IV == null)
                throw new ArgumentNullException("Init parameters must include an IV!");
            if (KeyParam.IV.Length != 8)
                throw new ArgumentOutOfRangeException("Requires exactly 8 bytes of IV!");

            ResetCounter();

            if (KeyParam.Key == null)
            {
                if (!_isInitialized)
                    throw new ArgumentException("Key can not be null for first initialisation!");

                SetKey(null, KeyParam.IV);
            }
            else
            {
                if (KeyParam.Key.Length != 16 && KeyParam.Key.Length != 32 && KeyParam.Key.Length != 48 && KeyParam.Key.Length != 56)
                    throw new ArgumentOutOfRangeException("Key must be 16, 32, 48, or 56 bytes!");

                SetKey(KeyParam.Key, KeyParam.IV);
            }

            Reset();

            _isInitialized = true;
        }

        /// <summary>
        /// Reset the state counter
        /// </summary>
        public void ResetCounter()
        {
            _wrkState[8] = _wrkState[9] = 0;
        }

        /// <summary>
        /// Set the counter back by 1
        /// </summary>
        public void RetreatCounter()
        {
            if (--_wrkState[8] == -1)
                --_wrkState[9];
        }

        /// <summary>
        /// Return a transformed byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        /// 
        /// <returns>Transformed byte</returns>
        public byte ReturnByte(byte Input)
        {
            // 2^70 is 1180 exabytes, this check is not realistic
            //if (LimitExceeded()) // can never happen
            //    throw new ArgumentException("2^70 byte limit per IV; Change IV!");

            byte output = (byte)(_keyStream[_ksIndex] ^ Input);
            _ksIndex = (_ksIndex + 1) & 63;

            if (_ksIndex == 0)
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
                    _ksIndex = (_ksIndex + 1) & 63;

                    if (_ksIndex == 0)
                        AdvanceCounter();
                }
            }
            else
            {
                for (long i = 0; i > Length; i--)
                {
                    if (_ksIndex == 0)
                        RetreatCounter();

                    _ksIndex = (_ksIndex - 1) & 63;
                }
            }

            GenerateKeyStream(_keyStream);

            return Length;
        }

        /// <summary>
        /// Encrypt/Decrypt an array of bytes.
        /// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
        /// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            int len = Output.Length;
            int ctr = 0;

            while (ctr < len)
            {
                Output[ctr] = (byte)(_keyStream[_ksIndex] ^ Input[ctr]);
                _ksIndex = (_ksIndex + 1) & 63;

                if (_ksIndex == 0)
                {
                    AdvanceCounter();
                    GenerateKeyStream(_keyStream);
                }

                ctr++;
            }
        }

        /// <summary>
        /// Encrypt/Decrypt an array of bytes with offset parameters.
        /// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, Int32 InOffset, byte[] Output, Int32 OutOffset)
        {
            int len = Output.Length - OutOffset;
            int ctr = 0;

            while (ctr < len)
            {
                Output[ctr + OutOffset] = (byte)(_keyStream[_ksIndex] ^ Input[ctr + InOffset]);
                _ksIndex = (_ksIndex + 1) & 63;

                if (_ksIndex == 0)
                {
                    AdvanceCounter();
                    GenerateKeyStream(_keyStream);
                }

                ctr++;
            }
        }

        /// <summary>
        /// Encrypt/Decrypt an array of bytes with offset and length parameters.
        /// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Length">Number of bytes to process</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, Int32 InOffset, Int32 Length, byte[] Output, Int32 OutOffset)
        {
            int ctr = 0;

            while (ctr < Length)
            {
                Output[ctr + OutOffset] = (byte)(_keyStream[_ksIndex] ^ Input[ctr + InOffset]);
                _ksIndex = (_ksIndex + 1) & 63;

                if (_ksIndex == 0)
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
            _ksIndex = 0;
            GenerateKeyStream(_keyStream);
        }
        #endregion

        #region Key Schedule
        private void SetKey(byte[] Key, byte[] Iv)
        {
            _wrkState[6] = LEToDword(Iv, 0);
            _wrkState[7] = LEToDword(Iv, 4);

            if (Key != null)
            {
                _wrkState[1] = LEToDword(Key, 0);
                _wrkState[2] = LEToDword(Key, 4);
                _wrkState[3] = LEToDword(Key, 8);
                _wrkState[4] = LEToDword(Key, 12);

                if (Key.Length == 56)
                {
                    _wrkState[11] = LEToDword(Key, 16);
                    _wrkState[12] = LEToDword(Key, 20);
                    _wrkState[13] = LEToDword(Key, 24);
                    _wrkState[14] = LEToDword(Key, 28);
                    // nonce
                    _wrkState[0] = LEToDword(Key, 32);
                    _wrkState[5] = LEToDword(Key, 36);
                    _wrkState[10] = LEToDword(Key, 40);
                    _wrkState[15] = LEToDword(Key, 44);
                    // counter
                    _wrkState[8] = LEToDword(Key, 48);
                    _wrkState[9] = LEToDword(Key, 52);
                }
                else if (Key.Length == 48)
                {
                    _wrkState[11] = LEToDword(Key, 16);
                    _wrkState[12] = LEToDword(Key, 20);
                    _wrkState[13] = LEToDword(Key, 24);
                    _wrkState[14] = LEToDword(Key, 28);
                    // nonce
                    _wrkState[0] = LEToDword(Key, 32);
                    _wrkState[5] = LEToDword(Key, 36);
                    _wrkState[10] = LEToDword(Key, 40);
                    _wrkState[15] = LEToDword(Key, 44);
                }
                else if (Key.Length == 32)
                {
                    _wrkState[11] = LEToDword(Key, 16);
                    _wrkState[12] = LEToDword(Key, 20);
                    _wrkState[13] = LEToDword(Key, 24);
                    _wrkState[14] = LEToDword(Key, 28);
                    // nonce constant
                    _wrkState[0] = LEToDword(_ftSigma, 0);
                    _wrkState[5] = LEToDword(_ftSigma, 4);
                    _wrkState[10] = LEToDword(_ftSigma, 8);
                    _wrkState[15] = LEToDword(_ftSigma, 12);
                }
                else
                {
                    _wrkState[11] = LEToDword(Key, 0);
                    _wrkState[12] = LEToDword(Key, 4);
                    _wrkState[13] = LEToDword(Key, 8);
                    _wrkState[14] = LEToDword(Key, 12);
                    // nonce constant
                    _wrkState[0] = LEToDword(_ftTau, 0);
                    _wrkState[5] = LEToDword(_ftTau, 4);
                    _wrkState[10] = LEToDword(_ftTau, 8);
                    _wrkState[15] = LEToDword(_ftTau, 12);
                }

                // if nonce portion of key is too symmetrical, pre-process
                if (Key.Length > 32 && !ValidNonce(Key, 32, 16))
                    CreateNonce();
            }
        }
        #endregion

        #region Transform
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
            int stateLen = _wrkState.Length;
            Int32[] chachaOut = new Int32[stateLen];
            Int32[] stateTemp = new Int32[stateLen];

            // copy state
            Buffer.BlockCopy(_wrkState, 0, stateTemp, 0, stateLen * 4);

            // create a new nonce with core
            SalsaCore(20, stateTemp, chachaOut);

            // copy new nonce to state
            _wrkState[0] = chachaOut[0];
            _wrkState[5] = chachaOut[5];
            _wrkState[10] = chachaOut[10];
            _wrkState[15] = chachaOut[15];

            // check for unique counter
            if (_wrkState[8] == _wrkState[6])
                _wrkState[8] = chachaOut[8];
            if (_wrkState[9] == _wrkState[7])
                _wrkState[9] = chachaOut[9];
        }

        private static byte[] DwordToLE(Int32 Dword, byte[] Le, Int32 OutOffset)
        {
            Le[OutOffset] = (byte)Dword;
            Le[OutOffset + 1] = (byte)(Dword >> 8);
            Le[OutOffset + 2] = (byte)(Dword >> 16);
            Le[OutOffset + 3] = (byte)(Dword >> 24);
            return Le;
        }

        private static void DwordsToLEs(Int32[] Dwords, byte[] Le, Int32 OutOffset)
        {
            for (int i = 0; i < Dwords.Length; ++i)
            {
                DwordToLE(Dwords[i], Le, OutOffset);
                OutOffset += 4;
            }
        }

        private static Int32 LEToDword(byte[] Le, Int32 InOffset)
        {
            return ((Le[InOffset] & 255)) |
                   ((Le[InOffset + 1] & 255) << 8) |
                   ((Le[InOffset + 2] & 255) << 16) |
                   (Le[InOffset + 3] << 24);
        }

        private void GenerateKeyStream(byte[] Output)
        {
            SalsaCore(_dfnRounds, _wrkState, _wrkBuffer);
            DwordsToLEs(_wrkBuffer, Output, 0);
        }

        private static Int32 RotL(Int32 X, Int32 Y)
        {
            return (X << Y) | ((Int32)((uint)X >> -Y));
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
                    if (_keyStream != null)
                    {
                        Array.Clear(_keyStream, 0, _keyStream.Length);
                        _keyStream = null;
                    }
                    if (_wrkBuffer != null)
                    {
                        Array.Clear(_wrkBuffer, 0, _wrkBuffer.Length);
                        _wrkBuffer = null;
                    }
                    if (_wrkState != null)
                    {
                        Array.Clear(_wrkState, 0, _wrkState.Length);
                        _wrkState = null;
                    }
                    if (_ftTau != null)
                    {
                        Array.Clear(_ftTau, 0, _ftTau.Length);
                        _ftTau = null;
                    }
                    if (_ftSigma != null)
                    {
                        Array.Clear(_ftSigma, 0, _ftSigma.Length);
                        _ftSigma = null;
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
