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
/// 
/// SHA3: <see cref="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report of the SHA-3 Cryptographic Hash Algorithm Competition</see>.</para>
/// 
/// <para><description>Code Base Guides:</description>
/// Portions of this code based on the Bouncy Castle Java 
/// <see cref="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</para>
/// 
/// <para><description>Implementation Details:</description>
/// An implementation of the Skein digest. 
/// Written by John Underhill, January 12, 2014
/// contact: steppenwolfe_2000@yahoo.com</para>
/// </remarks>
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    /// <summary>
    /// Specifies the Skein initialization type.
    /// </summary>
    public enum SkeinInitializationType
    {
        /// <summary>
        /// Identical to the standard Skein initialization.
        /// </summary>
        Normal,
        /// <summary>
        /// Creates the initial state with zeros instead of the configuration block, then initializes the hash.
        /// This does not start a new UBI block type, and must be done manually.
        /// </summary>
        ZeroedState,
        /// <summary>
        /// Leaves the initial state set to its previous value, which is then chained with subsequent block transforms.
        /// This does not start a new UBI block type, and must be done manually.
        /// </summary>
        ChainedState,
        /// <summary>
        /// Creates the initial state by chaining the previous state value with the config block, then initializes the hash.
        /// This starts a new UBI block type with the standard Payload type.
        /// </summary>
        ChainedConfig
    }

    /// <summary>
    /// Skein: An implementation of the Skein digest.
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new Skein())
    /// {
    ///     // compute a hash
    ///     byte[] Output = ComputeHash(Input);
    /// }
    /// </code>
    /// </example>
    /// </summary> 
    public sealed class Skein : IDigest, IDisposable
    {
        #region Constants
        private const string ALG_NAME = "Skein";
        private const int BLOCK_SIZE = 32;
        private const int DIGEST_SIZE = 64;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private ThreefishCipher _cipher;
        private int _cipherStateBits;
        private int _cipherStateBytes;
        private int _cipherStateWords;
        private int _outputBytes;
        private byte[] _inputBuffer;
        private int _bytesFilled;
        private ulong[] _cipherInput;
        private ulong[] _state;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize 
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// 
        /// </summary>
        public SkeinConfig Configuration { get; private set; }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize 
        {
            get { return DIGEST_SIZE; }
        }

        /// <summary>
        /// Get: The Digest name
        /// </summary>
        public string Name 
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// 
        /// </summary>
        public UbiTweak UbiParameters { get; private set; }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        public Skein(int stateSize, int outputSize)
        {
            // Make sure the output bit size > 0
            if (outputSize <= 0)
                throw new Exception("Output bit size must be greater than zero.");

            // Make sure output size is divisible by 8
            if (outputSize % 8 != 0)
                throw new Exception("Output bit size must be divisible by 8.");

            _cipherStateBits = stateSize;
            _cipherStateBytes = stateSize / 8;
            _cipherStateWords = stateSize / 64;

            int HashSizeValue = outputSize;// adjust digest size
            _outputBytes = (outputSize + 7) / 8;

            // Figure out which cipher we need based on
            // the state size
            _cipher = ThreefishCipher.CreateCipher(stateSize);
            if (_cipher == null)
                throw new Exception("Unsupported state size.");

            // Allocate buffers
            _inputBuffer = new byte[_cipherStateBytes];
            _cipherInput = new ulong[_cipherStateWords];
            _state = new ulong[_cipherStateWords];

            // Allocate tweak
            UbiParameters = new UbiTweak();

            // Generate the configuration string
            Configuration = new SkeinConfig(this);
            Configuration.SetSchema(83, 72, 65, 51); // "SHA3"
            Configuration.SetVersion(1);
            Configuration.GenerateConfiguration();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            int bytesDone = 0;
            int offset = InOffset;

            // Fill input buffer
            while (bytesDone < Length && offset < Input.Length)
            {
                // Do a transform if the input buffer is filled
                if (_bytesFilled == _cipherStateBytes)
                {
                    // Copy input buffer to cipher input buffer
                    InputBufferToCipherInput();

                    // Process the block
                    ProcessBlock(_cipherStateBytes);

                    // Clear first flag, which will be set
                    // by Initialize() if this is the first transform
                    UbiParameters.IsFirstBlock = false;

                    // Reset buffer fill count
                    _bytesFilled = 0;
                }

                _inputBuffer[_bytesFilled++] = Input[offset++];
                bytesDone++;
            }
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Hash value</returns>
        public byte[] ComputeHash(byte[] Input)
        {
            return null;
        }

        /// <summary>
        /// Do processing
        /// </summary>
        /// 
        /// <param name="Output">Inputs the block, and returns the Hash value</param>
        /// <param name="OutOffset">The starting positional offset within the Output array</param>
        /// 
        /// <returns>Size of Hash value</returns>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            int i;

            // Pad left over space in input buffer with zeros
            // and copy to cipher input buffer
            for (i = _bytesFilled; i < _inputBuffer.Length; i++)
                _inputBuffer[i] = 0;

            InputBufferToCipherInput();

            // Do final message block
            UbiParameters.IsFinalBlock = true;
            ProcessBlock(_bytesFilled);

            // Clear cipher input
            for (i = 0; i < _cipherInput.Length; i++)
                _cipherInput[i] = 0;

            // Do output block counter mode output
            int j;

            var hash = new byte[_outputBytes];
            var oldState = new ulong[_cipherStateWords];

            // Save old state
            for (j = 0; j < _state.Length; j++)
                oldState[j] = _state[j];

            for (i = 0; i < _outputBytes; i += _cipherStateBytes)
            {
                UbiParameters.StartNewBlockType(UbiType.Out);
                UbiParameters.IsFinalBlock = true;
                ProcessBlock(8);

                // Output a chunk of the hash
                int outputSize = _outputBytes - i;
                if (outputSize > _cipherStateBytes)
                    outputSize = _cipherStateBytes;

                PutBytes(_state, hash, i, outputSize);

                // Restore old state
                for (j = 0; j < _state.Length; j++)
                    _state[j] = oldState[j];

                // Increment counter
                _cipherInput[0]++;
            }

            Buffer.BlockCopy(hash, 0, Output, OutOffset, hash.Length);

            return hash.Length;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {

        }

        /// <summary>
        /// Update the message digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {

        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Creates the initial state with zeros instead of the configuration block, then initializes the hash.
        /// This does not start a new UBI block type, and must be done manually.
        /// </summary>
        public void Initialize(SkeinInitializationType initializationType)
        {
            switch (initializationType)
            {
                case SkeinInitializationType.Normal:
                    // Normal initialization
                    Initialize();
                    return;

                case SkeinInitializationType.ZeroedState:
                    // Copy the configuration value to the state
                    for (int i = 0; i < _state.Length; i++)
                        _state[i] = 0;
                    break;

                case SkeinInitializationType.ChainedState:
                    // Keep the state as it is and do nothing
                    break;

                case SkeinInitializationType.ChainedConfig:
                    // Generate a chained configuration
                    Configuration.GenerateConfiguration(_state);
                    // Continue initialization
                    Initialize();
                    return;
            }

            // Reset bytes filled
            _bytesFilled = 0;
        }

        public void Initialize()
        {
            // Copy the configuration value to the state
            for (int i = 0; i < _state.Length; i++)
                _state[i] = Configuration.ConfigValue[i];

            // Set up tweak for message block
            UbiParameters.StartNewBlockType(UbiType.Message);

            // Reset bytes filled
            _bytesFilled = 0;
        }

        // Moves the byte input buffer to the ulong cipher input
        void InputBufferToCipherInput()
        {
            for (int i = 0; i < _cipherStateWords; i++)
                _cipherInput[i] = GetUInt64(_inputBuffer, i * 8);
        }

        void ProcessBlock(int bytes)
        {
            // Set the key to the current state
            _cipher.SetKey(_state);

            // Update tweak
            UbiParameters.BitsProcessed += (ulong)bytes;
            _cipher.SetTweak(UbiParameters.Tweak);

            // Encrypt block
            _cipher.Encrypt(_cipherInput, _state);

            // Feed-forward input with state
            for (int i = 0; i < _cipherInput.Length; i++)
                _state[i] ^= _cipherInput[i];
        }

        static ulong GetUInt64(byte[] buf, int offset)
        {
            ulong v = buf[offset];
            v |= (ulong)buf[offset + 1] << 8;
            v |= (ulong)buf[offset + 2] << 16;
            v |= (ulong)buf[offset + 3] << 24;
            v |= (ulong)buf[offset + 4] << 32;
            v |= (ulong)buf[offset + 5] << 40;
            v |= (ulong)buf[offset + 6] << 48;
            v |= (ulong)buf[offset + 7] << 56;
            return v;
        }

        static void PutBytes(ulong[] input, byte[] output, int offset, int byteCount)
        {
            int j = 0;
            for (int i = 0; i < byteCount; i++)
            {
                //PutUInt64(output, i + offset, input[i / 8]);
                output[offset + i] = (byte)((input[i / 8] >> j) & 0xff);
                j = (j + 8) % 64;
            }
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
            if (!_isDisposed)
            {
                if (Disposing)
                {
                    /*if (_cipherMode != null)
                    {
                        _cipherMode.Dispose();
                        _cipherMode = null;
                    }
                    if (_messageCode != null)
                    {
                        Array.Clear(_messageCode, 0, _messageCode.Length);
                        _messageCode = null;
                    }*/

                    _isDisposed = true;
                }
            }
        }
        #endregion

        #region Threefish
        #region ThreefishCipher
        internal abstract class ThreefishCipher
        {
            protected const ulong KeyScheduleConst = 0x1BD11BDAA9FC1A22;
            protected const int ExpandedTweakSize = 3;

            protected ulong[] ExpandedKey;
            protected ulong[] ExpandedTweak;

            protected ThreefishCipher()
            {
                ExpandedTweak = new ulong[ExpandedTweakSize];
            }

            protected static ulong RotateLeft64(ulong v, int b)
            {
                return (v << b) | (v >> (64 - b));
            }

            protected static ulong RotateRight64(ulong v, int b)
            {
                return (v >> b) | (v << (64 - b));
            }

            protected static void Mix(ref ulong a, ref ulong b, int r)
            {
                a += b;
                b = RotateLeft64(b, r) ^ a;
            }

            protected static void Mix(ref ulong a, ref ulong b, int r, ulong k0, ulong k1)
            {
                b += k1;
                a += b + k0;
                b = RotateLeft64(b, r) ^ a;
            }

            protected static void UnMix(ref ulong a, ref ulong b, int r)
            {
                b = RotateRight64(b ^ a, r);
                a -= b;
            }

            protected static void UnMix(ref ulong a, ref ulong b, int r, ulong k0, ulong k1)
            {
                b = RotateRight64(b ^ a, r);
                a -= b + k0;
                b -= k1;
            }

            public void SetTweak(ulong[] tweak)
            {
                ExpandedTweak[0] = tweak[0];
                ExpandedTweak[1] = tweak[1];
                ExpandedTweak[2] = tweak[0] ^ tweak[1];
            }

            public void SetKey(ulong[] key)
            {
                int i;
                ulong parity = KeyScheduleConst;

                for (i = 0; i < ExpandedKey.Length - 1; i++)
                {
                    ExpandedKey[i] = key[i];
                    parity ^= key[i];
                }

                ExpandedKey[i] = parity;
            }

            public static ThreefishCipher CreateCipher(int stateSize)
            {
                switch (stateSize)
                {
                    case 256: return new Threefish256();
                    case 512: return new Threefish512();
                    case 1024: return new Threefish1024();
                }
                return null;
            }

            abstract public void Encrypt(ulong[] input, ulong[] output);
            abstract public void Decrypt(ulong[] input, ulong[] output);
        }
        #endregion

        #region UbiTweak
        public enum UbiType : ulong
        {
            Key = 0,
            Config = 4,
            Personalization = 8,
            PublicKey = 12,
            KeyIdentifier = 16,
            Nonce = 20,
            Message = 48,
            Out = 63
        }

        public class UbiTweak
        {
            private const ulong T1FlagFinal = unchecked((ulong)1 << 63);
            private const ulong T1FlagFirst = unchecked((ulong)1 << 62);

            public UbiTweak()
            {
                Tweak = new ulong[2];
            }

            /// <summary>
            /// Gets or sets the first block flag.
            /// </summary>
            public bool IsFirstBlock
            {
                get { return (Tweak[1] & T1FlagFirst) != 0; }
                set
                {
                    long mask = value ? 1 : 0;
                    Tweak[1] = (Tweak[1] & ~T1FlagFirst) | ((ulong)-mask & T1FlagFirst);
                }
            }

            /// <summary>
            /// Gets or sets the final block flag.
            /// </summary>
            public bool IsFinalBlock
            {
                get { return (Tweak[1] & T1FlagFinal) != 0; }
                set
                {
                    long mask = value ? 1 : 0;
                    Tweak[1] = (Tweak[1] & ~T1FlagFinal) | ((ulong)-mask & T1FlagFinal);
                }
            }

            /// <summary>
            /// Gets or sets the current tree level.
            /// </summary>
            public byte TreeLevel
            {
                get { return (byte)((Tweak[1] >> 48) & 0x3f); }
                set
                {
                    if (value > 63)
                        throw new Exception("Tree level must be between 0 and 63, inclusive.");

                    Tweak[1] &= ~((ulong)0x3f << 48);
                    Tweak[1] |= (ulong)value << 48;
                }
            }

            /// <summary>
            /// Gets or sets the number of bits processed so far, inclusive.
            /// </summary>
            public ulong BitsProcessed
            {
                get { return Tweak[0]; }
                set { Tweak[0] = value; }
            }

            /// <summary>
            /// Gets or sets the current UBI block type.
            /// </summary>
            public UbiType BlockType
            {
                get { return (UbiType)(Tweak[1] >> 56); }
                set { Tweak[1] = (ulong)value << 56; }
            }

            /// <summary>
            /// Starts a new UBI block type by setting BitsProcessed to zero, setting the first flag, and setting the block type.
            /// </summary>
            /// <param name="type">The UBI block type of the new block.</param>
            public void StartNewBlockType(UbiType type)
            {
                BitsProcessed = 0;
                BlockType = type;
                IsFirstBlock = true;
            }

            /// <summary>
            /// The current Threefish tweak value.
            /// </summary>
            public ulong[] Tweak { get; private set; }
        }
        #endregion

        #region Threefish256
        internal class Threefish256 : ThreefishCipher
        {
            const int CipherSize = 256;
            const int CipherQwords = CipherSize / 64;
            const int ExpandedKeySize = CipherQwords + 1;

            public Threefish256()
            {
                // Create the expanded key array
                ExpandedKey = new ulong[ExpandedKeySize];
                ExpandedKey[ExpandedKeySize - 1] = KeyScheduleConst;
            }

            public override void Encrypt(ulong[] input, ulong[] output)
            {
                // Cache the block, key, and tweak
                ulong b0 = input[0], b1 = input[1],
                      b2 = input[2], b3 = input[3];
                ulong k0 = ExpandedKey[0], k1 = ExpandedKey[1],
                      k2 = ExpandedKey[2], k3 = ExpandedKey[3],
                      k4 = ExpandedKey[4];
                ulong t0 = ExpandedTweak[0], t1 = ExpandedTweak[1],
                      t2 = ExpandedTweak[2];

                Mix(ref b0, ref b1, 14, k0, k1 + t0);
                Mix(ref b2, ref b3, 16, k2 + t1, k3);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k1, k2 + t1);
                Mix(ref b2, ref b3, 33, k3 + t2, k4 + 1);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k2, k3 + t2);
                Mix(ref b2, ref b3, 16, k4 + t0, k0 + 2);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k3, k4 + t0);
                Mix(ref b2, ref b3, 33, k0 + t1, k1 + 3);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k4, k0 + t1);
                Mix(ref b2, ref b3, 16, k1 + t2, k2 + 4);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k0, k1 + t2);
                Mix(ref b2, ref b3, 33, k2 + t0, k3 + 5);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k1, k2 + t0);
                Mix(ref b2, ref b3, 16, k3 + t1, k4 + 6);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k2, k3 + t1);
                Mix(ref b2, ref b3, 33, k4 + t2, k0 + 7);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k3, k4 + t2);
                Mix(ref b2, ref b3, 16, k0 + t0, k1 + 8);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k4, k0 + t0);
                Mix(ref b2, ref b3, 33, k1 + t1, k2 + 9);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k0, k1 + t1);
                Mix(ref b2, ref b3, 16, k2 + t2, k3 + 10);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k1, k2 + t2);
                Mix(ref b2, ref b3, 33, k3 + t0, k4 + 11);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k2, k3 + t0);
                Mix(ref b2, ref b3, 16, k4 + t1, k0 + 12);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k3, k4 + t1);
                Mix(ref b2, ref b3, 33, k0 + t2, k1 + 13);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k4, k0 + t2);
                Mix(ref b2, ref b3, 16, k1 + t0, k2 + 14);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k0, k1 + t0);
                Mix(ref b2, ref b3, 33, k2 + t1, k3 + 15);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);
                Mix(ref b0, ref b1, 14, k1, k2 + t1);
                Mix(ref b2, ref b3, 16, k3 + t2, k4 + 16);
                Mix(ref b0, ref b3, 52);
                Mix(ref b2, ref b1, 57);
                Mix(ref b0, ref b1, 23);
                Mix(ref b2, ref b3, 40);
                Mix(ref b0, ref b3, 5);
                Mix(ref b2, ref b1, 37);
                Mix(ref b0, ref b1, 25, k2, k3 + t2);
                Mix(ref b2, ref b3, 33, k4 + t0, k0 + 17);
                Mix(ref b0, ref b3, 46);
                Mix(ref b2, ref b1, 12);
                Mix(ref b0, ref b1, 58);
                Mix(ref b2, ref b3, 22);
                Mix(ref b0, ref b3, 32);
                Mix(ref b2, ref b1, 32);

                output[0] = b0 + k3;
                output[1] = b1 + k4 + t0;
                output[2] = b2 + k0 + t1;
                output[3] = b3 + k1 + 18;
            }

            public override void Decrypt(ulong[] input, ulong[] output)
            {
                // Cache the block, key, and tweak
                ulong b0 = input[0], b1 = input[1],
                      b2 = input[2], b3 = input[3];
                ulong k0 = ExpandedKey[0], k1 = ExpandedKey[1],
                      k2 = ExpandedKey[2], k3 = ExpandedKey[3],
                      k4 = ExpandedKey[4];
                ulong t0 = ExpandedTweak[0], t1 = ExpandedTweak[1],
                      t2 = ExpandedTweak[2];

                b0 -= k3;
                b1 -= k4 + t0;
                b2 -= k0 + t1;
                b3 -= k1 + 18;
                UnMix(ref b0, ref b3, 32);
                UnMix(ref b2, ref b1, 32);
                UnMix(ref b0, ref b1, 58);
                UnMix(ref b2, ref b3, 22);
                UnMix(ref b0, ref b3, 46);
                UnMix(ref b2, ref b1, 12);
                UnMix(ref b0, ref b1, 25, k2, k3 + t2);
                UnMix(ref b2, ref b3, 33, k4 + t0, k0 + 17);
                UnMix(ref b0, ref b3, 5);
                UnMix(ref b2, ref b1, 37);
                UnMix(ref b0, ref b1, 23);
                UnMix(ref b2, ref b3, 40);
                UnMix(ref b0, ref b3, 52);
                UnMix(ref b2, ref b1, 57);
                UnMix(ref b0, ref b1, 14, k1, k2 + t1);
                UnMix(ref b2, ref b3, 16, k3 + t2, k4 + 16);
                UnMix(ref b0, ref b3, 32);
                UnMix(ref b2, ref b1, 32);
                UnMix(ref b0, ref b1, 58);
                UnMix(ref b2, ref b3, 22);
                UnMix(ref b0, ref b3, 46);
                UnMix(ref b2, ref b1, 12);
                UnMix(ref b0, ref b1, 25, k0, k1 + t0);
                UnMix(ref b2, ref b3, 33, k2 + t1, k3 + 15);
                UnMix(ref b0, ref b3, 5);
                UnMix(ref b2, ref b1, 37);
                UnMix(ref b0, ref b1, 23);
                UnMix(ref b2, ref b3, 40);
                UnMix(ref b0, ref b3, 52);
                UnMix(ref b2, ref b1, 57);
                UnMix(ref b0, ref b1, 14, k4, k0 + t2);
                UnMix(ref b2, ref b3, 16, k1 + t0, k2 + 14);
                UnMix(ref b0, ref b3, 32);
                UnMix(ref b2, ref b1, 32);
                UnMix(ref b0, ref b1, 58);
                UnMix(ref b2, ref b3, 22);
                UnMix(ref b0, ref b3, 46);
                UnMix(ref b2, ref b1, 12);
                UnMix(ref b0, ref b1, 25, k3, k4 + t1);
                UnMix(ref b2, ref b3, 33, k0 + t2, k1 + 13);
                UnMix(ref b0, ref b3, 5);
                UnMix(ref b2, ref b1, 37);
                UnMix(ref b0, ref b1, 23);
                UnMix(ref b2, ref b3, 40);
                UnMix(ref b0, ref b3, 52);
                UnMix(ref b2, ref b1, 57);
                UnMix(ref b0, ref b1, 14, k2, k3 + t0);
                UnMix(ref b2, ref b3, 16, k4 + t1, k0 + 12);
                UnMix(ref b0, ref b3, 32);
                UnMix(ref b2, ref b1, 32);
                UnMix(ref b0, ref b1, 58);
                UnMix(ref b2, ref b3, 22);
                UnMix(ref b0, ref b3, 46);
                UnMix(ref b2, ref b1, 12);
                UnMix(ref b0, ref b1, 25, k1, k2 + t2);
                UnMix(ref b2, ref b3, 33, k3 + t0, k4 + 11);
                UnMix(ref b0, ref b3, 5);
                UnMix(ref b2, ref b1, 37);
                UnMix(ref b0, ref b1, 23);
                UnMix(ref b2, ref b3, 40);
                UnMix(ref b0, ref b3, 52);
                UnMix(ref b2, ref b1, 57);
                UnMix(ref b0, ref b1, 14, k0, k1 + t1);
                UnMix(ref b2, ref b3, 16, k2 + t2, k3 + 10);
                UnMix(ref b0, ref b3, 32);
                UnMix(ref b2, ref b1, 32);
                UnMix(ref b0, ref b1, 58);
                UnMix(ref b2, ref b3, 22);
                UnMix(ref b0, ref b3, 46);
                UnMix(ref b2, ref b1, 12);
                UnMix(ref b0, ref b1, 25, k4, k0 + t0);
                UnMix(ref b2, ref b3, 33, k1 + t1, k2 + 9);
                UnMix(ref b0, ref b3, 5);
                UnMix(ref b2, ref b1, 37);
                UnMix(ref b0, ref b1, 23);
                UnMix(ref b2, ref b3, 40);
                UnMix(ref b0, ref b3, 52);
                UnMix(ref b2, ref b1, 57);
                UnMix(ref b0, ref b1, 14, k3, k4 + t2);
                UnMix(ref b2, ref b3, 16, k0 + t0, k1 + 8);
                UnMix(ref b0, ref b3, 32);
                UnMix(ref b2, ref b1, 32);
                UnMix(ref b0, ref b1, 58);
                UnMix(ref b2, ref b3, 22);
                UnMix(ref b0, ref b3, 46);
                UnMix(ref b2, ref b1, 12);
                UnMix(ref b0, ref b1, 25, k2, k3 + t1);
                UnMix(ref b2, ref b3, 33, k4 + t2, k0 + 7);
                UnMix(ref b0, ref b3, 5);
                UnMix(ref b2, ref b1, 37);
                UnMix(ref b0, ref b1, 23);
                UnMix(ref b2, ref b3, 40);
                UnMix(ref b0, ref b3, 52);
                UnMix(ref b2, ref b1, 57);
                UnMix(ref b0, ref b1, 14, k1, k2 + t0);
                UnMix(ref b2, ref b3, 16, k3 + t1, k4 + 6);
                UnMix(ref b0, ref b3, 32);
                UnMix(ref b2, ref b1, 32);
                UnMix(ref b0, ref b1, 58);
                UnMix(ref b2, ref b3, 22);
                UnMix(ref b0, ref b3, 46);
                UnMix(ref b2, ref b1, 12);
                UnMix(ref b0, ref b1, 25, k0, k1 + t2);
                UnMix(ref b2, ref b3, 33, k2 + t0, k3 + 5);
                UnMix(ref b0, ref b3, 5);
                UnMix(ref b2, ref b1, 37);
                UnMix(ref b0, ref b1, 23);
                UnMix(ref b2, ref b3, 40);
                UnMix(ref b0, ref b3, 52);
                UnMix(ref b2, ref b1, 57);
                UnMix(ref b0, ref b1, 14, k4, k0 + t1);
                UnMix(ref b2, ref b3, 16, k1 + t2, k2 + 4);
                UnMix(ref b0, ref b3, 32);
                UnMix(ref b2, ref b1, 32);
                UnMix(ref b0, ref b1, 58);
                UnMix(ref b2, ref b3, 22);
                UnMix(ref b0, ref b3, 46);
                UnMix(ref b2, ref b1, 12);
                UnMix(ref b0, ref b1, 25, k3, k4 + t0);
                UnMix(ref b2, ref b3, 33, k0 + t1, k1 + 3);
                UnMix(ref b0, ref b3, 5);
                UnMix(ref b2, ref b1, 37);
                UnMix(ref b0, ref b1, 23);
                UnMix(ref b2, ref b3, 40);
                UnMix(ref b0, ref b3, 52);
                UnMix(ref b2, ref b1, 57);
                UnMix(ref b0, ref b1, 14, k2, k3 + t2);
                UnMix(ref b2, ref b3, 16, k4 + t0, k0 + 2);
                UnMix(ref b0, ref b3, 32);
                UnMix(ref b2, ref b1, 32);
                UnMix(ref b0, ref b1, 58);
                UnMix(ref b2, ref b3, 22);
                UnMix(ref b0, ref b3, 46);
                UnMix(ref b2, ref b1, 12);
                UnMix(ref b0, ref b1, 25, k1, k2 + t1);
                UnMix(ref b2, ref b3, 33, k3 + t2, k4 + 1);
                UnMix(ref b0, ref b3, 5);
                UnMix(ref b2, ref b1, 37);
                UnMix(ref b0, ref b1, 23);
                UnMix(ref b2, ref b3, 40);
                UnMix(ref b0, ref b3, 52);
                UnMix(ref b2, ref b1, 57);
                UnMix(ref b0, ref b1, 14, k0, k1 + t0);
                UnMix(ref b2, ref b3, 16, k2 + t1, k3);

                output[0] = b0;
                output[1] = b1;
                output[2] = b2;
                output[3] = b3;
            }
        }
        #endregion

        #region Threefish512
        internal class Threefish512 : ThreefishCipher
        {
            const int CipherSize = 512;
            const int CipherQwords = CipherSize / 64;
            const int ExpandedKeySize = CipherQwords + 1;

            public Threefish512()
            {
                // Create the expanded key array
                ExpandedKey = new ulong[ExpandedKeySize];
                ExpandedKey[ExpandedKeySize - 1] = KeyScheduleConst;
            }

            public override void Encrypt(ulong[] input, ulong[] output)
            {
                // Cache the block, key, and tweak
                ulong b0 = input[0], b1 = input[1],
                      b2 = input[2], b3 = input[3],
                      b4 = input[4], b5 = input[5],
                      b6 = input[6], b7 = input[7];
                ulong k0 = ExpandedKey[0], k1 = ExpandedKey[1],
                      k2 = ExpandedKey[2], k3 = ExpandedKey[3],
                      k4 = ExpandedKey[4], k5 = ExpandedKey[5],
                      k6 = ExpandedKey[6], k7 = ExpandedKey[7],
                      k8 = ExpandedKey[8];
                ulong t0 = ExpandedTweak[0], t1 = ExpandedTweak[1],
                      t2 = ExpandedTweak[2];

                Mix(ref b0, ref b1, 46, k0, k1);
                Mix(ref b2, ref b3, 36, k2, k3);
                Mix(ref b4, ref b5, 19, k4, k5 + t0);
                Mix(ref b6, ref b7, 37, k6 + t1, k7);
                Mix(ref b2, ref b1, 33);
                Mix(ref b4, ref b7, 27);
                Mix(ref b6, ref b5, 14);
                Mix(ref b0, ref b3, 42);
                Mix(ref b4, ref b1, 17);
                Mix(ref b6, ref b3, 49);
                Mix(ref b0, ref b5, 36);
                Mix(ref b2, ref b7, 39);
                Mix(ref b6, ref b1, 44);
                Mix(ref b0, ref b7, 9);
                Mix(ref b2, ref b5, 54);
                Mix(ref b4, ref b3, 56);
                Mix(ref b0, ref b1, 39, k1, k2);
                Mix(ref b2, ref b3, 30, k3, k4);
                Mix(ref b4, ref b5, 34, k5, k6 + t1);
                Mix(ref b6, ref b7, 24, k7 + t2, k8 + 1);
                Mix(ref b2, ref b1, 13);
                Mix(ref b4, ref b7, 50);
                Mix(ref b6, ref b5, 10);
                Mix(ref b0, ref b3, 17);
                Mix(ref b4, ref b1, 25);
                Mix(ref b6, ref b3, 29);
                Mix(ref b0, ref b5, 39);
                Mix(ref b2, ref b7, 43);
                Mix(ref b6, ref b1, 8);
                Mix(ref b0, ref b7, 35);
                Mix(ref b2, ref b5, 56);
                Mix(ref b4, ref b3, 22);
                Mix(ref b0, ref b1, 46, k2, k3);
                Mix(ref b2, ref b3, 36, k4, k5);
                Mix(ref b4, ref b5, 19, k6, k7 + t2);
                Mix(ref b6, ref b7, 37, k8 + t0, k0 + 2);
                Mix(ref b2, ref b1, 33);
                Mix(ref b4, ref b7, 27);
                Mix(ref b6, ref b5, 14);
                Mix(ref b0, ref b3, 42);
                Mix(ref b4, ref b1, 17);
                Mix(ref b6, ref b3, 49);
                Mix(ref b0, ref b5, 36);
                Mix(ref b2, ref b7, 39);
                Mix(ref b6, ref b1, 44);
                Mix(ref b0, ref b7, 9);
                Mix(ref b2, ref b5, 54);
                Mix(ref b4, ref b3, 56);
                Mix(ref b0, ref b1, 39, k3, k4);
                Mix(ref b2, ref b3, 30, k5, k6);
                Mix(ref b4, ref b5, 34, k7, k8 + t0);
                Mix(ref b6, ref b7, 24, k0 + t1, k1 + 3);
                Mix(ref b2, ref b1, 13);
                Mix(ref b4, ref b7, 50);
                Mix(ref b6, ref b5, 10);
                Mix(ref b0, ref b3, 17);
                Mix(ref b4, ref b1, 25);
                Mix(ref b6, ref b3, 29);
                Mix(ref b0, ref b5, 39);
                Mix(ref b2, ref b7, 43);
                Mix(ref b6, ref b1, 8);
                Mix(ref b0, ref b7, 35);
                Mix(ref b2, ref b5, 56);
                Mix(ref b4, ref b3, 22);
                Mix(ref b0, ref b1, 46, k4, k5);
                Mix(ref b2, ref b3, 36, k6, k7);
                Mix(ref b4, ref b5, 19, k8, k0 + t1);
                Mix(ref b6, ref b7, 37, k1 + t2, k2 + 4);
                Mix(ref b2, ref b1, 33);
                Mix(ref b4, ref b7, 27);
                Mix(ref b6, ref b5, 14);
                Mix(ref b0, ref b3, 42);
                Mix(ref b4, ref b1, 17);
                Mix(ref b6, ref b3, 49);
                Mix(ref b0, ref b5, 36);
                Mix(ref b2, ref b7, 39);
                Mix(ref b6, ref b1, 44);
                Mix(ref b0, ref b7, 9);
                Mix(ref b2, ref b5, 54);
                Mix(ref b4, ref b3, 56);
                Mix(ref b0, ref b1, 39, k5, k6);
                Mix(ref b2, ref b3, 30, k7, k8);
                Mix(ref b4, ref b5, 34, k0, k1 + t2);
                Mix(ref b6, ref b7, 24, k2 + t0, k3 + 5);
                Mix(ref b2, ref b1, 13);
                Mix(ref b4, ref b7, 50);
                Mix(ref b6, ref b5, 10);
                Mix(ref b0, ref b3, 17);
                Mix(ref b4, ref b1, 25);
                Mix(ref b6, ref b3, 29);
                Mix(ref b0, ref b5, 39);
                Mix(ref b2, ref b7, 43);
                Mix(ref b6, ref b1, 8);
                Mix(ref b0, ref b7, 35);
                Mix(ref b2, ref b5, 56);
                Mix(ref b4, ref b3, 22);
                Mix(ref b0, ref b1, 46, k6, k7);
                Mix(ref b2, ref b3, 36, k8, k0);
                Mix(ref b4, ref b5, 19, k1, k2 + t0);
                Mix(ref b6, ref b7, 37, k3 + t1, k4 + 6);
                Mix(ref b2, ref b1, 33);
                Mix(ref b4, ref b7, 27);
                Mix(ref b6, ref b5, 14);
                Mix(ref b0, ref b3, 42);
                Mix(ref b4, ref b1, 17);
                Mix(ref b6, ref b3, 49);
                Mix(ref b0, ref b5, 36);
                Mix(ref b2, ref b7, 39);
                Mix(ref b6, ref b1, 44);
                Mix(ref b0, ref b7, 9);
                Mix(ref b2, ref b5, 54);
                Mix(ref b4, ref b3, 56);
                Mix(ref b0, ref b1, 39, k7, k8);
                Mix(ref b2, ref b3, 30, k0, k1);
                Mix(ref b4, ref b5, 34, k2, k3 + t1);
                Mix(ref b6, ref b7, 24, k4 + t2, k5 + 7);
                Mix(ref b2, ref b1, 13);
                Mix(ref b4, ref b7, 50);
                Mix(ref b6, ref b5, 10);
                Mix(ref b0, ref b3, 17);
                Mix(ref b4, ref b1, 25);
                Mix(ref b6, ref b3, 29);
                Mix(ref b0, ref b5, 39);
                Mix(ref b2, ref b7, 43);
                Mix(ref b6, ref b1, 8);
                Mix(ref b0, ref b7, 35);
                Mix(ref b2, ref b5, 56);
                Mix(ref b4, ref b3, 22);
                Mix(ref b0, ref b1, 46, k8, k0);
                Mix(ref b2, ref b3, 36, k1, k2);
                Mix(ref b4, ref b5, 19, k3, k4 + t2);
                Mix(ref b6, ref b7, 37, k5 + t0, k6 + 8);
                Mix(ref b2, ref b1, 33);
                Mix(ref b4, ref b7, 27);
                Mix(ref b6, ref b5, 14);
                Mix(ref b0, ref b3, 42);
                Mix(ref b4, ref b1, 17);
                Mix(ref b6, ref b3, 49);
                Mix(ref b0, ref b5, 36);
                Mix(ref b2, ref b7, 39);
                Mix(ref b6, ref b1, 44);
                Mix(ref b0, ref b7, 9);
                Mix(ref b2, ref b5, 54);
                Mix(ref b4, ref b3, 56);
                Mix(ref b0, ref b1, 39, k0, k1);
                Mix(ref b2, ref b3, 30, k2, k3);
                Mix(ref b4, ref b5, 34, k4, k5 + t0);
                Mix(ref b6, ref b7, 24, k6 + t1, k7 + 9);
                Mix(ref b2, ref b1, 13);
                Mix(ref b4, ref b7, 50);
                Mix(ref b6, ref b5, 10);
                Mix(ref b0, ref b3, 17);
                Mix(ref b4, ref b1, 25);
                Mix(ref b6, ref b3, 29);
                Mix(ref b0, ref b5, 39);
                Mix(ref b2, ref b7, 43);
                Mix(ref b6, ref b1, 8);
                Mix(ref b0, ref b7, 35);
                Mix(ref b2, ref b5, 56);
                Mix(ref b4, ref b3, 22);
                Mix(ref b0, ref b1, 46, k1, k2);
                Mix(ref b2, ref b3, 36, k3, k4);
                Mix(ref b4, ref b5, 19, k5, k6 + t1);
                Mix(ref b6, ref b7, 37, k7 + t2, k8 + 10);
                Mix(ref b2, ref b1, 33);
                Mix(ref b4, ref b7, 27);
                Mix(ref b6, ref b5, 14);
                Mix(ref b0, ref b3, 42);
                Mix(ref b4, ref b1, 17);
                Mix(ref b6, ref b3, 49);
                Mix(ref b0, ref b5, 36);
                Mix(ref b2, ref b7, 39);
                Mix(ref b6, ref b1, 44);
                Mix(ref b0, ref b7, 9);
                Mix(ref b2, ref b5, 54);
                Mix(ref b4, ref b3, 56);
                Mix(ref b0, ref b1, 39, k2, k3);
                Mix(ref b2, ref b3, 30, k4, k5);
                Mix(ref b4, ref b5, 34, k6, k7 + t2);
                Mix(ref b6, ref b7, 24, k8 + t0, k0 + 11);
                Mix(ref b2, ref b1, 13);
                Mix(ref b4, ref b7, 50);
                Mix(ref b6, ref b5, 10);
                Mix(ref b0, ref b3, 17);
                Mix(ref b4, ref b1, 25);
                Mix(ref b6, ref b3, 29);
                Mix(ref b0, ref b5, 39);
                Mix(ref b2, ref b7, 43);
                Mix(ref b6, ref b1, 8);
                Mix(ref b0, ref b7, 35);
                Mix(ref b2, ref b5, 56);
                Mix(ref b4, ref b3, 22);
                Mix(ref b0, ref b1, 46, k3, k4);
                Mix(ref b2, ref b3, 36, k5, k6);
                Mix(ref b4, ref b5, 19, k7, k8 + t0);
                Mix(ref b6, ref b7, 37, k0 + t1, k1 + 12);
                Mix(ref b2, ref b1, 33);
                Mix(ref b4, ref b7, 27);
                Mix(ref b6, ref b5, 14);
                Mix(ref b0, ref b3, 42);
                Mix(ref b4, ref b1, 17);
                Mix(ref b6, ref b3, 49);
                Mix(ref b0, ref b5, 36);
                Mix(ref b2, ref b7, 39);
                Mix(ref b6, ref b1, 44);
                Mix(ref b0, ref b7, 9);
                Mix(ref b2, ref b5, 54);
                Mix(ref b4, ref b3, 56);
                Mix(ref b0, ref b1, 39, k4, k5);
                Mix(ref b2, ref b3, 30, k6, k7);
                Mix(ref b4, ref b5, 34, k8, k0 + t1);
                Mix(ref b6, ref b7, 24, k1 + t2, k2 + 13);
                Mix(ref b2, ref b1, 13);
                Mix(ref b4, ref b7, 50);
                Mix(ref b6, ref b5, 10);
                Mix(ref b0, ref b3, 17);
                Mix(ref b4, ref b1, 25);
                Mix(ref b6, ref b3, 29);
                Mix(ref b0, ref b5, 39);
                Mix(ref b2, ref b7, 43);
                Mix(ref b6, ref b1, 8);
                Mix(ref b0, ref b7, 35);
                Mix(ref b2, ref b5, 56);
                Mix(ref b4, ref b3, 22);
                Mix(ref b0, ref b1, 46, k5, k6);
                Mix(ref b2, ref b3, 36, k7, k8);
                Mix(ref b4, ref b5, 19, k0, k1 + t2);
                Mix(ref b6, ref b7, 37, k2 + t0, k3 + 14);
                Mix(ref b2, ref b1, 33);
                Mix(ref b4, ref b7, 27);
                Mix(ref b6, ref b5, 14);
                Mix(ref b0, ref b3, 42);
                Mix(ref b4, ref b1, 17);
                Mix(ref b6, ref b3, 49);
                Mix(ref b0, ref b5, 36);
                Mix(ref b2, ref b7, 39);
                Mix(ref b6, ref b1, 44);
                Mix(ref b0, ref b7, 9);
                Mix(ref b2, ref b5, 54);
                Mix(ref b4, ref b3, 56);
                Mix(ref b0, ref b1, 39, k6, k7);
                Mix(ref b2, ref b3, 30, k8, k0);
                Mix(ref b4, ref b5, 34, k1, k2 + t0);
                Mix(ref b6, ref b7, 24, k3 + t1, k4 + 15);
                Mix(ref b2, ref b1, 13);
                Mix(ref b4, ref b7, 50);
                Mix(ref b6, ref b5, 10);
                Mix(ref b0, ref b3, 17);
                Mix(ref b4, ref b1, 25);
                Mix(ref b6, ref b3, 29);
                Mix(ref b0, ref b5, 39);
                Mix(ref b2, ref b7, 43);
                Mix(ref b6, ref b1, 8);
                Mix(ref b0, ref b7, 35);
                Mix(ref b2, ref b5, 56);
                Mix(ref b4, ref b3, 22);
                Mix(ref b0, ref b1, 46, k7, k8);
                Mix(ref b2, ref b3, 36, k0, k1);
                Mix(ref b4, ref b5, 19, k2, k3 + t1);
                Mix(ref b6, ref b7, 37, k4 + t2, k5 + 16);
                Mix(ref b2, ref b1, 33);
                Mix(ref b4, ref b7, 27);
                Mix(ref b6, ref b5, 14);
                Mix(ref b0, ref b3, 42);
                Mix(ref b4, ref b1, 17);
                Mix(ref b6, ref b3, 49);
                Mix(ref b0, ref b5, 36);
                Mix(ref b2, ref b7, 39);
                Mix(ref b6, ref b1, 44);
                Mix(ref b0, ref b7, 9);
                Mix(ref b2, ref b5, 54);
                Mix(ref b4, ref b3, 56);
                Mix(ref b0, ref b1, 39, k8, k0);
                Mix(ref b2, ref b3, 30, k1, k2);
                Mix(ref b4, ref b5, 34, k3, k4 + t2);
                Mix(ref b6, ref b7, 24, k5 + t0, k6 + 17);
                Mix(ref b2, ref b1, 13);
                Mix(ref b4, ref b7, 50);
                Mix(ref b6, ref b5, 10);
                Mix(ref b0, ref b3, 17);
                Mix(ref b4, ref b1, 25);
                Mix(ref b6, ref b3, 29);
                Mix(ref b0, ref b5, 39);
                Mix(ref b2, ref b7, 43);
                Mix(ref b6, ref b1, 8);
                Mix(ref b0, ref b7, 35);
                Mix(ref b2, ref b5, 56);
                Mix(ref b4, ref b3, 22);

                // Final key schedule
                output[0] = b0 + k0;
                output[1] = b1 + k1;
                output[2] = b2 + k2;
                output[3] = b3 + k3;
                output[4] = b4 + k4;
                output[5] = b5 + k5 + t0;
                output[6] = b6 + k6 + t1;
                output[7] = b7 + k7 + 18;
            }

            public override void Decrypt(ulong[] input, ulong[] output)
            {
                // Cache the block, key, and tweak
                ulong b0 = input[0], b1 = input[1],
                      b2 = input[2], b3 = input[3],
                      b4 = input[4], b5 = input[5],
                      b6 = input[6], b7 = input[7];
                ulong k0 = ExpandedKey[0], k1 = ExpandedKey[1],
                      k2 = ExpandedKey[2], k3 = ExpandedKey[3],
                      k4 = ExpandedKey[4], k5 = ExpandedKey[5],
                      k6 = ExpandedKey[6], k7 = ExpandedKey[7],
                      k8 = ExpandedKey[8];
                ulong t0 = ExpandedTweak[0], t1 = ExpandedTweak[1],
                      t2 = ExpandedTweak[2];


                b0 -= k0;
                b1 -= k1;
                b2 -= k2;
                b3 -= k3;
                b4 -= k4;
                b5 -= k5 + t0;
                b6 -= k6 + t1;
                b7 -= k7 + 18;
                UnMix(ref b4, ref b3, 22);
                UnMix(ref b2, ref b5, 56);
                UnMix(ref b0, ref b7, 35);
                UnMix(ref b6, ref b1, 8);
                UnMix(ref b2, ref b7, 43);
                UnMix(ref b0, ref b5, 39);
                UnMix(ref b6, ref b3, 29);
                UnMix(ref b4, ref b1, 25);
                UnMix(ref b0, ref b3, 17);
                UnMix(ref b6, ref b5, 10);
                UnMix(ref b4, ref b7, 50);
                UnMix(ref b2, ref b1, 13);
                UnMix(ref b6, ref b7, 24, k5 + t0, k6 + 17);
                UnMix(ref b4, ref b5, 34, k3, k4 + t2);
                UnMix(ref b2, ref b3, 30, k1, k2);
                UnMix(ref b0, ref b1, 39, k8, k0);
                UnMix(ref b4, ref b3, 56);
                UnMix(ref b2, ref b5, 54);
                UnMix(ref b0, ref b7, 9);
                UnMix(ref b6, ref b1, 44);
                UnMix(ref b2, ref b7, 39);
                UnMix(ref b0, ref b5, 36);
                UnMix(ref b6, ref b3, 49);
                UnMix(ref b4, ref b1, 17);
                UnMix(ref b0, ref b3, 42);
                UnMix(ref b6, ref b5, 14);
                UnMix(ref b4, ref b7, 27);
                UnMix(ref b2, ref b1, 33);
                UnMix(ref b6, ref b7, 37, k4 + t2, k5 + 16);
                UnMix(ref b4, ref b5, 19, k2, k3 + t1);
                UnMix(ref b2, ref b3, 36, k0, k1);
                UnMix(ref b0, ref b1, 46, k7, k8);
                UnMix(ref b4, ref b3, 22);
                UnMix(ref b2, ref b5, 56);
                UnMix(ref b0, ref b7, 35);
                UnMix(ref b6, ref b1, 8);
                UnMix(ref b2, ref b7, 43);
                UnMix(ref b0, ref b5, 39);
                UnMix(ref b6, ref b3, 29);
                UnMix(ref b4, ref b1, 25);
                UnMix(ref b0, ref b3, 17);
                UnMix(ref b6, ref b5, 10);
                UnMix(ref b4, ref b7, 50);
                UnMix(ref b2, ref b1, 13);
                UnMix(ref b6, ref b7, 24, k3 + t1, k4 + 15);
                UnMix(ref b4, ref b5, 34, k1, k2 + t0);
                UnMix(ref b2, ref b3, 30, k8, k0);
                UnMix(ref b0, ref b1, 39, k6, k7);
                UnMix(ref b4, ref b3, 56);
                UnMix(ref b2, ref b5, 54);
                UnMix(ref b0, ref b7, 9);
                UnMix(ref b6, ref b1, 44);
                UnMix(ref b2, ref b7, 39);
                UnMix(ref b0, ref b5, 36);
                UnMix(ref b6, ref b3, 49);
                UnMix(ref b4, ref b1, 17);
                UnMix(ref b0, ref b3, 42);
                UnMix(ref b6, ref b5, 14);
                UnMix(ref b4, ref b7, 27);
                UnMix(ref b2, ref b1, 33);
                UnMix(ref b6, ref b7, 37, k2 + t0, k3 + 14);
                UnMix(ref b4, ref b5, 19, k0, k1 + t2);
                UnMix(ref b2, ref b3, 36, k7, k8);
                UnMix(ref b0, ref b1, 46, k5, k6);
                UnMix(ref b4, ref b3, 22);
                UnMix(ref b2, ref b5, 56);
                UnMix(ref b0, ref b7, 35);
                UnMix(ref b6, ref b1, 8);
                UnMix(ref b2, ref b7, 43);
                UnMix(ref b0, ref b5, 39);
                UnMix(ref b6, ref b3, 29);
                UnMix(ref b4, ref b1, 25);
                UnMix(ref b0, ref b3, 17);
                UnMix(ref b6, ref b5, 10);
                UnMix(ref b4, ref b7, 50);
                UnMix(ref b2, ref b1, 13);
                UnMix(ref b6, ref b7, 24, k1 + t2, k2 + 13);
                UnMix(ref b4, ref b5, 34, k8, k0 + t1);
                UnMix(ref b2, ref b3, 30, k6, k7);
                UnMix(ref b0, ref b1, 39, k4, k5);
                UnMix(ref b4, ref b3, 56);
                UnMix(ref b2, ref b5, 54);
                UnMix(ref b0, ref b7, 9);
                UnMix(ref b6, ref b1, 44);
                UnMix(ref b2, ref b7, 39);
                UnMix(ref b0, ref b5, 36);
                UnMix(ref b6, ref b3, 49);
                UnMix(ref b4, ref b1, 17);
                UnMix(ref b0, ref b3, 42);
                UnMix(ref b6, ref b5, 14);
                UnMix(ref b4, ref b7, 27);
                UnMix(ref b2, ref b1, 33);
                UnMix(ref b6, ref b7, 37, k0 + t1, k1 + 12);
                UnMix(ref b4, ref b5, 19, k7, k8 + t0);
                UnMix(ref b2, ref b3, 36, k5, k6);
                UnMix(ref b0, ref b1, 46, k3, k4);
                UnMix(ref b4, ref b3, 22);
                UnMix(ref b2, ref b5, 56);
                UnMix(ref b0, ref b7, 35);
                UnMix(ref b6, ref b1, 8);
                UnMix(ref b2, ref b7, 43);
                UnMix(ref b0, ref b5, 39);
                UnMix(ref b6, ref b3, 29);
                UnMix(ref b4, ref b1, 25);
                UnMix(ref b0, ref b3, 17);
                UnMix(ref b6, ref b5, 10);
                UnMix(ref b4, ref b7, 50);
                UnMix(ref b2, ref b1, 13);
                UnMix(ref b6, ref b7, 24, k8 + t0, k0 + 11);
                UnMix(ref b4, ref b5, 34, k6, k7 + t2);
                UnMix(ref b2, ref b3, 30, k4, k5);
                UnMix(ref b0, ref b1, 39, k2, k3);
                UnMix(ref b4, ref b3, 56);
                UnMix(ref b2, ref b5, 54);
                UnMix(ref b0, ref b7, 9);
                UnMix(ref b6, ref b1, 44);
                UnMix(ref b2, ref b7, 39);
                UnMix(ref b0, ref b5, 36);
                UnMix(ref b6, ref b3, 49);
                UnMix(ref b4, ref b1, 17);
                UnMix(ref b0, ref b3, 42);
                UnMix(ref b6, ref b5, 14);
                UnMix(ref b4, ref b7, 27);
                UnMix(ref b2, ref b1, 33);
                UnMix(ref b6, ref b7, 37, k7 + t2, k8 + 10);
                UnMix(ref b4, ref b5, 19, k5, k6 + t1);
                UnMix(ref b2, ref b3, 36, k3, k4);
                UnMix(ref b0, ref b1, 46, k1, k2);
                UnMix(ref b4, ref b3, 22);
                UnMix(ref b2, ref b5, 56);
                UnMix(ref b0, ref b7, 35);
                UnMix(ref b6, ref b1, 8);
                UnMix(ref b2, ref b7, 43);
                UnMix(ref b0, ref b5, 39);
                UnMix(ref b6, ref b3, 29);
                UnMix(ref b4, ref b1, 25);
                UnMix(ref b0, ref b3, 17);
                UnMix(ref b6, ref b5, 10);
                UnMix(ref b4, ref b7, 50);
                UnMix(ref b2, ref b1, 13);
                UnMix(ref b6, ref b7, 24, k6 + t1, k7 + 9);
                UnMix(ref b4, ref b5, 34, k4, k5 + t0);
                UnMix(ref b2, ref b3, 30, k2, k3);
                UnMix(ref b0, ref b1, 39, k0, k1);
                UnMix(ref b4, ref b3, 56);
                UnMix(ref b2, ref b5, 54);
                UnMix(ref b0, ref b7, 9);
                UnMix(ref b6, ref b1, 44);
                UnMix(ref b2, ref b7, 39);
                UnMix(ref b0, ref b5, 36);
                UnMix(ref b6, ref b3, 49);
                UnMix(ref b4, ref b1, 17);
                UnMix(ref b0, ref b3, 42);
                UnMix(ref b6, ref b5, 14);
                UnMix(ref b4, ref b7, 27);
                UnMix(ref b2, ref b1, 33);
                UnMix(ref b6, ref b7, 37, k5 + t0, k6 + 8);
                UnMix(ref b4, ref b5, 19, k3, k4 + t2);
                UnMix(ref b2, ref b3, 36, k1, k2);
                UnMix(ref b0, ref b1, 46, k8, k0);
                UnMix(ref b4, ref b3, 22);
                UnMix(ref b2, ref b5, 56);
                UnMix(ref b0, ref b7, 35);
                UnMix(ref b6, ref b1, 8);
                UnMix(ref b2, ref b7, 43);
                UnMix(ref b0, ref b5, 39);
                UnMix(ref b6, ref b3, 29);
                UnMix(ref b4, ref b1, 25);
                UnMix(ref b0, ref b3, 17);
                UnMix(ref b6, ref b5, 10);
                UnMix(ref b4, ref b7, 50);
                UnMix(ref b2, ref b1, 13);
                UnMix(ref b6, ref b7, 24, k4 + t2, k5 + 7);
                UnMix(ref b4, ref b5, 34, k2, k3 + t1);
                UnMix(ref b2, ref b3, 30, k0, k1);
                UnMix(ref b0, ref b1, 39, k7, k8);
                UnMix(ref b4, ref b3, 56);
                UnMix(ref b2, ref b5, 54);
                UnMix(ref b0, ref b7, 9);
                UnMix(ref b6, ref b1, 44);
                UnMix(ref b2, ref b7, 39);
                UnMix(ref b0, ref b5, 36);
                UnMix(ref b6, ref b3, 49);
                UnMix(ref b4, ref b1, 17);
                UnMix(ref b0, ref b3, 42);
                UnMix(ref b6, ref b5, 14);
                UnMix(ref b4, ref b7, 27);
                UnMix(ref b2, ref b1, 33);
                UnMix(ref b6, ref b7, 37, k3 + t1, k4 + 6);
                UnMix(ref b4, ref b5, 19, k1, k2 + t0);
                UnMix(ref b2, ref b3, 36, k8, k0);
                UnMix(ref b0, ref b1, 46, k6, k7);
                UnMix(ref b4, ref b3, 22);
                UnMix(ref b2, ref b5, 56);
                UnMix(ref b0, ref b7, 35);
                UnMix(ref b6, ref b1, 8);
                UnMix(ref b2, ref b7, 43);
                UnMix(ref b0, ref b5, 39);
                UnMix(ref b6, ref b3, 29);
                UnMix(ref b4, ref b1, 25);
                UnMix(ref b0, ref b3, 17);
                UnMix(ref b6, ref b5, 10);
                UnMix(ref b4, ref b7, 50);
                UnMix(ref b2, ref b1, 13);
                UnMix(ref b6, ref b7, 24, k2 + t0, k3 + 5);
                UnMix(ref b4, ref b5, 34, k0, k1 + t2);
                UnMix(ref b2, ref b3, 30, k7, k8);
                UnMix(ref b0, ref b1, 39, k5, k6);
                UnMix(ref b4, ref b3, 56);
                UnMix(ref b2, ref b5, 54);
                UnMix(ref b0, ref b7, 9);
                UnMix(ref b6, ref b1, 44);
                UnMix(ref b2, ref b7, 39);
                UnMix(ref b0, ref b5, 36);
                UnMix(ref b6, ref b3, 49);
                UnMix(ref b4, ref b1, 17);
                UnMix(ref b0, ref b3, 42);
                UnMix(ref b6, ref b5, 14);
                UnMix(ref b4, ref b7, 27);
                UnMix(ref b2, ref b1, 33);
                UnMix(ref b6, ref b7, 37, k1 + t2, k2 + 4);
                UnMix(ref b4, ref b5, 19, k8, k0 + t1);
                UnMix(ref b2, ref b3, 36, k6, k7);
                UnMix(ref b0, ref b1, 46, k4, k5);
                UnMix(ref b4, ref b3, 22);
                UnMix(ref b2, ref b5, 56);
                UnMix(ref b0, ref b7, 35);
                UnMix(ref b6, ref b1, 8);
                UnMix(ref b2, ref b7, 43);
                UnMix(ref b0, ref b5, 39);
                UnMix(ref b6, ref b3, 29);
                UnMix(ref b4, ref b1, 25);
                UnMix(ref b0, ref b3, 17);
                UnMix(ref b6, ref b5, 10);
                UnMix(ref b4, ref b7, 50);
                UnMix(ref b2, ref b1, 13);
                UnMix(ref b6, ref b7, 24, k0 + t1, k1 + 3);
                UnMix(ref b4, ref b5, 34, k7, k8 + t0);
                UnMix(ref b2, ref b3, 30, k5, k6);
                UnMix(ref b0, ref b1, 39, k3, k4);
                UnMix(ref b4, ref b3, 56);
                UnMix(ref b2, ref b5, 54);
                UnMix(ref b0, ref b7, 9);
                UnMix(ref b6, ref b1, 44);
                UnMix(ref b2, ref b7, 39);
                UnMix(ref b0, ref b5, 36);
                UnMix(ref b6, ref b3, 49);
                UnMix(ref b4, ref b1, 17);
                UnMix(ref b0, ref b3, 42);
                UnMix(ref b6, ref b5, 14);
                UnMix(ref b4, ref b7, 27);
                UnMix(ref b2, ref b1, 33);
                UnMix(ref b6, ref b7, 37, k8 + t0, k0 + 2);
                UnMix(ref b4, ref b5, 19, k6, k7 + t2);
                UnMix(ref b2, ref b3, 36, k4, k5);
                UnMix(ref b0, ref b1, 46, k2, k3);
                UnMix(ref b4, ref b3, 22);
                UnMix(ref b2, ref b5, 56);
                UnMix(ref b0, ref b7, 35);
                UnMix(ref b6, ref b1, 8);
                UnMix(ref b2, ref b7, 43);
                UnMix(ref b0, ref b5, 39);
                UnMix(ref b6, ref b3, 29);
                UnMix(ref b4, ref b1, 25);
                UnMix(ref b0, ref b3, 17);
                UnMix(ref b6, ref b5, 10);
                UnMix(ref b4, ref b7, 50);
                UnMix(ref b2, ref b1, 13);
                UnMix(ref b6, ref b7, 24, k7 + t2, k8 + 1);
                UnMix(ref b4, ref b5, 34, k5, k6 + t1);
                UnMix(ref b2, ref b3, 30, k3, k4);
                UnMix(ref b0, ref b1, 39, k1, k2);
                UnMix(ref b4, ref b3, 56);
                UnMix(ref b2, ref b5, 54);
                UnMix(ref b0, ref b7, 9);
                UnMix(ref b6, ref b1, 44);
                UnMix(ref b2, ref b7, 39);
                UnMix(ref b0, ref b5, 36);
                UnMix(ref b6, ref b3, 49);
                UnMix(ref b4, ref b1, 17);
                UnMix(ref b0, ref b3, 42);
                UnMix(ref b6, ref b5, 14);
                UnMix(ref b4, ref b7, 27);
                UnMix(ref b2, ref b1, 33);
                UnMix(ref b6, ref b7, 37, k6 + t1, k7);
                UnMix(ref b4, ref b5, 19, k4, k5 + t0);
                UnMix(ref b2, ref b3, 36, k2, k3);
                UnMix(ref b0, ref b1, 46, k0, k1);

                output[7] = b7;
                output[6] = b6;
                output[5] = b5;
                output[4] = b4;
                output[3] = b3;
                output[2] = b2;
                output[1] = b1;
                output[0] = b0;
            }
        }
        #endregion

        #region Threefish1024
        internal class Threefish1024 : ThreefishCipher
        {
            const int CIPHER_SIZE = 1024;
            const int CIPHER_QWORDS = CIPHER_SIZE / 64;
            const int EXPANDED_KEY_SIZE = CIPHER_QWORDS + 1;

            public Threefish1024()
            {
                // Create the expanded key array
                ExpandedKey = new ulong[EXPANDED_KEY_SIZE];
                ExpandedKey[EXPANDED_KEY_SIZE - 1] = KeyScheduleConst;
            }

            public override void Encrypt(ulong[] input, ulong[] output)
            {
                // Cache the block, key, and tweak
                ulong b0 = input[0], b1 = input[1],
                      b2 = input[2], b3 = input[3],
                      b4 = input[4], b5 = input[5],
                      b6 = input[6], b7 = input[7],
                      b8 = input[8], b9 = input[9],
                      b10 = input[10], b11 = input[11],
                      b12 = input[12], b13 = input[13],
                      b14 = input[14], b15 = input[15];
                ulong k0 = ExpandedKey[0], k1 = ExpandedKey[1],
                      k2 = ExpandedKey[2], k3 = ExpandedKey[3],
                      k4 = ExpandedKey[4], k5 = ExpandedKey[5],
                      k6 = ExpandedKey[6], k7 = ExpandedKey[7],
                      k8 = ExpandedKey[8], k9 = ExpandedKey[9],
                      k10 = ExpandedKey[10], k11 = ExpandedKey[11],
                      k12 = ExpandedKey[12], k13 = ExpandedKey[13],
                      k14 = ExpandedKey[14], k15 = ExpandedKey[15],
                      k16 = ExpandedKey[16];
                ulong t0 = ExpandedTweak[0], t1 = ExpandedTweak[1],
                      t2 = ExpandedTweak[2];


                Mix(ref b0, ref b1, 24, k0, k1);
                Mix(ref b2, ref b3, 13, k2, k3);
                Mix(ref b4, ref b5, 8, k4, k5);
                Mix(ref b6, ref b7, 47, k6, k7);
                Mix(ref b8, ref b9, 8, k8, k9);
                Mix(ref b10, ref b11, 17, k10, k11);
                Mix(ref b12, ref b13, 22, k12, k13 + t0);
                Mix(ref b14, ref b15, 37, k14 + t1, k15);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k1, k2);
                Mix(ref b2, ref b3, 9, k3, k4);
                Mix(ref b4, ref b5, 37, k5, k6);
                Mix(ref b6, ref b7, 31, k7, k8);
                Mix(ref b8, ref b9, 12, k9, k10);
                Mix(ref b10, ref b11, 47, k11, k12);
                Mix(ref b12, ref b13, 44, k13, k14 + t1);
                Mix(ref b14, ref b15, 30, k15 + t2, k16 + 1);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);
                Mix(ref b0, ref b1, 24, k2, k3);
                Mix(ref b2, ref b3, 13, k4, k5);
                Mix(ref b4, ref b5, 8, k6, k7);
                Mix(ref b6, ref b7, 47, k8, k9);
                Mix(ref b8, ref b9, 8, k10, k11);
                Mix(ref b10, ref b11, 17, k12, k13);
                Mix(ref b12, ref b13, 22, k14, k15 + t2);
                Mix(ref b14, ref b15, 37, k16 + t0, k0 + 2);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k3, k4);
                Mix(ref b2, ref b3, 9, k5, k6);
                Mix(ref b4, ref b5, 37, k7, k8);
                Mix(ref b6, ref b7, 31, k9, k10);
                Mix(ref b8, ref b9, 12, k11, k12);
                Mix(ref b10, ref b11, 47, k13, k14);
                Mix(ref b12, ref b13, 44, k15, k16 + t0);
                Mix(ref b14, ref b15, 30, k0 + t1, k1 + 3);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);
                Mix(ref b0, ref b1, 24, k4, k5);
                Mix(ref b2, ref b3, 13, k6, k7);
                Mix(ref b4, ref b5, 8, k8, k9);
                Mix(ref b6, ref b7, 47, k10, k11);
                Mix(ref b8, ref b9, 8, k12, k13);
                Mix(ref b10, ref b11, 17, k14, k15);
                Mix(ref b12, ref b13, 22, k16, k0 + t1);
                Mix(ref b14, ref b15, 37, k1 + t2, k2 + 4);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k5, k6);
                Mix(ref b2, ref b3, 9, k7, k8);
                Mix(ref b4, ref b5, 37, k9, k10);
                Mix(ref b6, ref b7, 31, k11, k12);
                Mix(ref b8, ref b9, 12, k13, k14);
                Mix(ref b10, ref b11, 47, k15, k16);
                Mix(ref b12, ref b13, 44, k0, k1 + t2);
                Mix(ref b14, ref b15, 30, k2 + t0, k3 + 5);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);
                Mix(ref b0, ref b1, 24, k6, k7);
                Mix(ref b2, ref b3, 13, k8, k9);
                Mix(ref b4, ref b5, 8, k10, k11);
                Mix(ref b6, ref b7, 47, k12, k13);
                Mix(ref b8, ref b9, 8, k14, k15);
                Mix(ref b10, ref b11, 17, k16, k0);
                Mix(ref b12, ref b13, 22, k1, k2 + t0);
                Mix(ref b14, ref b15, 37, k3 + t1, k4 + 6);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k7, k8);
                Mix(ref b2, ref b3, 9, k9, k10);
                Mix(ref b4, ref b5, 37, k11, k12);
                Mix(ref b6, ref b7, 31, k13, k14);
                Mix(ref b8, ref b9, 12, k15, k16);
                Mix(ref b10, ref b11, 47, k0, k1);
                Mix(ref b12, ref b13, 44, k2, k3 + t1);
                Mix(ref b14, ref b15, 30, k4 + t2, k5 + 7);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);
                Mix(ref b0, ref b1, 24, k8, k9);
                Mix(ref b2, ref b3, 13, k10, k11);
                Mix(ref b4, ref b5, 8, k12, k13);
                Mix(ref b6, ref b7, 47, k14, k15);
                Mix(ref b8, ref b9, 8, k16, k0);
                Mix(ref b10, ref b11, 17, k1, k2);
                Mix(ref b12, ref b13, 22, k3, k4 + t2);
                Mix(ref b14, ref b15, 37, k5 + t0, k6 + 8);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k9, k10);
                Mix(ref b2, ref b3, 9, k11, k12);
                Mix(ref b4, ref b5, 37, k13, k14);
                Mix(ref b6, ref b7, 31, k15, k16);
                Mix(ref b8, ref b9, 12, k0, k1);
                Mix(ref b10, ref b11, 47, k2, k3);
                Mix(ref b12, ref b13, 44, k4, k5 + t0);
                Mix(ref b14, ref b15, 30, k6 + t1, k7 + 9);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);
                Mix(ref b0, ref b1, 24, k10, k11);
                Mix(ref b2, ref b3, 13, k12, k13);
                Mix(ref b4, ref b5, 8, k14, k15);
                Mix(ref b6, ref b7, 47, k16, k0);
                Mix(ref b8, ref b9, 8, k1, k2);
                Mix(ref b10, ref b11, 17, k3, k4);
                Mix(ref b12, ref b13, 22, k5, k6 + t1);
                Mix(ref b14, ref b15, 37, k7 + t2, k8 + 10);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k11, k12);
                Mix(ref b2, ref b3, 9, k13, k14);
                Mix(ref b4, ref b5, 37, k15, k16);
                Mix(ref b6, ref b7, 31, k0, k1);
                Mix(ref b8, ref b9, 12, k2, k3);
                Mix(ref b10, ref b11, 47, k4, k5);
                Mix(ref b12, ref b13, 44, k6, k7 + t2);
                Mix(ref b14, ref b15, 30, k8 + t0, k9 + 11);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);
                Mix(ref b0, ref b1, 24, k12, k13);
                Mix(ref b2, ref b3, 13, k14, k15);
                Mix(ref b4, ref b5, 8, k16, k0);
                Mix(ref b6, ref b7, 47, k1, k2);
                Mix(ref b8, ref b9, 8, k3, k4);
                Mix(ref b10, ref b11, 17, k5, k6);
                Mix(ref b12, ref b13, 22, k7, k8 + t0);
                Mix(ref b14, ref b15, 37, k9 + t1, k10 + 12);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k13, k14);
                Mix(ref b2, ref b3, 9, k15, k16);
                Mix(ref b4, ref b5, 37, k0, k1);
                Mix(ref b6, ref b7, 31, k2, k3);
                Mix(ref b8, ref b9, 12, k4, k5);
                Mix(ref b10, ref b11, 47, k6, k7);
                Mix(ref b12, ref b13, 44, k8, k9 + t1);
                Mix(ref b14, ref b15, 30, k10 + t2, k11 + 13);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);
                Mix(ref b0, ref b1, 24, k14, k15);
                Mix(ref b2, ref b3, 13, k16, k0);
                Mix(ref b4, ref b5, 8, k1, k2);
                Mix(ref b6, ref b7, 47, k3, k4);
                Mix(ref b8, ref b9, 8, k5, k6);
                Mix(ref b10, ref b11, 17, k7, k8);
                Mix(ref b12, ref b13, 22, k9, k10 + t2);
                Mix(ref b14, ref b15, 37, k11 + t0, k12 + 14);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k15, k16);
                Mix(ref b2, ref b3, 9, k0, k1);
                Mix(ref b4, ref b5, 37, k2, k3);
                Mix(ref b6, ref b7, 31, k4, k5);
                Mix(ref b8, ref b9, 12, k6, k7);
                Mix(ref b10, ref b11, 47, k8, k9);
                Mix(ref b12, ref b13, 44, k10, k11 + t0);
                Mix(ref b14, ref b15, 30, k12 + t1, k13 + 15);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);
                Mix(ref b0, ref b1, 24, k16, k0);
                Mix(ref b2, ref b3, 13, k1, k2);
                Mix(ref b4, ref b5, 8, k3, k4);
                Mix(ref b6, ref b7, 47, k5, k6);
                Mix(ref b8, ref b9, 8, k7, k8);
                Mix(ref b10, ref b11, 17, k9, k10);
                Mix(ref b12, ref b13, 22, k11, k12 + t1);
                Mix(ref b14, ref b15, 37, k13 + t2, k14 + 16);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k0, k1);
                Mix(ref b2, ref b3, 9, k2, k3);
                Mix(ref b4, ref b5, 37, k4, k5);
                Mix(ref b6, ref b7, 31, k6, k7);
                Mix(ref b8, ref b9, 12, k8, k9);
                Mix(ref b10, ref b11, 47, k10, k11);
                Mix(ref b12, ref b13, 44, k12, k13 + t2);
                Mix(ref b14, ref b15, 30, k14 + t0, k15 + 17);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);
                Mix(ref b0, ref b1, 24, k1, k2);
                Mix(ref b2, ref b3, 13, k3, k4);
                Mix(ref b4, ref b5, 8, k5, k6);
                Mix(ref b6, ref b7, 47, k7, k8);
                Mix(ref b8, ref b9, 8, k9, k10);
                Mix(ref b10, ref b11, 17, k11, k12);
                Mix(ref b12, ref b13, 22, k13, k14 + t0);
                Mix(ref b14, ref b15, 37, k15 + t1, k16 + 18);
                Mix(ref b0, ref b9, 38);
                Mix(ref b2, ref b13, 19);
                Mix(ref b6, ref b11, 10);
                Mix(ref b4, ref b15, 55);
                Mix(ref b10, ref b7, 49);
                Mix(ref b12, ref b3, 18);
                Mix(ref b14, ref b5, 23);
                Mix(ref b8, ref b1, 52);
                Mix(ref b0, ref b7, 33);
                Mix(ref b2, ref b5, 4);
                Mix(ref b4, ref b3, 51);
                Mix(ref b6, ref b1, 13);
                Mix(ref b12, ref b15, 34);
                Mix(ref b14, ref b13, 41);
                Mix(ref b8, ref b11, 59);
                Mix(ref b10, ref b9, 17);
                Mix(ref b0, ref b15, 5);
                Mix(ref b2, ref b11, 20);
                Mix(ref b6, ref b13, 48);
                Mix(ref b4, ref b9, 41);
                Mix(ref b14, ref b1, 47);
                Mix(ref b8, ref b5, 28);
                Mix(ref b10, ref b3, 16);
                Mix(ref b12, ref b7, 25);
                Mix(ref b0, ref b1, 41, k2, k3);
                Mix(ref b2, ref b3, 9, k4, k5);
                Mix(ref b4, ref b5, 37, k6, k7);
                Mix(ref b6, ref b7, 31, k8, k9);
                Mix(ref b8, ref b9, 12, k10, k11);
                Mix(ref b10, ref b11, 47, k12, k13);
                Mix(ref b12, ref b13, 44, k14, k15 + t1);
                Mix(ref b14, ref b15, 30, k16 + t2, k0 + 19);
                Mix(ref b0, ref b9, 16);
                Mix(ref b2, ref b13, 34);
                Mix(ref b6, ref b11, 56);
                Mix(ref b4, ref b15, 51);
                Mix(ref b10, ref b7, 4);
                Mix(ref b12, ref b3, 53);
                Mix(ref b14, ref b5, 42);
                Mix(ref b8, ref b1, 41);
                Mix(ref b0, ref b7, 31);
                Mix(ref b2, ref b5, 44);
                Mix(ref b4, ref b3, 47);
                Mix(ref b6, ref b1, 46);
                Mix(ref b12, ref b15, 19);
                Mix(ref b14, ref b13, 42);
                Mix(ref b8, ref b11, 44);
                Mix(ref b10, ref b9, 25);
                Mix(ref b0, ref b15, 9);
                Mix(ref b2, ref b11, 48);
                Mix(ref b6, ref b13, 35);
                Mix(ref b4, ref b9, 52);
                Mix(ref b14, ref b1, 23);
                Mix(ref b8, ref b5, 31);
                Mix(ref b10, ref b3, 37);
                Mix(ref b12, ref b7, 20);

                // Final key schedule
                output[0] = b0 + k3;
                output[1] = b1 + k4;
                output[2] = b2 + k5;
                output[3] = b3 + k6;
                output[4] = b4 + k7;
                output[5] = b5 + k8;
                output[6] = b6 + k9;
                output[7] = b7 + k10;
                output[8] = b8 + k11;
                output[9] = b9 + k12;
                output[10] = b10 + k13;
                output[11] = b11 + k14;
                output[12] = b12 + k15;
                output[13] = b13 + k16 + t2;
                output[14] = b14 + k0 + t0;
                output[15] = b15 + k1 + 20;
            }

            public override void Decrypt(ulong[] input, ulong[] output)
            {
                // Cache the block, key, and tweak
                ulong b0 = input[0], b1 = input[1],
                      b2 = input[2], b3 = input[3],
                      b4 = input[4], b5 = input[5],
                      b6 = input[6], b7 = input[7],
                      b8 = input[8], b9 = input[9],
                      b10 = input[10], b11 = input[11],
                      b12 = input[12], b13 = input[13],
                      b14 = input[14], b15 = input[15];
                ulong k0 = ExpandedKey[0], k1 = ExpandedKey[1],
                      k2 = ExpandedKey[2], k3 = ExpandedKey[3],
                      k4 = ExpandedKey[4], k5 = ExpandedKey[5],
                      k6 = ExpandedKey[6], k7 = ExpandedKey[7],
                      k8 = ExpandedKey[8], k9 = ExpandedKey[9],
                      k10 = ExpandedKey[10], k11 = ExpandedKey[11],
                      k12 = ExpandedKey[12], k13 = ExpandedKey[13],
                      k14 = ExpandedKey[14], k15 = ExpandedKey[15],
                      k16 = ExpandedKey[16];
                ulong t0 = ExpandedTweak[0], t1 = ExpandedTweak[1],
                      t2 = ExpandedTweak[2];

                b0 -= k3;
                b1 -= k4;
                b2 -= k5;
                b3 -= k6;
                b4 -= k7;
                b5 -= k8;
                b6 -= k9;
                b7 -= k10;
                b8 -= k11;
                b9 -= k12;
                b10 -= k13;
                b11 -= k14;
                b12 -= k15;
                b13 -= k16 + t2;
                b14 -= k0 + t0;
                b15 -= k1 + 20;
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k16 + t2, k0 + 19);
                UnMix(ref b12, ref b13, 44, k14, k15 + t1);
                UnMix(ref b10, ref b11, 47, k12, k13);
                UnMix(ref b8, ref b9, 12, k10, k11);
                UnMix(ref b6, ref b7, 31, k8, k9);
                UnMix(ref b4, ref b5, 37, k6, k7);
                UnMix(ref b2, ref b3, 9, k4, k5);
                UnMix(ref b0, ref b1, 41, k2, k3);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k15 + t1, k16 + 18);
                UnMix(ref b12, ref b13, 22, k13, k14 + t0);
                UnMix(ref b10, ref b11, 17, k11, k12);
                UnMix(ref b8, ref b9, 8, k9, k10);
                UnMix(ref b6, ref b7, 47, k7, k8);
                UnMix(ref b4, ref b5, 8, k5, k6);
                UnMix(ref b2, ref b3, 13, k3, k4);
                UnMix(ref b0, ref b1, 24, k1, k2);
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k14 + t0, k15 + 17);
                UnMix(ref b12, ref b13, 44, k12, k13 + t2);
                UnMix(ref b10, ref b11, 47, k10, k11);
                UnMix(ref b8, ref b9, 12, k8, k9);
                UnMix(ref b6, ref b7, 31, k6, k7);
                UnMix(ref b4, ref b5, 37, k4, k5);
                UnMix(ref b2, ref b3, 9, k2, k3);
                UnMix(ref b0, ref b1, 41, k0, k1);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k13 + t2, k14 + 16);
                UnMix(ref b12, ref b13, 22, k11, k12 + t1);
                UnMix(ref b10, ref b11, 17, k9, k10);
                UnMix(ref b8, ref b9, 8, k7, k8);
                UnMix(ref b6, ref b7, 47, k5, k6);
                UnMix(ref b4, ref b5, 8, k3, k4);
                UnMix(ref b2, ref b3, 13, k1, k2);
                UnMix(ref b0, ref b1, 24, k16, k0);
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k12 + t1, k13 + 15);
                UnMix(ref b12, ref b13, 44, k10, k11 + t0);
                UnMix(ref b10, ref b11, 47, k8, k9);
                UnMix(ref b8, ref b9, 12, k6, k7);
                UnMix(ref b6, ref b7, 31, k4, k5);
                UnMix(ref b4, ref b5, 37, k2, k3);
                UnMix(ref b2, ref b3, 9, k0, k1);
                UnMix(ref b0, ref b1, 41, k15, k16);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k11 + t0, k12 + 14);
                UnMix(ref b12, ref b13, 22, k9, k10 + t2);
                UnMix(ref b10, ref b11, 17, k7, k8);
                UnMix(ref b8, ref b9, 8, k5, k6);
                UnMix(ref b6, ref b7, 47, k3, k4);
                UnMix(ref b4, ref b5, 8, k1, k2);
                UnMix(ref b2, ref b3, 13, k16, k0);
                UnMix(ref b0, ref b1, 24, k14, k15);
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k10 + t2, k11 + 13);
                UnMix(ref b12, ref b13, 44, k8, k9 + t1);
                UnMix(ref b10, ref b11, 47, k6, k7);
                UnMix(ref b8, ref b9, 12, k4, k5);
                UnMix(ref b6, ref b7, 31, k2, k3);
                UnMix(ref b4, ref b5, 37, k0, k1);
                UnMix(ref b2, ref b3, 9, k15, k16);
                UnMix(ref b0, ref b1, 41, k13, k14);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k9 + t1, k10 + 12);
                UnMix(ref b12, ref b13, 22, k7, k8 + t0);
                UnMix(ref b10, ref b11, 17, k5, k6);
                UnMix(ref b8, ref b9, 8, k3, k4);
                UnMix(ref b6, ref b7, 47, k1, k2);
                UnMix(ref b4, ref b5, 8, k16, k0);
                UnMix(ref b2, ref b3, 13, k14, k15);
                UnMix(ref b0, ref b1, 24, k12, k13);
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k8 + t0, k9 + 11);
                UnMix(ref b12, ref b13, 44, k6, k7 + t2);
                UnMix(ref b10, ref b11, 47, k4, k5);
                UnMix(ref b8, ref b9, 12, k2, k3);
                UnMix(ref b6, ref b7, 31, k0, k1);
                UnMix(ref b4, ref b5, 37, k15, k16);
                UnMix(ref b2, ref b3, 9, k13, k14);
                UnMix(ref b0, ref b1, 41, k11, k12);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k7 + t2, k8 + 10);
                UnMix(ref b12, ref b13, 22, k5, k6 + t1);
                UnMix(ref b10, ref b11, 17, k3, k4);
                UnMix(ref b8, ref b9, 8, k1, k2);
                UnMix(ref b6, ref b7, 47, k16, k0);
                UnMix(ref b4, ref b5, 8, k14, k15);
                UnMix(ref b2, ref b3, 13, k12, k13);
                UnMix(ref b0, ref b1, 24, k10, k11);
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k6 + t1, k7 + 9);
                UnMix(ref b12, ref b13, 44, k4, k5 + t0);
                UnMix(ref b10, ref b11, 47, k2, k3);
                UnMix(ref b8, ref b9, 12, k0, k1);
                UnMix(ref b6, ref b7, 31, k15, k16);
                UnMix(ref b4, ref b5, 37, k13, k14);
                UnMix(ref b2, ref b3, 9, k11, k12);
                UnMix(ref b0, ref b1, 41, k9, k10);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k5 + t0, k6 + 8);
                UnMix(ref b12, ref b13, 22, k3, k4 + t2);
                UnMix(ref b10, ref b11, 17, k1, k2);
                UnMix(ref b8, ref b9, 8, k16, k0);
                UnMix(ref b6, ref b7, 47, k14, k15);
                UnMix(ref b4, ref b5, 8, k12, k13);
                UnMix(ref b2, ref b3, 13, k10, k11);
                UnMix(ref b0, ref b1, 24, k8, k9);
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k4 + t2, k5 + 7);
                UnMix(ref b12, ref b13, 44, k2, k3 + t1);
                UnMix(ref b10, ref b11, 47, k0, k1);
                UnMix(ref b8, ref b9, 12, k15, k16);
                UnMix(ref b6, ref b7, 31, k13, k14);
                UnMix(ref b4, ref b5, 37, k11, k12);
                UnMix(ref b2, ref b3, 9, k9, k10);
                UnMix(ref b0, ref b1, 41, k7, k8);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k3 + t1, k4 + 6);
                UnMix(ref b12, ref b13, 22, k1, k2 + t0);
                UnMix(ref b10, ref b11, 17, k16, k0);
                UnMix(ref b8, ref b9, 8, k14, k15);
                UnMix(ref b6, ref b7, 47, k12, k13);
                UnMix(ref b4, ref b5, 8, k10, k11);
                UnMix(ref b2, ref b3, 13, k8, k9);
                UnMix(ref b0, ref b1, 24, k6, k7);
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k2 + t0, k3 + 5);
                UnMix(ref b12, ref b13, 44, k0, k1 + t2);
                UnMix(ref b10, ref b11, 47, k15, k16);
                UnMix(ref b8, ref b9, 12, k13, k14);
                UnMix(ref b6, ref b7, 31, k11, k12);
                UnMix(ref b4, ref b5, 37, k9, k10);
                UnMix(ref b2, ref b3, 9, k7, k8);
                UnMix(ref b0, ref b1, 41, k5, k6);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k1 + t2, k2 + 4);
                UnMix(ref b12, ref b13, 22, k16, k0 + t1);
                UnMix(ref b10, ref b11, 17, k14, k15);
                UnMix(ref b8, ref b9, 8, k12, k13);
                UnMix(ref b6, ref b7, 47, k10, k11);
                UnMix(ref b4, ref b5, 8, k8, k9);
                UnMix(ref b2, ref b3, 13, k6, k7);
                UnMix(ref b0, ref b1, 24, k4, k5);
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k0 + t1, k1 + 3);
                UnMix(ref b12, ref b13, 44, k15, k16 + t0);
                UnMix(ref b10, ref b11, 47, k13, k14);
                UnMix(ref b8, ref b9, 12, k11, k12);
                UnMix(ref b6, ref b7, 31, k9, k10);
                UnMix(ref b4, ref b5, 37, k7, k8);
                UnMix(ref b2, ref b3, 9, k5, k6);
                UnMix(ref b0, ref b1, 41, k3, k4);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k16 + t0, k0 + 2);
                UnMix(ref b12, ref b13, 22, k14, k15 + t2);
                UnMix(ref b10, ref b11, 17, k12, k13);
                UnMix(ref b8, ref b9, 8, k10, k11);
                UnMix(ref b6, ref b7, 47, k8, k9);
                UnMix(ref b4, ref b5, 8, k6, k7);
                UnMix(ref b2, ref b3, 13, k4, k5);
                UnMix(ref b0, ref b1, 24, k2, k3);
                UnMix(ref b12, ref b7, 20);
                UnMix(ref b10, ref b3, 37);
                UnMix(ref b8, ref b5, 31);
                UnMix(ref b14, ref b1, 23);
                UnMix(ref b4, ref b9, 52);
                UnMix(ref b6, ref b13, 35);
                UnMix(ref b2, ref b11, 48);
                UnMix(ref b0, ref b15, 9);
                UnMix(ref b10, ref b9, 25);
                UnMix(ref b8, ref b11, 44);
                UnMix(ref b14, ref b13, 42);
                UnMix(ref b12, ref b15, 19);
                UnMix(ref b6, ref b1, 46);
                UnMix(ref b4, ref b3, 47);
                UnMix(ref b2, ref b5, 44);
                UnMix(ref b0, ref b7, 31);
                UnMix(ref b8, ref b1, 41);
                UnMix(ref b14, ref b5, 42);
                UnMix(ref b12, ref b3, 53);
                UnMix(ref b10, ref b7, 4);
                UnMix(ref b4, ref b15, 51);
                UnMix(ref b6, ref b11, 56);
                UnMix(ref b2, ref b13, 34);
                UnMix(ref b0, ref b9, 16);
                UnMix(ref b14, ref b15, 30, k15 + t2, k16 + 1);
                UnMix(ref b12, ref b13, 44, k13, k14 + t1);
                UnMix(ref b10, ref b11, 47, k11, k12);
                UnMix(ref b8, ref b9, 12, k9, k10);
                UnMix(ref b6, ref b7, 31, k7, k8);
                UnMix(ref b4, ref b5, 37, k5, k6);
                UnMix(ref b2, ref b3, 9, k3, k4);
                UnMix(ref b0, ref b1, 41, k1, k2);
                UnMix(ref b12, ref b7, 25);
                UnMix(ref b10, ref b3, 16);
                UnMix(ref b8, ref b5, 28);
                UnMix(ref b14, ref b1, 47);
                UnMix(ref b4, ref b9, 41);
                UnMix(ref b6, ref b13, 48);
                UnMix(ref b2, ref b11, 20);
                UnMix(ref b0, ref b15, 5);
                UnMix(ref b10, ref b9, 17);
                UnMix(ref b8, ref b11, 59);
                UnMix(ref b14, ref b13, 41);
                UnMix(ref b12, ref b15, 34);
                UnMix(ref b6, ref b1, 13);
                UnMix(ref b4, ref b3, 51);
                UnMix(ref b2, ref b5, 4);
                UnMix(ref b0, ref b7, 33);
                UnMix(ref b8, ref b1, 52);
                UnMix(ref b14, ref b5, 23);
                UnMix(ref b12, ref b3, 18);
                UnMix(ref b10, ref b7, 49);
                UnMix(ref b4, ref b15, 55);
                UnMix(ref b6, ref b11, 10);
                UnMix(ref b2, ref b13, 19);
                UnMix(ref b0, ref b9, 38);
                UnMix(ref b14, ref b15, 37, k14 + t1, k15);
                UnMix(ref b12, ref b13, 22, k12, k13 + t0);
                UnMix(ref b10, ref b11, 17, k10, k11);
                UnMix(ref b8, ref b9, 8, k8, k9);
                UnMix(ref b6, ref b7, 47, k6, k7);
                UnMix(ref b4, ref b5, 8, k4, k5);
                UnMix(ref b2, ref b3, 13, k2, k3);
                UnMix(ref b0, ref b1, 24, k0, k1);

                output[15] = b15;
                output[14] = b14;
                output[13] = b13;
                output[12] = b12;
                output[11] = b11;
                output[10] = b10;
                output[9] = b9;
                output[8] = b8;
                output[7] = b7;
                output[6] = b6;
                output[5] = b5;
                output[4] = b4;
                output[3] = b3;
                output[2] = b2;
                output[1] = b1;
                output[0] = b0;
            }
        }
        #endregion

        #region SkeinConfig
        public class SkeinConfig
        {
            private readonly int _stateSize;

            public SkeinConfig(Skein sourceHash)
            {
                _stateSize = sourceHash.StateSize;

                // Allocate config value
                ConfigValue = new ulong[sourceHash.StateSize / 8];

                // Set the state size for the configuration
                ConfigString = new ulong[ConfigValue.Length];
                ConfigString[1] = (ulong)sourceHash.DigestSize;
            }

            public void GenerateConfiguration()
            {
                var cipher = ThreefishCipher.CreateCipher(_stateSize);
                var tweak = new UbiTweak();

                // Initialize the tweak value
                tweak.StartNewBlockType(UbiType.Config);
                tweak.IsFinalBlock = true;
                tweak.BitsProcessed = 32;

                cipher.SetTweak(tweak.Tweak);
                cipher.Encrypt(ConfigString, ConfigValue);

                ConfigValue[0] ^= ConfigString[0];
                ConfigValue[1] ^= ConfigString[1];
                ConfigValue[2] ^= ConfigString[2];
            }

            public void GenerateConfiguration(ulong[] initialState)
            {
                var cipher = ThreefishCipher.CreateCipher(_stateSize);
                var tweak = new UbiTweak();

                // Initialize the tweak value
                tweak.StartNewBlockType(UbiType.Config);
                tweak.IsFinalBlock = true;
                tweak.BitsProcessed = 32;

                cipher.SetKey(initialState);
                cipher.SetTweak(tweak.Tweak);
                cipher.Encrypt(ConfigString, ConfigValue);

                ConfigValue[0] ^= ConfigString[0];
                ConfigValue[1] ^= ConfigString[1];
                ConfigValue[2] ^= ConfigString[2];
            }

            public void SetSchema(params byte[] schema)
            {
                if (schema.Length != 4) throw new Exception("Schema must be 4 bytes.");

                ulong n = ConfigString[0];

                // Clear the schema bytes
                n &= ~(ulong)0xfffffffful;
                // Set schema bytes
                n |= (ulong)schema[3] << 24;
                n |= (ulong)schema[2] << 16;
                n |= (ulong)schema[1] << 8;
                n |= (ulong)schema[0];

                ConfigString[0] = n;
            }

            public void SetVersion(int version)
            {
                if (version < 0 || version > 3)
                    throw new Exception("Version must be between 0 and 3, inclusive.");

                ConfigString[0] &= ~((ulong)0x03 << 32);
                ConfigString[0] |= (ulong)version << 32;
            }

            public void SetTreeLeafSize(byte size)
            {
                ConfigString[2] &= ~(ulong)0xff;
                ConfigString[2] |= (ulong)size;
            }

            public void SetTreeFanOutSize(byte size)
            {
                ConfigString[2] &= ~((ulong)0xff << 8);
                ConfigString[2] |= (ulong)size << 8;
            }

            public void SetMaxTreeHeight(byte height)
            {
                if (height == 1)
                    throw new Exception("Tree height must be zero or greater than 1.");

                ConfigString[2] &= ~((ulong)0xff << 16);
                ConfigString[2] |= (ulong)height << 16;
            }

            public ulong[] ConfigValue { get; private set; }

            public ulong[] ConfigString { get; private set; }
        }
        #endregion
        #endregion
    }
}
