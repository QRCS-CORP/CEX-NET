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
// An implementation of the SHA-3 digest based on Keccak, designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. 
// SHA3 <see href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</see>.
// 
// Implementation Details:
// An implementation of the SHA-3 digest. 
// Refactoring, a couple of small optimizations, Dispose, and a ComputeHash method added.
// Many thanks to the authors of BouncyCastle for their great contributions.
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Digest
{
    #region Enums
    /// <summary>
    /// Available SHA3 digest return sizes
    /// </summary>
    public enum KeccakDigestSizes : int
    {
        /// <summary>
        /// Digest size is 224 bits (28 bytes)
        /// </summary>
        D224,
        /// <summary>
        /// Digest size is 256 bits (32 bytes)
        /// </summary>
        D256,
        /// <summary>
        /// Digest size is 288 bits (36 bytes)
        /// </summary>
        D288,
        /// <summary>
        /// Digest size is 384 bits (48 bytes)
        /// </summary>
        D384,
        /// <summary>
        /// Digest size is 512 bits (64 bytes)
        /// </summary>
        D512
    }
    #endregion

    /// <summary>
    /// <h3>Keccak: An implementation of the SHA-3 Keccak digest.</h3>
    /// <para>SHA-3 competition winner<cite>SHA-3 Standardization</cite>: The Keccak<cite>Keccak</cite> digest</para>
    /// <list type="bullet">
    /// <item><description>Hash sizes are 28, 32, 48 and 64 bytes (224, 256, 384 and 512 bits).</description></item>
    /// <item><description>Block sizes are 144, 136, 104, and 72 bytes (1152, 1088, 832, 576 bits).</description></item>
    /// <item><description>Use the <see cref="BlockSize"/> property to determine block sizes at runtime.</description></item>
    /// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
    /// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
    /// </list>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IDigest</c> interface:</description>
    /// <code>
    /// using (IDigest hash = new SHA3Digest())
    /// {
    ///     // compute a hash
    ///     byte[] Output = ComputeHash(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    ///     <revision date="2014/11/11" version="1.2.0.0" author="John Underhill">Initial release</revision>
    ///     <revision date="2015/01/23" version="1.3.0.0" author="John Underhill">Changes to formatting and documentation</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digests">VTDev.Libraries.CEXEngine.Crypto.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>SHA3 <see href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</see>.</description></item>
    /// <item><description>SHA3: <see href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report of the SHA-3 Cryptographic Hash Algorithm Competition</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the Bouncy Castle <see href="http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/digests/SHA3Digest.java">SHA3Digest</see> class, 
    /// sphlib 3.0 <see href="http://www.saphir2.com/sphlib/">keccak512.java</see>, 
    /// and the <see href="https://github.com/gvanas/KeccakCodePackage">Keccak Code Package</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class Keccak : IDigest, IDisposable
    {
        #region Constants
        private const string ALG_NAME = "Keccak";
        #endregion

        #region Fields
        private int _bitsForSqueezing;
        private int _bitsInQueue;
        private int _bitRate;
        private Int64[] _C = new Int64[5];
        private Int64[] _chiC = new Int64[5];
        private byte[] _chunk;
        private byte[] _dataQueue = new byte[192];
        private int _fixedOutputLength;
        private bool _isDisposed = false;
        private bool _isSqueezing = false;
        private byte[] _oneByte = new byte[1];
        private static Int64[] _roundConstants;
        private static int[] _rhoOffsets;
        private byte[] _digestState = new byte[200];
        private Int64[] _tempA = new Int64[25];
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return _bitRate / 8; }
        }

        /// <summary>
        /// Get: Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return _fixedOutputLength / 8; }
        }

        /// <summary>
        /// Get: Digest name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the digest; a 512 bit digest size is selected by default
        /// </summary>
        /// 
        /// <param name="DigestSize">Digest return size in bits</param>
        public Keccak(int DigestSize = 512)
        {
            Initialize(DigestSize);
        }

        /// <summary>
        /// Initialize the digest
        /// </summary>
        /// <param name="DigestSize">Digest size enum in bits</param>
        public Keccak(KeccakDigestSizes DigestSize)
        {
            int dgtLen = 512;

            switch (DigestSize)
            {
                case KeccakDigestSizes.D224:
                    dgtLen = 224;
                    break;
                case KeccakDigestSizes.D256:
                    dgtLen = 256;
                    break;
                case KeccakDigestSizes.D288:
                    dgtLen = 288;
                    break;
                case KeccakDigestSizes.D384:
                    dgtLen = 384;
                    break;
            }

            Initialize(dgtLen);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~Keccak()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the SHA3 buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input array</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            DoUpdate(Input, InOffset, Length * 8L);
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
            byte[] hash = new byte[DigestSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Do final processing and get the hash value
        /// </summary>
        /// 
        /// <param name="Output">The Hash value container</param>
        /// <param name="OutOffset">The starting offset within the Output array</param>
        /// 
        /// <returns>Size of Hash value</returns>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            Squeeze(Output, OutOffset, _fixedOutputLength);
            Reset();

            return DigestSize;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            Initialize(DigestSize * 8);
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            _oneByte[0] = Input;

            DoUpdate(_oneByte, 0, 8L);
        }
        #endregion

        #region Private Methods
        private void Absorb(byte[] data, int Offset, long DataBitLen)
        {
            if ((_bitsInQueue % 8) != 0)
                throw new Exception("Attempt to absorb with odd Length queue.");
            if (_isSqueezing)
                throw new Exception("Attempt to absorb while squeezing.");

            long i = 0;
            while (i < DataBitLen)
            {
                if ((_bitsInQueue == 0) && (DataBitLen >= _bitRate) && (i <= (DataBitLen - _bitRate)))
                {
                    long wholeBlocks = (DataBitLen - i) / _bitRate;

                    for (long j = 0; j < wholeBlocks; j++)
                    {
                        Array.Copy(data, (int)(Offset + (i / 8) + (j * _chunk.Length)), _chunk, 0, _chunk.Length);
                        KeccakAbsorb(_digestState, _chunk, _chunk.Length);
                    }

                    i += wholeBlocks * _bitRate;
                }
                else
                {
                    int partialBlock = (int)(DataBitLen - i);

                    if (partialBlock + _bitsInQueue > _bitRate)
                        partialBlock = _bitRate - _bitsInQueue;

                    int partialByte = partialBlock % 8;
                    partialBlock -= partialByte;
                    Array.Copy(data, Offset + (int)(i / 8), _dataQueue, _bitsInQueue / 8, partialBlock / 8);

                    _bitsInQueue += partialBlock;
                    i += partialBlock;

                    if (_bitsInQueue == _bitRate)
                        AbsorbQueue();

                    if (partialByte > 0)
                    {
                        int mask = (1 << partialByte) - 1;
                        _dataQueue[_bitsInQueue / 8] = (byte)(data[Offset + ((int)(i / 8))] & mask);
                        _bitsInQueue += partialByte;
                        i += partialByte;
                    }
                }
            }
        }

        private void AbsorbQueue()
        {
            KeccakAbsorb(_digestState, _dataQueue, _bitRate / 8);
            _bitsInQueue = 0;
        }

        private void ClearDataQueueSection(int Offset, int Length)
        {
            for (int i = Offset; i != Offset + Length; i++)
                _dataQueue[i] = 0;
        }

        private void DoUpdate(byte[] Data, int Offset, long DataBitLen)
        {
            if ((DataBitLen % 8) == 0)
            {
                Absorb(Data, Offset, DataBitLen);
            }
            else
            {
                Absorb(Data, Offset, DataBitLen - (DataBitLen % 8));

                byte[] lastByte = new byte[1];

                lastByte[0] = (byte)(Data[Offset + (int)(DataBitLen / 8)] >> (byte)(8 - (DataBitLen % 8)));
                Absorb(lastByte, Offset, DataBitLen % 8);
            }
        }

        private void Initialize(int BitLength)
        {
            _roundConstants = InitializeRoundConstants(); 
            _rhoOffsets = InitializeRhoOffsets();

            switch (BitLength)
            {
                case 0:
                case 288:
                    InitSponge(1024, 576);
                    break;
                case 224:
                    InitSponge(1152, 448);
                    break;
                case 256:
                    InitSponge(1088, 512);
                    break;
                case 384:
                    InitSponge(832, 768);
                    break;
                case 512:
                    InitSponge(576, 1024);
                    break;
                default:
                    throw new ArgumentException("bitLength must be one of 224, 256, 384, or 512.");
            }
        }

        private static long[] InitializeRoundConstants()
        {
            long[] keccakRoundConstants = new long[24];
            byte[] LFSRstate = new byte[1];

            LFSRstate[0] = 0x01;
            int i, j, bitPosition;

            for (i = 0; i < 24; i++)
            {
                keccakRoundConstants[i] = 0;
                for (j = 0; j < 7; j++)
                {
                    bitPosition = (1 << j) - 1;

                    if (LFSR86540(LFSRstate))
                        keccakRoundConstants[i] ^= 1L << bitPosition;
                }
            }

            return keccakRoundConstants;
        }

        private static int[] InitializeRhoOffsets()
        {
            int[] keccakRhoOffsets = new int[25];
            int x, y, t, newX, newY;

            keccakRhoOffsets[(((0) % 5) + 5 * ((0) % 5))] = 0;
            x = 1;
            y = 0;

            for (t = 0; t < 24; t++)
            {
                keccakRhoOffsets[(((x) % 5) + 5 * ((y) % 5))] = ((t + 1) * (t + 2) / 2) % 64;
                newX = (0 * x + 1 * y) % 5;
                newY = (2 * x + 3 * y) % 5;
                x = newX;
                y = newY;
            }

            return keccakRhoOffsets;
        }

        private void InitSponge(int Rate, int Capacity)
        {
            if (Rate + Capacity != 1600)
                throw new Exception("rate + capacity != 1600");
            if ((Rate <= 0) || (Rate >= 1600) || ((Rate % 64) != 0))
                throw new Exception("invalid rate value");

            _bitRate = Rate;
            _fixedOutputLength = 0;
            Array.Clear(_digestState, 0, _digestState.Length);
            Array.Clear(_dataQueue, 0, _dataQueue.Length);
            _bitsInQueue = 0;
            _isSqueezing = false;
            _bitsForSqueezing = 0;
            _fixedOutputLength = Capacity / 2;
            _chunk = new byte[Rate / 8];
            _oneByte = new byte[1];
        }

        private void KeccakAbsorb(byte[] State, byte[] Data, int DataInBytes)
        {
            KeccakPermutationAfterXor(State, Data, DataInBytes);
        }

        private void KeccakExtract(byte[] State, byte[] Data, int LaneCount)
        {
            Buffer.BlockCopy(State, 0, Data, 0, LaneCount * 8);
        }

        private void KeccakExtract1024bits(byte[] State, byte[] Data)
        {
            Buffer.BlockCopy(State, 0, Data, 0, 128);
        }

        private void KeccakPermutation(byte[] State)
        {
            long[] longState = new long[State.Length / 8];

            BytesToWords(longState, State);
            KeccakPermutationOnWords(longState);
            WordsToBytes(State, longState);
        }

        private void KeccakPermutationAfterXor(byte[] State, byte[] Data, int DataLength)
        {
            for (int i = 0; i < DataLength; i++)
                State[i] ^= Data[i];

            KeccakPermutation(State);
        }

        private void KeccakPermutationOnWords(long[] State)
        {
            for (int i = 0; i < 24; i++)
            {
                Theta(State);
                Rho(State);
                Pi(State);
                Chi(State);
                Iota(State, i);
            }
        }

        private static bool LFSR86540(byte[] LFSR)
        {
            bool result = (((LFSR[0]) & 0x01) != 0);

            if (((LFSR[0]) & 0x80) != 0)
                LFSR[0] = (byte)(((LFSR[0]) << 1) ^ 0x71);
            else
                LFSR[0] <<= 1;

            return result;
        }

        private void PadAndSwitchToSqueezingPhase()
        {
            if (_bitsInQueue + 1 == _bitRate)
            {
                _dataQueue[_bitsInQueue / 8] |= (byte)(1 << (_bitsInQueue % 8));
                AbsorbQueue();
                ClearDataQueueSection(0, _bitRate / 8);
            }
            else
            {
                ClearDataQueueSection((_bitsInQueue + 7) / 8, _bitRate / 8 - (_bitsInQueue + 7) / 8);
                _dataQueue[_bitsInQueue / 8] |= (byte)(1 << (_bitsInQueue % 8));
            }

            _dataQueue[(_bitRate - 1) / 8] |= (byte)(1 << ((_bitRate - 1) % 8));
            AbsorbQueue();

            if (_bitRate == 1024)
            {
                KeccakExtract1024bits(_digestState, _dataQueue);
                _bitsForSqueezing = 1024;
            }
            else
            {
                KeccakExtract(_digestState, _dataQueue, _bitRate / 64);
                _bitsForSqueezing = _bitRate;
            }

            _isSqueezing = true;
        }

        private void Squeeze(byte[] Output, int Offset, long OutputLength)
        {
            int partialBlock;

            if (!_isSqueezing)
                PadAndSwitchToSqueezingPhase();

            if ((OutputLength % 8) != 0)
                throw new Exception("outputLength not a multiple of 8");

            long i = 0;
            while (i < OutputLength)
            {
                if (_bitsForSqueezing == 0)
                {
                    KeccakPermutation(_digestState);

                    if (_bitRate == 1024)
                    {
                        KeccakExtract1024bits(_digestState, _dataQueue);
                        _bitsForSqueezing = 1024;
                    }
                    else
                    {
                        KeccakExtract(_digestState, _dataQueue, _bitRate / 64);
                        _bitsForSqueezing = _bitRate;
                    }
                }

                partialBlock = _bitsForSqueezing;

                if ((long)partialBlock > OutputLength - i)
                    partialBlock = (int)(OutputLength - i);

                Buffer.BlockCopy(_dataQueue, (_bitRate - _bitsForSqueezing) / 8, Output, Offset + (int)(i / 8), partialBlock / 8);
                _bitsForSqueezing -= partialBlock;
                i += partialBlock;
            }
        }
        #endregion

        #region Helpers
        private void BytesToWords(long[] StateWords, byte[] State)
        {
            for (int i = 0; i < (1600 / 64); i++)
            {
                StateWords[i] = 0;
                int index = i * (64 / 8);

                for (int j = 0; j < (64 / 8); j++)
                    StateWords[i] |= ((long)State[index + j] & 0xff) << ((8 * j));
            }
        }

        private void Chi(Int64[] A)
        {
            for (int y = 0; y < 5; y++)
            {
                for (int x = 0; x < 5; x++)
                    _chiC[x] = A[x + 5 * y] ^ ((~A[(((x + 1) % 5) + 5 * y)]) & A[(((x + 2) % 5) + 5 * y)]);
                
                for (int x = 0; x < 5; x++)
                    A[x + 5 * y] = _chiC[x];
            }
        }

        private void Iota(Int64[] A, int indexRound)
        {
            A[(((0) % 5) + 5 * ((0) % 5))] ^= _roundConstants[indexRound];
        }

        private void Pi(Int64[] A)
        {
            Array.Copy(A, 0, _tempA, 0, _tempA.Length);

            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                    A[y + 5 * ((2 * x + 3 * y) % 5)] = _tempA[x + 5 * y];
            }
        }

        private void Rho(Int64[] A)
        {
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    int index = x + 5 * y;
                    A[index] = ((_rhoOffsets[index] != 0) ? (((A[index]) << _rhoOffsets[index]) ^ (Int64)((UInt64)(A[index]) >> (64 - _rhoOffsets[index]))) : A[index]);
                }
            }
        }

        private void Theta(Int64[] A)
        {
            for (int x = 0; x < 5; x++)
            {
                _C[x] = 0;

                for (int y = 0; y < 5; y++)
                    _C[x] ^= A[x + 5 * y];
            }
            for (int x = 0; x < 5; x++)
            {
                Int64 dX = ((((_C[(x + 1) % 5]) << 1) ^ (Int64)((UInt64)(_C[(x + 1) % 5]) >> (64 - 1)))) ^ _C[(x + 4) % 5];

                for (int y = 0; y < 5; y++)
                    A[x + 5 * y] ^= dX;
            }
        }

        private void WordsToBytes(byte[] State, Int64[] StateWords)
        {
            for (int i = 0; i < (1600 / 64); i++)
            {
                int index = i * (64 / 8);

                for (int j = 0; j < (64 / 8); j++)
                    State[index + j] = (byte)((StateWords[i] >> ((8 * j))) & 0xFF);
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
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_digestState != null)
                    {
                        Array.Clear(_digestState, 0, _digestState.Length);
                        _digestState = null;
                    }
                    if (_chunk != null)
                    {
                        Array.Clear(_chunk, 0, _chunk.Length);
                        _chunk = null;
                    }
                    if (_dataQueue != null)
                    {
                        Array.Clear(_dataQueue, 0, _dataQueue.Length);
                        _dataQueue = null;
                    }
                    if (_tempA != null)
                    {
                        Array.Clear(_tempA, 0, _tempA.Length);
                        _tempA = null;
                    }
                    if (_C != null)
                    {
                        Array.Clear(_C, 0, _C.Length);
                        _C = null;
                    }
                    if (_chiC != null)
                    {
                        Array.Clear(_chiC, 0, _chiC.Length);
                        _chiC = null;
                    }
                    if (_roundConstants != null)
                    {
                        Array.Clear(_roundConstants, 0, _roundConstants.Length);
                        _roundConstants = null;
                    }
                    if (_rhoOffsets != null)
                    {
                        Array.Clear(_rhoOffsets, 0, _rhoOffsets.Length);
                        _rhoOffsets = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
