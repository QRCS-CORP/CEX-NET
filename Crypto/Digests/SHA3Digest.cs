using System;

/// Based on Keccak, designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. 
/// http://keccak.noekeon.org/Keccak-submission-3.pdf
/// 
/// Adapted from the BouncyCastle java 1.51 implementation: http://bouncycastle.org/
/// SHA3Digest class: http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/digests/SHA3Digest.java
/// Refactoring, a couple of small optimizations, Dispose, and a ComputeHash method added.
/// Many thanks to the authors of BouncyCastle for their great contributions..

namespace VTDev.Libraries.CEXEngine.Crypto.Digests
{
    public class SHA3Digest : IDigest, IDisposable
    {
        #region Fields
        private int _bitsForSqueezing;
        private int _bitsInQueue;
        private int _bitRate;
        long[] _C = new long[5];
        long[] _chiC = new long[5];
        private byte[] _chunk;
        private byte[] _dataQueue = new byte[(1536 / 8)];
        private int _fixedOutputLength;
        private bool _isDisposed = false;
        private bool _isSqueezing = false;
        private byte[] _oneByte;
        private static long[] _roundConstants;
        private static int[] _rhoOffsets;
        private byte[] _State = new byte[(1600 / 8)];
        long[] _tempA = new long[25];
        #endregion

        #region Properties
        /// <summary>
        /// The Digests internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return _bitRate / 8; }
        }

        /// <summary>
        /// Size of returned digest in bytes
        /// </summary>
        public int DigestSize
        {
            get { return _fixedOutputLength / 8; }
        }

        /// <summary>
        /// Digest name
        /// </summary>
        public string Name
        {
            get { return "SHA3-" + _fixedOutputLength; }
        }
        #endregion

        #region Constructor
        public SHA3Digest()
        {
            Init(0);
        }

        public SHA3Digest(int Length)
        {
            Init(Length);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the SHA3 buffer
        /// </summary>
        /// <param name="Input">Input data [bytes]</param>
        /// <param name="InOffset">Offset within Input array</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            DoUpdate(Input, InOffset, Length * 8L);
        }

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// <param name="Input">Input data [bytes]</param>
        /// <returns>Hash value [64 bytes]</returns>
        public byte[] ComputeHash(byte[] Input)
        {
            byte[] hash = new byte[this.DigestSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Do final processing
        /// </summary>
        /// <param name="Output">Inputs the final block, and returns the Hash value</param>
        /// <param name="OutOffset">The starting positional offset within the Output array</param>
        /// <returns>Size of Hash value</returns>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            Squeeze(Output, OutOffset, _fixedOutputLength);
            Reset();

            return this.DigestSize;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            Init(_fixedOutputLength);
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
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
                        KeccakAbsorb(_State, _chunk, _chunk.Length);
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
            KeccakAbsorb(_State, _dataQueue, _bitRate / 8);
            _bitsInQueue = 0;
        }

        private void ClearDataQueueSection(int Offset, int Length)
        {
            for (int i = Offset; i != Offset + Length; i++)
            {
                _dataQueue[i] = 0;
            }
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

        private void Init(int BitLength)
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
                    {
                        keccakRoundConstants[i] ^= 1L << bitPosition;
                    }
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

            this._bitRate = Rate;
            this._fixedOutputLength = 0;
            Array.Clear(this._State, 0, this._State.Length);
            Array.Clear(this._dataQueue, 0, this._dataQueue.Length);
            this._bitsInQueue = 0;
            this._isSqueezing = false;
            this._bitsForSqueezing = 0;
            this._fixedOutputLength = Capacity / 2;
            this._chunk = new byte[Rate / 8];
            this._oneByte = new byte[1];
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
                KeccakExtract1024bits(_State, _dataQueue);
                _bitsForSqueezing = 1024;
            }
            else
            {
                KeccakExtract(_State, _dataQueue, _bitRate / 64);
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
                    KeccakPermutation(_State);

                    if (_bitRate == 1024)
                    {
                        KeccakExtract1024bits(_State, _dataQueue);
                        _bitsForSqueezing = 1024;
                    }
                    else
                    {
                        KeccakExtract(_State, _dataQueue, _bitRate / 64);
                        _bitsForSqueezing = _bitRate;
                    }
                }

                partialBlock = _bitsForSqueezing;

                if ((long)partialBlock > OutputLength - i)
                    partialBlock = (int)(OutputLength - i);

                Array.Copy(_dataQueue, (_bitRate - _bitsForSqueezing) / 8, Output, Offset + (int)(i / 8), partialBlock / 8);
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
                {
                    StateWords[i] |= ((long)State[index + j] & 0xff) << ((8 * j));
                }
            }
        }

        private void Chi(long[] A)
        {
            for (int y = 0; y < 5; y++)
            {
                for (int x = 0; x < 5; x++)
                {
                    _chiC[x] = A[x + 5 * y] ^ ((~A[(((x + 1) % 5) + 5 * y)]) & A[(((x + 2) % 5) + 5 * y)]);
                }
                for (int x = 0; x < 5; x++)
                {
                    A[x + 5 * y] = _chiC[x];
                }
            }
        }

        private void Iota(long[] A, int indexRound)
        {
            A[(((0) % 5) + 5 * ((0) % 5))] ^= _roundConstants[indexRound];
        }

        private void Pi(long[] A)
        {
            Array.Copy(A, 0, _tempA, 0, _tempA.Length);

            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    A[y + 5 * ((2 * x + 3 * y) % 5)] = _tempA[x + 5 * y];
                }
            }
        }

        private void Rho(long[] A)
        {
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    int index = x + 5 * y;
                    A[index] = ((_rhoOffsets[index] != 0) ? (((A[index]) << _rhoOffsets[index]) ^ (long)((ulong)(A[index]) >> (64 - _rhoOffsets[index]))) : A[index]);
                }
            }
        }

        private void Theta(long[] A)
        {
            for (int x = 0; x < 5; x++)
            {
                _C[x] = 0;
                for (int y = 0; y < 5; y++)
                {
                    _C[x] ^= A[x + 5 * y];
                }
            }
            for (int x = 0; x < 5; x++)
            {
                long dX = ((((_C[(x + 1) % 5]) << 1) ^ (long)((ulong)(_C[(x + 1) % 5]) >> (64 - 1)))) ^ _C[(x + 4) % 5];
                for (int y = 0; y < 5; y++)
                {
                    A[x + 5 * y] ^= dX;
                }
            }
        }

        private void WordsToBytes(byte[] State, long[] StateWords)
        {
            for (int i = 0; i < (1600 / 64); i++)
            {
                int index = i * (64 / 8);
                for (int j = 0; j < (64 / 8); j++)
                {
                    State[index + j] = (byte)((StateWords[i] >> ((8 * j))) & 0xFF);
                }
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class, releasing the resources
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
                    if (_State != null)
                    {
                        Array.Clear(_State, 0, _State.Length);
                        _State = null;
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

                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
