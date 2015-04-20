#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Mode;
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
// Implementation Details:
// An implementation of the XDC (Xor Digest Cipher) random generator.
// Written by John Underhill, March 24, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// <h3>An implementation of </h3>
    /// </summary>
    /// 
    /// <example>
    /// <code>
    /// int x;
    /// using (IRandom rnd = new XDC())
    ///     x = rnd.Next();
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Xorshift RNGs: <see href="http://www.jstatsoft.org/v08/i14/paper">Description of a class of simple, extremely fast random number generators</see>.</description></item>
    /// <item><description>SHA3 <see href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</see>.</description></item>
    /// <item><description>SHA3: <see href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report of the SHA-3 Cryptographic Hash Algorithm Competition</see>.</description></item>
    /// <item><description>AES Proposal: <see href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael</see>.</description></item>
    /// <item><description>Fips 197: Announcing the <see href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">Advanced Encryption Standard (AES)</see></description></item>
    /// <item><description>TestU01: <see href="http://www.iro.umontreal.ca/~simardr/testu01/guideshorttestu01.pdf">A Software Library in ANSI C for Empirical Testing of Random Number Generators</see></description></item>
    /// </list> 
    /// </remarks>
    public sealed class XDC : IRandom, IDisposable
    {
        #region Constants
        private const string ALG_NAME = "XDC";
        #endregion

        #region Fields
        private bool _isDisposed = false;
        #endregion

        #region Properties
        /// <summary>
        /// Algorithm name
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
        public XDC()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~XDC()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>Random byte array</returns>
        public byte[] GetBytes(int Size)
        {
            return Generate(Size);
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Data">Array to fill with random bytes</param>
        public void GetBytes(byte[] Data)
        {
            Data = Generate(Data.Length);
        }

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public int Next()
        {
            return BitConverter.ToInt32(GetBytes(4), 0);
        }


        /// <summary>
        /// Get a ranged pseudo random 32bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 Next(int Maximum)
        {
            byte[] rand;
            Int32[] num = new Int32[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a ranged pseudo random 32bit integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 Next(int Minimum, int Maximum)
        {
            Int32 num = 0;
            while ((num = Next(Maximum)) < Minimum) { }
            return num;
        }


        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public Int64 NextLong()
        {
            return BitConverter.ToInt64(GetBytes(8), 0);
        }

        /// <summary>
        /// Reset the XDC instance.
        /// </summary>
        public void Reset()
        {
            
        }
        #endregion

        #region Private Methods
        private byte[] GetByteRange(Int64 Maximum)
        {
            byte[] data;

            if (Maximum < 256)
                data = GetBytes(1);
            else if (Maximum < 65536)
                data = GetBytes(2);
            else if (Maximum < 16777216)
                data = GetBytes(3);
            else if (Maximum < 4294967296)
                data = GetBytes(4);
            else if (Maximum < 1099511627776)
                data = GetBytes(5);
            else if (Maximum < 281474976710656)
                data = GetBytes(6);
            else if (Maximum < 72057594037927936)
                data = GetBytes(7);
            else
                data = GetBytes(8);

            return GetBits(data, Maximum);
        }

        private byte[] GetBits(byte[] Data, Int64 Maximum)
        {
            UInt64[] val = new UInt64[1];
            Buffer.BlockCopy(Data, 0, val, 0, Data.Length);
            int bits = Data.Length * 8;

            while (val[0] > (UInt64)Maximum && bits > 0)
            {
                val[0] >>= 1;
                bits--;
            }

            byte[] ret = new byte[Data.Length];
            Buffer.BlockCopy(val, 0, ret, 0, Data.Length);

            return ret;
        }

        private byte[] Entropy()
        {

            return new byte[96];
        }

        private byte[] Generate(int Size)
        {
            byte[] pool = XorShift(Entropy(), 144);
            byte[] hash;

            using (Keccak512 digest = new Keccak512(384))
                hash = digest.ComputeHash(pool);

            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            Buffer.BlockCopy(hash, 0, key, 0, key.Length);
            Buffer.BlockCopy(hash, key.Length, iv, 0, iv.Length);
            byte[] data = new byte[Size];

            using (KeyParams keyparam = new KeyParams(key, iv))
            {
                // 40 rounds of serpent
                using (CTR cipher = new CTR(new SPX(40)))
                {
                    cipher.Initialize(true, keyparam);
                    cipher.Transform(data, data);
                }
            }

            return data;
        }

        private byte[] XorShift(byte[] Seed, int Size)
        {
            int offset = 0;
            long[] X = new long[2];
            long[] S = new long[2];
            byte[] buffer = new byte[Size];

            Buffer.BlockCopy(Seed, 0, S, 0, 16);

            while (offset < Size)
            {
                X[0] = S[0];
                X[1] = S[1];
                S[0] = X[1];
                X[0] ^= X[0] << 23;             // a
                X[0] ^= X[0] >> 17;             // b
                X[0] ^= X[1] ^ (X[1] >> 26);    // c
                S[1] = X[0];
                X[0] += X[1];                   // +

                buffer[offset++] = (byte)(X[0] & 0xFF);
                buffer[offset++] = (byte)((X[0] >> 8) & 0xFF);
                buffer[offset++] = (byte)((X[0] >> 16) & 0xFF);
                buffer[offset++] = (byte)((X[0] >> 24) & 0xFF);
            }

            return buffer;
        }

        private byte[] XorShift2(byte[] Seed, int Size)
        {
            int offset = 0;
            ulong[] X = new ulong[4];
            ulong[] S = new ulong[4];
            byte[] buffer = new byte[Size];

            Buffer.BlockCopy(Seed, 0, S, 0, 32);

            while (offset < Size)
            {
                X[0] = S[0];
                X[1] = S[1];
                S[0] = X[1];
                X[0] ^= X[0] << 23;             // a
                X[0] ^= X[0] >> 17;             // b
                X[0] ^= X[1] ^ (X[1] >> 26);    // c
                S[1] = X[0];
                X[0] += X[1];                   // +
                // next 64
                X[3] = S[3];
                X[4] = S[4];
                S[3] = X[4];
                X[3] ^= X[3] << 23;             // a
                X[3] ^= X[3] >> 17;             // b
                X[3] ^= X[4] ^ (X[4] >> 26);    // c
                S[4] = X[3];
                X[3] += X[4];                   // +

                // copy first
                buffer[offset++] = (byte)(X[0] & 0xFF);
                buffer[offset++] = (byte)((X[0] >> 8) & 0xFF);
                buffer[offset++] = (byte)((X[0] >> 16) & 0xFF);
                buffer[offset++] = (byte)((X[0] >> 24) & 0xFF);
                // copy second
                buffer[offset++] = (byte)(X[3] & 0xFF);
                buffer[offset++] = (byte)((X[3] >> 8) & 0xFF);
                buffer[offset++] = (byte)((X[3] >> 16) & 0xFF);
                buffer[offset++] = (byte)((X[3] >> 24) & 0xFF);
            }

            return buffer;
        }

        // variable seed size.. test
        private byte[] XorShift3(byte[] Seed, int Size)
        {
            int offset = 0;
            int stateLen = Seed.Length / 8;
            ulong[] X = new ulong[stateLen];
            ulong[] S = new ulong[stateLen];
            byte[] buffer = new byte[Size];

            Buffer.BlockCopy(Seed, 0, S, 0, stateLen * 8);

            while (offset < Size)
            {
                for (int i = 0; i < stateLen - 1; i += 2)
                {
                    X[i] = S[i];
                    X[i + 1] = S[i + 1];
                    S[i] = X[i + 1];
                    X[i] ^= X[i] << 23;                     // a
                    X[i] ^= X[i] >> 17;                     // b
                    X[i] ^= X[i + 1] ^ (X[i + 1] >> 26);    // c
                    S[1] = X[i];
                    X[i] += X[i + 1];                       // +

                    buffer[offset++] = (byte)(X[i] & 0xFF);
                    buffer[offset++] = (byte)((X[i] >> 8) & 0xFF);
                    buffer[offset++] = (byte)((X[i] >> 16) & 0xFF);
                    buffer[offset++] = (byte)((X[i] >> 24) & 0xFF);
                }
            }

            return buffer;
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
                    /*if (_rngCrypto != null)
                    {
                        _rngCrypto.Dispose();
                        _rngCrypto = null;
                    }*/
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
/*
The current process ID (GetCurrentProcessID). 

The current thread ID (GetCurrentThreadID). 

The ticks since boot (GetTickCount). 

The current time (GetLocalTime). 

Various high-precision performance counters (QueryPerformanceCounter). 

An MD4 hash of the user's environment block, which includes username, computer name, and search path. MD4 is a hashing algorithm that creates a 128-bit message digest from input data to verify data integrity. 

High-precision internal CPU counters, such as RDTSC, RDMSR, RDPMC 

Low-level system information: Idle Process Time, Io Read Transfer Count, I/O Write Transfer Count, I/O Other Transfer Count, I/O Read Operation Count, I/O Write Operation Count, I/O Other Operation Count, Available Pages, Committed Pages, Commit Limit, Peak Commitment, Page Fault Count, Copy On Write Count, Transition Count, Cache Transition Count, Demand Zero Count, Page Read Count, Page Read I/O Count, Cache Read Count, Cache I/O Count, Dirty Pages Write Count, Dirty Write I/O Count, Mapped Pages Write Count, Mapped Write I/O Count, Paged Pool Pages, Non Paged Pool Pages, Paged Pool Allocated space, Paged Pool Free space, Non Paged Pool Allocated space, Non Paged Pool Free space, Free System page table entry, Resident System Code Page, Total System Driver Pages, Total System Code Pages, Non Paged Pool Lookaside Hits, Paged Pool Lookaside Hits, Available Paged Pool Pages, Resident System Cache Page, Resident Paged Pool Page, Resident System Driver Page, Cache manager Fast Read with No Wait, Cache manager Fast Read with Wait, Cache manager Fast Read Resource Missed, Cache manager Fast Read Not Possible, Cache manager Fast Memory Descriptor List Read with No Wait, Cache manager Fast Memory Descriptor List Read with Wait, Cache manager Fast Memory Descriptor List Read Resource Missed, Cache manager Fast Memory Descriptor List Read Not Possible, Cache manager Map Data with No Wait, Cache manager Map Data with Wait, Cache manager Map Data with No Wait Miss, Cache manager Map Data Wait Miss, Cache manager Pin-Mapped Data Count, Cache manager Pin-Read with No Wait, Cache manager Pin Read with Wait, Cache manager Pin-Read with No Wait Miss, Cache manager Pin-Read Wait Miss, Cache manager Copy-Read with No Wait, Cache manager Copy-Read with Wait, Cache manager Copy-Read with No Wait Miss, Cache manager Copy-Read with Wait Miss, Cache manager Memory Descriptor List Read with No Wait, Cache manager Memory Descriptor List Read with Wait, Cache manager Memory Descriptor List Read with No Wait Miss, Cache manager Memory Descriptor List Read with Wait Miss, Cache manager Read Ahead IOs, Cache manager Lazy-Write IOs, Cache manager Lazy-Write Pages, Cache manager Data Flushes, Cache manager Data Pages, Context Switches, First Level Translation buffer Fills, Second Level Translation buffer Fills, and System Calls. 

System exception information consisting of Alignment Fix up Count, Exception Dispatch Count, Floating Emulation Count, and Byte Word Emulation Count. 

System lookaside information consisting of Current Depth, Maximum Depth, Total Allocates, Allocate Misses, Total Frees, Free Misses, Type, Tag, and Size. 

System interrupt information consisting of context switches, deferred procedure call count, deferred procedure call rate, time increment, deferred procedure call bypass count, and asynchronous procedure call bypass count. 

System process information consisting of Next Entry Offset, Number Of Threads, Create Time, User Time, Kernel Time, Image Name, Base Priority, Unique Process ID, Inherited from Unique Process ID, Handle Count, Session ID, Page Directory Base, Peak Virtual Size, Virtual Size, Page Fault Count, Peak Working Set Size, Working Set Size, Quota Peak Paged Pool Usage, Quota Paged Pool Usage, Quota Peak Non Paged Pool Usage, Quota Non Paged Pool Usage, Page file Usage, Peak Page file Usage, Private Page Count, Read Operation Count, Write Operation Count, Other Operation Count, Read Transfer Count, Write Transfer Count, and Other Transfer Count. 
*/