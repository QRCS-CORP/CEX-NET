#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Numeric;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
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
// An implementation of the Modular Exponentiation Generator random number generator: MODEXPG
// Written by John Underhill, January 09, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// An implementation of the Modular Exponentiation Generator random number generator
    /// </summary>
    /// 
    /// <example>
    /// <code>
    /// int x;
    /// using (IRandom rnd = new MODEXPG())
    ///     x = rnd.Next();
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>, Section D.6: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
    /// </list> 
    /// 
    /// <description>Code Base Guides:</description>
    /// <list type="table">
    /// <item><description>This code based on the excellent Java version by Zur Aougav: <a href="http://sourceforge.net/projects/jrandtest/">ModulusExponentPrng</a> class.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MODEXPG : IRandom
    {
        #region Constants
        private const string ALG_NAME = "MODEXPG";
        private const int Y_BITS = 160;
        private const int G_BITS = 512;
        private const int LONG_SIZE = 8;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private SecureRandom _secRand;
        private BigInteger _G;
        private BigInteger _G0;
        private BigInteger _P;
        private BigInteger _Y;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The prngs type name
        /// </summary>
        public Prngs Enumeral
        {
            get { return Prngs.MODEXPG; }
        }

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
        public MODEXPG()
        {
            _secRand = new SecureRandom();

            Initialize(G_BITS);
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="BitLength">Length of integers used in equations, must be at least 512 bits</param>
        public MODEXPG(int BitLength)
        {
            _secRand = new SecureRandom();

            if (BitLength < G_BITS)
                Initialize(G_BITS);
            else
                Initialize(BitLength);
        }

        /// <summary>
        /// Initialize class with Prime and State Seed values. Values must be probable primes.
        /// </summary>
        /// 
        /// <param name="P">Random Prime</param>
        /// <param name="G">Random Generator State</param>
        /// <param name="Y">Random Generator Seed</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if P is not a valid prime</exception>
        public MODEXPG(BigInteger P, BigInteger G, BigInteger Y)
        {
            if (!P.IsProbablePrime(90))
                throw new CryptoRandomException("MODEXPG:Ctor", "P is not a valid prime number!", new ArgumentOutOfRangeException());

            _secRand = new SecureRandom();

            _P = P;
            _G = G;
            _Y = Y;
            _G0 = G;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MODEXPG()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Array to fill with random bytes</param>
        public void GetBytes(byte[] Output)
        {
            int reqSize = Output.Length;
            int algSize = (reqSize % LONG_SIZE == 0 ? reqSize : reqSize + LONG_SIZE - (reqSize % LONG_SIZE));
            int lstBlock = algSize - LONG_SIZE;
            Int64[] rndNum = new Int64[1];

            for (int i = 0; i < algSize; i += LONG_SIZE)
            {
                // get 8 bytes
                rndNum[0] = NextLong();

                // copy to output
                if (i != lstBlock)
                {
                    // copy in the int bytes
                    Buffer.BlockCopy(rndNum, 0, Output, i, LONG_SIZE);
                }
                else
                {
                    // final copy
                    int fnlSize = (reqSize % LONG_SIZE) == 0 ? LONG_SIZE : (reqSize % LONG_SIZE);
                    Buffer.BlockCopy(rndNum, 0, Output, i, fnlSize);
                }
            }
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>Random byte array</returns>
        public byte[] GetBytes(int Size)
        {
            byte[] data = new byte[Size];

            GetBytes(data);

            return data;
        }

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 Next()
        {
            // Xi+1 = (G pow Y) mod P
            _G = _G.ModPow(_Y, _P);

            // set G to 2 if G <= 1.
            if (_G.CompareTo(BigInteger.One) < 1)
                _G = BigInteger.ValueOf(2);

            return _G.ToInt32();
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
        /// Get a pseudo random 64bit integer
        /// </summary>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextLong()
        {
            // Xi+1 = (G pow seed) mod P
            _G = _G.ModPow(_Y, _P);

            // set G to 2 if G < 1
            if (_G.CompareTo(BigInteger.One) < 1)
                _G = BigInteger.ValueOf(2);

            return _G.ToInt64();
        }

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextLong(long Maximum)
        {
            byte[] rand;
            Int64[] num = new Int64[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Minimum">Minimum value</param>
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextLong(long Minimum, long Maximum)
        {
            Int64 num = 0;
            while ((num = NextLong(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Sets or resets the internal state
        /// </summary>
        public void Reset()
        {
            _G = _G0;
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

        private void Initialize(int BitLength)
        {
            _P = BigInteger.ProbablePrime(BitLength, _secRand);
            _G = BigInteger.ProbablePrime(BitLength, _secRand);
            _Y = BigInteger.ProbablePrime(Y_BITS, _secRand);

            // if g >= p swap(g, p).
            if (_G.CompareTo(_P) > -1)
            {
                BigInteger temp = _G;
                _G = _P;
                _P = temp;
            }

            _G0 = _G;
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
                    if (_secRand != null)
                    {
                        _secRand.Dispose();
                        _secRand = null;
                    }
                    if (_Y != null)
                        _Y = null;
                    if (_G != null)
                        _G = null;
                    if (_G0 != null)
                        _G0 = null;
                    if (_P != null)
                        _P = null;
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
