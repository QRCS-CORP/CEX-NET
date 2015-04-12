﻿#region Directives
using System;
using System.Security.Cryptography;
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
// An implementation of a Cryptographically Secure Psuedo Random Number Generator (SecureRandom). 
// Uses the <see href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</see> class to produce pseudo random output.
// Written by John Underhill, January 6, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// <h3>An implementation of a Cryptographically Secure Psuedo Random Number Generator: SecureRandom.</h3> 
    /// 
    /// <para>Uses the RNGCryptoServiceProvider<cite>RNGCryptoServiceProvider</cite> class to generate non-negative random numbers.</para>
    /// </summary>
    /// 
    /// <example>
    /// <code>
    /// int x;
    /// using (SecureRandom rnd = new SecureRandom())
    ///     x = rnd.NextInt32();
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    ///     <revision date="2015/01/23" version="1.3.0.0" author="John Underhill">Initial release</revision>
    /// </revisionHistory>
    public sealed class SecureRandom : IDisposable
    {
        #region Constants
        private const UInt16 MAXD16 = 16368;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private RNGCryptoServiceProvider _rngCrypto;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        public SecureRandom()
        {
            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SecureRandom()
        {
            Dispose(false);
        }
        #endregion

        #region Reset
        /// <summary>
        /// Reset the RNGCryptoServiceProvider instance.
        /// </summary>
        public void Reset()
        {
            if (_rngCrypto != null)
            {
                _rngCrypto.Dispose();
                _rngCrypto = null;
            }

            _rngCrypto = new RNGCryptoServiceProvider();
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Algorithm Name
        /// </summary>
        public string Name
        {
            get { return "SecureRandom"; }
        }
        #endregion

        #region Char
        /// <summary>
        /// Get a random char
        /// </summary>
        /// 
        /// <returns>Random char</returns>
        public char NextChar()
        {
            return BitConverter.ToChar(GetBytes(2), 0);
        }
        #endregion

        #region Double
        /// <summary>
        /// Get a non-ranged random double
        /// </summary>
        /// 
        /// <returns>Random double</returns>
        public double AnyDouble()
        {
            return BitConverter.ToDouble(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a random double in the range 0.0 to 1.0
        /// </summary>
        /// 
        /// <returns>Random double</returns>
        public double NextDouble()
        {
            double[] num = new double[1];
            UInt16[] mnv = new UInt16[1];

            mnv[0] = NextUInt16(MAXD16);
            Buffer.BlockCopy(mnv, 0, num, 6, 2);

            return num[0];
        }
        #endregion

        #region Int16
        /// <summary>
        /// Get a random non-negative short integer
        /// </summary>
        /// 
        /// <returns>Random Int16</returns>
        public Int16 NextInt16()
        {
            return BitConverter.ToInt16(GetBytes(2), 0);
        }

        /// <summary>
        /// Get a random non-negative short integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// <returns>Random Int16</returns>
        public Int16 NextInt16(Int16 Maximum)
        {
            byte[] rand;
            Int16[] num = new Int16[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            if (num[0] == -1) 
                num[0] = 0;

            return num[0];
        }

        /// <summary>
        /// Get a random non-negative short integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// <param name="Minimum">Minimum value</param>
        /// 
        /// <returns>Random Int16</returns>
        public Int16 NextInt16(Int16 Maximum, Int16 Minimum)
        {
            Int16 num = 0;
            while ((num = NextInt16(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region UInt16
        /// <summary>
        /// Get a random unsigned short integer
        /// </summary>
        /// 
        /// <returns>Random UInt16</returns>
        [CLSCompliant(false)]
        public UInt16 NextUInt16()
        {
            return BitConverter.ToUInt16(GetBytes(2), 0);
        }

        /// <summary>
        /// Get a random unsigned short integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random UInt16</returns>
        [CLSCompliant(false)]
        public UInt16 NextUInt16(UInt16 Maximum)
        {
            byte[] rand;
            UInt16[] num = new UInt16[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a random unsigned short integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// <param name="Minimum">Minimum value</param>
        /// 
        /// <returns>Random UInt32</returns>
        [CLSCompliant(false)]
        public UInt16 NextUInt16(UInt16 Maximum, UInt16 Minimum)
        {
            UInt16 num = 0;
            while ((num = NextUInt16(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region Int32
        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 Next()
        {
            return BitConverter.ToInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 NextInt32()
        {
            return BitConverter.ToInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 NextInt32(Int32 Maximum)
        {
            byte[] rand;
            Int32[] num = new Int32[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            if (num[0] == -1)
                num[0] = 0;

            return num[0];
        }

        /// <summary>
        /// Get a random non-negative 32bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// <param name="Minimum">Minimum value</param>
        /// 
        /// <returns>Random Int32</returns>
        public Int32 NextInt32(Int32 Maximum, Int32 Minimum)
        {
            Int32 num = 0;
            while ((num = NextInt32(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region UInt32
        /// <summary>
        /// Get a random unsigned 32bit integer
        /// </summary>
        /// 
        /// <returns>Random UInt32</returns>
        [CLSCompliant(false)]
        public UInt32 NextUInt32()
        {
            return BitConverter.ToUInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a random unsigned integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random UInt32</returns>
        [CLSCompliant(false)]
        public UInt32 NextUInt32(UInt32 Maximum)
        {
            byte[] rand;
            UInt32[] num = new UInt32[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a random unsigned integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// <param name="Minimum">Minimum value</param>
        /// 
        /// <returns>Random UInt32</returns>
        [CLSCompliant(false)]
        public UInt32 NextUInt32(UInt32 Maximum, UInt32 Minimum)
        {
            UInt32 num = 0;
            while ((num = NextUInt32(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region Int64
        /// <summary>
        /// Get a random long integer
        /// </summary>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextInt64()
        {
            return BitConverter.ToInt64(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a random long integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextInt64(Int64 Maximum)
        {
            byte[] rand;
            Int64[] num = new Int64[1];

            do
            {
                rand = GetByteRange((Int64)Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            if (num[0] == -1)
                num[0] = 0;

            return num[0];
        }

        /// <summary>
        /// Get a random long integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// <param name="Minimum">Minimum value</param>
        /// 
        /// <returns>Random Int64</returns>
        public Int64 NextInt64(Int64 Maximum, Int64 Minimum)
        {
            Int64 num = 0;
            while ((num = NextInt64(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region UInt64
        /// <summary>
        /// Get a random unsigned long integer
        /// </summary>
        /// 
        /// <returns>Random UInt64</returns>
        [CLSCompliant(false)]
        public UInt64 NextUInt64()
        {
            return BitConverter.ToUInt64(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a random unsigned long integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random UInt64</returns>
        [CLSCompliant(false)]
        public UInt64 NextUInt64(UInt64 Maximum)
        {
            byte[] rand = GetByteRange((Int64)Maximum);
            UInt64[] num = new UInt64[1];

            do
            {
                rand = GetByteRange((Int64)Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            return num[0];
        }

        /// <summary>
        /// Get a random unsigned long integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// <param name="Minimum">Minimum value</param>
        /// 
        /// <returns>Random UInt64</returns>
        [CLSCompliant(false)]
        public UInt64 NextUInt64(UInt64 Maximum, UInt64 Minimum)
        {
            UInt64 num = 0;
            while ((num = NextUInt64(Maximum)) < Minimum) { }
            return num;
        }
        #endregion

        #region Array Generators
        /// <summary>
        /// Gets bytes pseudo random from RNGCryptoServiceProvider
        /// </summary>
        /// 
        /// <param name="Size">Size of request</param>
        /// 
        /// <returns>P-Rand bytes</returns>
        public byte[] GetBytes(int Size)
        {
            byte[] data = new byte[Size];
            _rngCrypto.GetBytes(data);
            return data;
        }

        /// <summary>
        /// Gets bytes pseudo random from RNGCryptoServiceProvider
        /// </summary>
        /// 
        /// <param name="Data">Array to fill with pseudo random</param>
        public void GetBytes(byte[] Data)
        {
            _rngCrypto.GetBytes(Data);
        }

        /// <summary>
        /// Gets pseudo random chars
        /// </summary>
        /// 
        /// <param name="Size">Size of request</param>
        /// 
        /// <returns>P-Rand chars</returns>
        public char[] GetChars(int Size)
        {
            char[] data = new char[Size];
            Buffer.BlockCopy(GetBytes(Size * 2), 0, data, 0, Size);
            return data;
        }
        #endregion

        #region Private Methods
        /// <remarks>
        /// returns the number of bytes needed to build 
        /// an integer existing within a byte range
        /// </remarks>
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

        /// <remarks>
        /// If you need a dice roll, use the Random class (smaller range = reduced entropy)
        /// </remarks>
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
                    if (_rngCrypto != null)
                    {
                        _rngCrypto.Dispose();
                        _rngCrypto = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}