#region Directives
using System;
using System.Collections;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
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
// Code Base Guides:
// Based on the Bouncy Castle C# <see href="http://bouncycastle.org/latest_releases.html">Release 1.7</see> BigInteger class, 
// and Open JDK <see href="http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/8-b132/java/math/BigInteger.java#BigInteger">BigInteger.java</see>.
// 
// Implementation Details:
// An implementation of a BigInteger class. 
// Written by John Underhill, November 21, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Numeric
{
    /// <summary>
    /// BigInteger: Provides BigInteger operations for modular arithmetic, GCD calculation, primality testing, prime generation, bit manipulation, and other miscellaneous operations
    /// </summary>
    /// 
    /// <example>
    /// <description>Creating a random prime example:</description>
    /// <code>
    /// BigInteger P = BigInteger.ProbablePrime(BitLength, new SecureRandom());
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    ///     <revision date="2015/01/23" version="1.3.0.0" author="John Underhill">Initial release</revision>
    /// </revisionHistory>
    public class BigInteger
    {
        #region Constants
        private const long IMASK = 0xffffffffL;
        private const int BitsPerByte = 8;
        private const int BitsPerInt = 32;
        private const int BytesPerInt = 4;
        #endregion


        #region Constant Fields
        /// <summary>
        /// The BigInteger constant zero
        /// </summary>
        public static BigInteger Zero = new BigInteger(0, new int[1], false);

        /// <summary>
        /// The BigInteger constant one
        /// </summary>
        public static BigInteger One = CreateUValueOf(1);

        /// <summary>
        /// The BigInteger constant two
        /// </summary>
        public static BigInteger Two = CreateUValueOf(2);

        /// <summary>
        /// The BigInteger constant three
        /// </summary>
        public static BigInteger Three = CreateUValueOf(3);

        /// <summary>
        /// The BigInteger constant four
        /// </summary>
        public static BigInteger Four = CreateUValueOf(4);

        /// <summary>
        /// The BigInteger constant ten
        /// </summary>
        public static BigInteger Ten = CreateUValueOf(10);
        #endregion


        #region Fields
        private readonly static byte[] _bitCounts =
		{
			0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1,
			2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4,
			4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3,
			4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5,
			3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2,
			3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3,
			3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6,
			7, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6,
			5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5,
			6, 6, 7, 6, 7, 7, 8
		};

        private static int BitLen(int W)
        {
            // Binary search - decision tree (5 tests, rarely 6)
            return (W < 1 << 15 ? (W < 1 << 7
                ? (W < 1 << 3 ? (W < 1 << 1
                ? (W < 1 << 0 ? (W < 0 ? 32 : 0) : 1)
                : (W < 1 << 2 ? 2 : 3)) : (W < 1 << 5
                ? (W < 1 << 4 ? 4 : 5)
                : (W < 1 << 6 ? 6 : 7)))
                : (W < 1 << 11
                ? (W < 1 << 9 ? (W < 1 << 8 ? 8 : 9) : (W < 1 << 10 ? 10 : 11))
                : (W < 1 << 13 ? (W < 1 << 12 ? 12 : 13) : (W < 1 << 14 ? 14 : 15)))) : (W < 1 << 23 ? (W < 1 << 19
                ? (W < 1 << 17 ? (W < 1 << 16 ? 16 : 17) : (W < 1 << 18 ? 18 : 19))
                : (W < 1 << 21 ? (W < 1 << 20 ? 20 : 21) : (W < 1 << 22 ? 22 : 23))) : (W < 1 << 27
                ? (W < 1 << 25 ? (W < 1 << 24 ? 24 : 25) : (W < 1 << 26 ? 26 : 27))
                : (W < 1 << 29 ? (W < 1 << 28 ? 28 : 29) : (W < 1 << 30 ? 30 : 31)))));
        }

        /// <remarks>
        /// Each list has a product 2^31
        /// </remarks>
        private static readonly int[][] _primeLists = new int[][]
		{
			new int[]{ 3, 5, 7, 11, 13, 17, 19, 23 },
			new int[]{ 29, 31, 37, 41, 43 },
			new int[]{ 47, 53, 59, 61, 67 },
			new int[]{ 71, 73, 79, 83 },
			new int[]{ 89, 97, 101, 103 },
			new int[]{ 107, 109, 113, 127 },
			new int[]{ 131, 137, 139, 149 },
			new int[]{ 151, 157, 163, 167 },
			new int[]{ 173, 179, 181, 191 },
			new int[]{ 193, 197, 199, 211 },
			new int[]{ 223, 227, 229 },
			new int[]{ 233, 239, 241 },
			new int[]{ 251, 257, 263 },
			new int[]{ 269, 271, 277 },
			new int[]{ 281, 283, 293 },
			new int[]{ 307, 311, 313 },
			new int[]{ 317, 331, 337 },
			new int[]{ 347, 349, 353 },
			new int[]{ 359, 367, 373 },
			new int[]{ 379, 383, 389 },
			new int[]{ 397, 401, 409 },
			new int[]{ 419, 421, 431 },
			new int[]{ 433, 439, 443 },
			new int[]{ 449, 457, 461 },
			new int[]{ 463, 467, 479 },
			new int[]{ 487, 491, 499 },
			new int[]{ 503, 509, 521 },
			new int[]{ 523, 541, 547 },
			new int[]{ 557, 563, 569 },
			new int[]{ 571, 577, 587 },
			new int[]{ 593, 599, 601 },
			new int[]{ 607, 613, 617 },
			new int[]{ 619, 631, 641 },
			new int[]{ 643, 647, 653 },
			new int[]{ 659, 661, 673 },
			new int[]{ 677, 683, 691 },
			new int[]{ 701, 709, 719 },
			new int[]{ 727, 733, 739 },
			new int[]{ 743, 751, 757 },
			new int[]{ 761, 769, 773 },
			new int[]{ 787, 797, 809 },
			new int[]{ 811, 821, 823 },
			new int[]{ 827, 829, 839 },
			new int[]{ 853, 857, 859 },
			new int[]{ 863, 877, 881 },
			new int[]{ 883, 887, 907 },
			new int[]{ 911, 919, 929 },
			new int[]{ 937, 941, 947 },
			new int[]{ 953, 967, 971 },
			new int[]{ 977, 983, 991 },
			new int[]{ 997, 1009, 1013 },
			new int[]{ 1019, 1021, 1031 },
		};

        private static readonly ulong UIMASK = (ulong)IMASK;
        private static readonly int _chunk2 = 1;
        private static readonly int _chunk10 = 19;
        private static readonly int _chunk16 = 16;
        private int[] _magnitude;
        private long _mQuote = -1L;
        private int _nBits = -1;
        private int _nBitLength = -1;
        private static readonly int[] _primeProducts;
        private static readonly BigInteger _radix2 = ValueOf(2);
        private static readonly BigInteger _radix2E = _radix2.Pow(_chunk2);
        private static readonly BigInteger _radix10 = ValueOf(10);
        private static readonly BigInteger _radix10E = _radix10.Pow(_chunk10);
        private static readonly BigInteger _radix16 = ValueOf(16);
        private static readonly BigInteger _radix16E = _radix16.Pow(_chunk16);
        private static readonly byte[] _randomMask = { 255, 127, 63, 31, 15, 7, 3, 1 };
        private static readonly SecureRandom _randomSource = new SecureRandom();
        private int _signum;
        private static readonly int[] _zeroMagnitude = new int[0];
        private static readonly byte[] _zeroEncoding = new byte[0];
        #endregion

        #region Properties
        /// <summary>
        /// Number of bits in the two's complement representation of this BigInteger that differ from its sign bit
        /// </summary>
        public int BitCount
        {
            get
            {
                if (_nBits == -1)
                {
                    if (_signum < 0)
                    {
                        _nBits = Not().BitCount;
                    }
                    else
                    {
                        int sum = 0;
                        for (int i = 0; i < _magnitude.Length; i++)
                        {
                            sum += _bitCounts[(byte)_magnitude[i]];
                            sum += _bitCounts[(byte)(_magnitude[i] >> 8)];
                            sum += _bitCounts[(byte)(_magnitude[i] >> 16)];
                            sum += _bitCounts[(byte)(_magnitude[i] >> 24)];
                        }
                        _nBits = sum;
                    }
                }

                return _nBits;
            }
        }

        /// <summary>
        /// Number of bits in the minimal two's-complement representation of this BigInteger, excluding a sign bit
        /// </summary>
        public int BitLength
        {
            get
            {
                if (_nBitLength == -1)
                    _nBitLength = _signum == 0 ? 0 : CalcBitLength(0, _magnitude);

                return _nBitLength;
            }
        }

        /// <summary>
        /// <para>Converts this BigInteger to an int. 
        /// If this BigInteger is too big to fit in an int, only the low-order 32 bits are returned. 
        /// Note that this conversion can lose information about the overall magnitude of the BigInteger value as well as return a result with the opposite sign.</para>
        /// </summary>
        public int IntValue
        {
            get
            {
                return _signum == 0 ? 0 : _signum > 0 ? _magnitude[_magnitude.Length - 1] : -_magnitude[_magnitude.Length - 1];
            }
        }

        /// <summary>
        /// <para>Converts this BigInteger to a long. 
        /// If this BigInteger is too big to fit in a long, only the low-order 64 bits are returned. 
        /// Note that this conversion can lose information about the overall magnitude of the BigInteger value as well as return a result with the opposite sign.</para>
        /// </summary>
        public long LongValue
        {
            get
            {
                if (_signum == 0)
                    return 0;

                long v;

                if (_magnitude.Length > 1)
                    v = ((long)_magnitude[_magnitude.Length - 2] << 32) | (_magnitude[_magnitude.Length - 1] & IMASK);
                else
                    v = (_magnitude[_magnitude.Length - 1] & IMASK);

                return _signum < 0 ? -v : v;
            }
        }

        /// <summary>
        /// The sign value
        /// </summary>
        public int SignValue
        {
            get { return _signum; }
        }
        #endregion

        #region Constructor
        /// <remarks>
        /// Static constructor
        /// </remarks>
        static BigInteger()
        {
            _primeProducts = new int[_primeLists.Length];

            for (int i = 0; i < _primeLists.Length; ++i)
            {
                int[] primeList = _primeLists[i];
                int product = 1;

                for (int j = 0; j < primeList.Length; ++j)
                    product *= primeList[j];
                
                _primeProducts[i] = product;
            }
        }

        /// <summary>
        /// <para>Translates a byte array containing the two's-complement binary representation of a BigInteger into a BigInteger. 
        /// The input array is assumed to be in big-endian byte-order: the most significant byte is in the zeroth element.</para>
        /// </summary>
        /// <param name="Value">big-endian two's-complement binary representation of BigInteger</param>
        public BigInteger(byte[] Value) 
            : this(Value, 0, Value.Length)
        {
        }

        /// <summary>
        /// <para>Translates a byte array containing the two's-complement binary representation of a BigInteger into a BigInteger. 
        /// The input array is assumed to be in big-endian byte-order: the most significant byte is in the zeroth element.</para>
        /// </summary>
        /// <param name="Value">big-endian two's-complement binary representation of BigInteger</param>
        /// <param name="Offset">Byte offset within Value</param>
        /// <param name="Length">Byte length of Value</param>
        public BigInteger(byte[] Value, int Offset, int Length)
        {
            if (Length == 0)
                throw new FormatException("Zero length BigInteger");

            // TODO Move this processing into MakeMagnitude (provide sign argument)
            if ((sbyte)Value[Offset] < 0)
            {
                _signum = -1;
                int end = Offset + Length;

                int iBval;
                // strip leading sign bytes
                for (iBval = Offset; iBval < end && ((sbyte)Value[iBval] == -1); iBval++) { }

                if (iBval >= end)
                {
                    _magnitude = One._magnitude;
                }
                else
                {
                    int numBytes = end - iBval;
                    byte[] inverse = new byte[numBytes];
                    int index = 0;

                    while (index < numBytes)
                        inverse[index++] = (byte)~Value[iBval++];

                    Debug.Assert(iBval == end);

                    while (inverse[--index] == byte.MaxValue)
                        inverse[index] = byte.MinValue;

                    inverse[index]++;

                    _magnitude = MakeMagnitude(inverse, 0, inverse.Length);
                }
            }
            else
            {
                // strip leading zero bytes and return magnitude bytes
                _magnitude = MakeMagnitude(Value, Offset, Length);
                _signum = _magnitude.Length > 0 ? 1 : 0;
            }
        }

        /// <summary>
        /// <para>Translates the decimal String representation of a BigInteger into a BigInteger. 
        /// The String representation consists of an optional minus sign followed by a sequence of one or more decimal digits. 
        /// The character-to-digit mapping is provided by Character.digit. 
        /// The String may not contain any extraneous characters (whitespace, for example).</para>
        /// </summary>
        /// <param name="Value">Decimal String representation of BigInteger</param>
        public BigInteger(string Value) 
            : this(Value, 10)
        {
        }

        /// <summary>
        /// <para>Translates the String representation of a BigInteger in the specified radix into a BigInteger. 
        /// The String representation consists of an optional minus or plus sign followed by a sequence of one or more digits in the specified radix. 
        /// The character-to-digit mapping is provided by Character.digit. The String may not contain any extraneous characters (whitespace, for example).</para>
        /// </summary>
        /// <param name="Value">String representation of BigInteger</param>
        /// <param name="Radix">Radix to be used in interpreting Value</param>
        /// 
        /// <exception cref="System.FormatException">Thrown if a Zero length BigInteger  is used</exception>
        public BigInteger(string Value, int Radix)
        {
            if (Value.Length == 0)
                throw new FormatException("Zero length BigInteger");

            NumberStyles style;
            int chunk;
            BigInteger r;
            BigInteger rE;

            switch (Radix)
            {
                case 2:
                    // Is there anyway to restrict to binary digits?
                    style = NumberStyles.Integer;
                    chunk = _chunk2;
                    r = _radix2;
                    rE = _radix2E;
                    break;
                case 10:
                    // This style seems to handle spaces and minus sign already (our processing redundant?)
                    style = NumberStyles.Integer;
                    chunk = _chunk10;
                    r = _radix10;
                    rE = _radix10E;
                    break;
                case 16:
                    style = NumberStyles.AllowHexSpecifier;
                    chunk = _chunk16;
                    r = _radix16;
                    rE = _radix16E;
                    break;
                default:
                    throw new FormatException("Only bases 2, 10, or 16 allowed");
            }


            int index = 0;
            _signum = 1;

            if (Value[0] == '-')
            {
                if (Value.Length == 1)
                    throw new FormatException("Zero length BigInteger");

                _signum = -1;
                index = 1;
            }

            // strip leading zeros from the string str
            while (index < Value.Length && Int32.Parse(Value[index].ToString(), style) == 0)
                index++;

            if (index >= Value.Length)
            {
                // zero value - we're done
                _signum = 0;
                _magnitude = _zeroMagnitude;
                return;
            }

            // could we work out the max number of ints required to store
            // str.Length digits in the given base, then allocate that
            // storage in one hit?, then Generate the magnitude in one hit too?

            BigInteger b = Zero;
            int next = index + chunk;

            if (next <= Value.Length)
            {
                do
                {
                    string s = Value.Substring(index, chunk);
                    ulong i = ulong.Parse(s, style);
                    BigInteger bi = CreateUValueOf(i);

                    switch (Radix)
                    {
                        case 2:
                            if (i > 1)
                                throw new FormatException("Bad character in radix 2 string: " + s);

                            b = b.ShiftLeft(1);
                            break;
                        case 16:
                            b = b.ShiftLeft(64);
                            break;
                        default:
                            b = b.Multiply(rE);
                            break;
                    }

                    b = b.Add(bi);

                    index = next;
                    next += chunk;
                }
                while (next <= Value.Length);
            }

            if (index < Value.Length)
            {
                string s = Value.Substring(index);
                ulong i = ulong.Parse(s, style);
                BigInteger bi = CreateUValueOf(i);

                if (b._signum > 0)
                {
                    if (Radix == 2) // NB: Can't reach here since we are parsing one char at a time
                        Debug.Assert(false);
                    else if (Radix == 16)
                        b = b.ShiftLeft(s.Length << 2);
                    else
                        b = b.Multiply(r.Pow(s.Length));

                    b = b.Add(bi);
                }
                else
                {
                    b = bi;
                }
            }

            _magnitude = b._magnitude;
        }

        /// <summary>
        /// <para>Constructs a randomly generated BigInteger, uniformly distributed over the range 0 to (2numBits - 1), inclusive. 
        /// The uniformity of the distribution assumes that a fair source of SecureRandom bits is provided in rnd. 
        /// Note that this constructor always constructs a non-negative BigInteger.</para>
        /// </summary>
        /// <param name="BitLength">Maximum bitLength of the new BigInteger</param>
        /// <param name="Rnd">Source of randomness to be used in computing the new BigInteger</param>
        /// 
        /// <exception cref="System.ArgumentException">Thrown if a negative BitLength  is used</exception>
        public BigInteger(int BitLength, SecureRandom Rnd)
        {
            if (BitLength < 0)
                throw new ArgumentException("sizeInBits must be non-negative");

            _nBits = -1;
            _nBitLength = -1;

            if (BitLength == 0)
            {
                _magnitude = _zeroMagnitude;
                return;
            }

            int nBytes = GetByteLength(BitLength);
            byte[] b = new byte[nBytes];
            Rnd.GetBytes(b);

            // strip off any excess bits in the MSB
            b[0] &= _randomMask[BitsPerByte * nBytes - BitLength];

            _magnitude = MakeMagnitude(b, 0, b.Length);
            _signum = _magnitude.Length < 1 ? 0 : 1;
        }

        /// <summary>
        /// <para>Constructs a randomly generated positive BigInteger that is probably prime, with the specified bitLength. 
        /// It is recommended that the ProbablePrime method be used in preference to this constructor unless there is a compelling need to specify a certainty.</para>
        /// </summary>
        /// <param name="BitLength">BitLength of the returned BigInteger</param>
        /// <param name="Certainty"><para>A measure of the uncertainty that the caller is willing to tolerate. 
        /// The probability that the new BigInteger represents a prime number will exceed (1 - 1/2certainty). 
        /// The execution time of this constructor is proportional to the value of this parameter.</para></param>
        /// <param name="Rnd">Source of SecureRandom bits used to select candidates to be tested for primality</param>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if a BitLength of less than 2  is used</exception>
        public BigInteger(int BitLength, int Certainty, SecureRandom Rnd)
        {
            if (BitLength < 2)
                throw new ArithmeticException("bitLength < 2");

            _signum = 1;
            _nBitLength = BitLength;

            if (BitLength == 2)
            {
                _magnitude = Rnd.NextInt32(2) == 0 ? Two._magnitude : Three._magnitude;
                return;
            }

            int nBytes = GetByteLength(BitLength);
            byte[] b = new byte[nBytes];
            int xBits = BitsPerByte * nBytes - BitLength;
            byte mask = _randomMask[xBits];

            do
            {
                Rnd.GetBytes(b);
                // strip off any excess bits in the MSB
                b[0] &= mask;
                // ensure the leading bit is 1 (to meet the strength requirement)
                b[0] |= (byte)(1 << (7 - xBits));
                // ensure the trailing bit is 1 (i.e. must be odd)
                b[nBytes - 1] |= 1;

                _magnitude = MakeMagnitude(b, 0, b.Length);
                _nBits = -1;
                _mQuote = -1L;

                if (Certainty < 1)
                    break;

                if (CheckProbablePrime(Certainty, Rnd))
                    break;

                if (BitLength > 32)
                {
                    for (int rep = 0; rep < 10000; ++rep)
                    {
                        int n = 33 + Rnd.NextInt32(BitLength - 2);
                        _magnitude[_magnitude.Length - (n >> 5)] ^= (1 << (n & 31));
                        _magnitude[_magnitude.Length - 1] ^= ((Rnd.Next() + 1) << 1);
                        _mQuote = -1L;

                        if (CheckProbablePrime(Certainty, Rnd))
                            return;
                    }
                }
            } while (true);
        }

        /// <summary>
        /// <para>Translates the sign-magnitude representation of a BigInteger into a BigInteger. 
        /// The sign is represented as an integer signum value: -1 for negative, 0 for zero, or 1 for positive. 
        /// The magnitude is a byte array in big-endian byte-order: the most significant byte is in the zeroth element. 
        /// A zero-length magnitude array is permissible, and will result in a BigInteger value of 0, whether signum is -1, 0 or 1.</para>
        /// </summary>
        /// <param name="Signum">Signum of the number (-1 for negative, 0 for zero, 1 for positive)</param>
        /// <param name="Magnitude">Big-endian binary representation of the magnitude of the number</param>
        public BigInteger(int Signum, byte[] Magnitude)
            : this(Signum, Magnitude, 0, Magnitude.Length)
        {
        }

        /// <summary>
        /// <para>Translates the sign-magnitude representation of a BigInteger into a BigInteger. 
        /// The sign is represented as an integer signum value: -1 for negative, 0 for zero, or 1 for positive. 
        /// The magnitude is a byte array in big-endian byte-order: the most significant byte is in the zeroth element. 
        /// A zero-length magnitude array is permissible, and will result in a BigInteger value of 0, whether signum is -1, 0 or 1.</para>
        /// </summary>
        /// <param name="Signum">Signum of the number (-1 for negative, 0 for zero, 1 for positive)</param>
        /// <param name="Magnitude">Big-endian binary representation of the magnitude of the number</param>
        /// <param name="Offset">Byte offset within Magnitude</param>
        /// <param name="Length">Byte length of Magnitude</param>
        /// 
        /// <exception cref="System.FormatException">Thrown if an invalid Signum  is used</exception>
        public BigInteger(int Signum, byte[] Magnitude, int Offset, int Length)
        {
            if (Signum < -1 || Signum > 1)
                throw new FormatException("Invalid sign value");

            if (Signum == 0)
            {
                //sign = 0;
                _magnitude = _zeroMagnitude;
            }
            else
            {
                // copy bytes
                _magnitude = MakeMagnitude(Magnitude, Offset, Length);
                _signum = _magnitude.Length < 1 ? 0 : Signum;
            }
        }

        private BigInteger()
        {
        }

        private BigInteger(int Signum, int[] Magnitude, bool CheckMagnitude)
        {
            if (CheckMagnitude)
            {
                int i = 0;
                while (i < Magnitude.Length && Magnitude[i] == 0)
                {
                    ++i;
                }

                if (i == Magnitude.Length)
                {
                    _magnitude = _zeroMagnitude;
                }
                else
                {
                    _signum = Signum;

                    if (i == 0)
                    {
                        _magnitude = Magnitude;
                    }
                    else
                    {
                        // strip leading 0 words
                        _magnitude = new int[Magnitude.Length - i];
                        Array.Copy(Magnitude, i, _magnitude, 0, _magnitude.Length);
                    }
                }
            }
            else
            {
                _signum = Signum;
                _magnitude = Magnitude;
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Returns a BigInteger whose value is the absolute value of this BigInteger
        /// </summary>
        /// <returns>Abs(this)</returns>
        public BigInteger Abs()
        {
            return _signum >= 0 ? this : Negate();
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this + val)
        /// </summary>
        /// <param name="Value">Value to be added to this BigInteger</param>
        /// <returns>this + Value</returns>
        public BigInteger Add(BigInteger Value)
        {
            if (_signum == 0)
                return Value;

            if (_signum != Value._signum)
            {
                if (Value._signum == 0)
                    return this;

                if (Value._signum < 0)
                    return Subtract(Value.Negate());

                return Value.Subtract(Negate());
            }

            return AddToMagnitude(Value._magnitude);
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this &amp; Value). (This method returns a negative BigInteger if and only if this and val are both negative.)
        /// </summary>
        /// <param name="Value">Value to be AND'ed with this BigInteger</param>
        /// <returns>this &amp; Value</returns>
        public BigInteger And(BigInteger Value)
        {
            if (_signum == 0 || Value._signum == 0)
                return Zero;

            int[] aMag = _signum > 0 ? _magnitude : Add(One)._magnitude;
            int[] bMag = Value._signum > 0 ? Value._magnitude : Value.Add(One)._magnitude;

            bool resultNeg = _signum < 0 && Value._signum < 0;
            int resultLength = System.Math.Max(aMag.Length, bMag.Length);
            int[] resultMag = new int[resultLength];
            int aStart = resultMag.Length - aMag.Length;
            int bStart = resultMag.Length - bMag.Length;

            for (int i = 0; i < resultMag.Length; ++i)
            {
                int aWord = i >= aStart ? aMag[i - aStart] : 0;
                int bWord = i >= bStart ? bMag[i - bStart] : 0;

                if (_signum < 0)
                    aWord = ~aWord;

                if (Value._signum < 0)
                    bWord = ~bWord;

                resultMag[i] = aWord & bWord;

                if (resultNeg)
                    resultMag[i] = ~resultMag[i];
            }

            BigInteger result = new BigInteger(1, resultMag, true);

            if (resultNeg)
                result = result.Not();

            return result;
        }

        /// <summary>
        /// <para>Returns a BigInteger whose value is (this &amp; ~val). 
        /// This method, which is equivalent to and(val.not()), is provided as a convenience for masking operations. 
        /// (This method returns a negative BigInteger if and only if this is negative and val is positive.)</para>
        /// </summary>
        /// <param name="Value">Value to be complemented and AND'ed with this BigInteger</param>
        /// <returns>this &amp; ~Value</returns>
        public BigInteger AndNot(BigInteger Value)
        {
            return And(Value.Not());
        }

        /// <summary>
        /// Returns a BigInteger whose value is equivalent to this BigInteger with the designated bit cleared. (Computes (this &amp; ~(1 &lt; &lt; n)).)
        /// </summary>
        /// <param name="N">Index of bit to clear</param>
        /// <returns>this &amp; ~(1 &lt; &lt; N)</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if Bit address (N) is less than zero</exception>
        public BigInteger ClearBit(int N)
        {
            if (N < 0)
                throw new ArithmeticException("Bit address less than zero");

            if (!TestBit(N))
                return this;

            if (_signum > 0 && N < (BitLength - 1))
                return FlipExistingBit(N);

            return AndNot(One.ShiftLeft(N));
        }

        /// <summary>
        /// Compares this BigInteger with the specified Object for equality
        /// </summary>
        /// <param name="Obj">Object to which this BigInteger is to be compared</param>
        /// <returns>True if and only if the specified Object is a BigInteger whose value is numerically equal to this BigInteger</returns>
        public int CompareTo(object Obj)
        {
            return CompareTo((BigInteger)Obj);
        }

        /// <summary>
        /// <para>Compares this BigInteger with the specified BigInteger. 
        /// This method is provided in preference to individual methods for each of the six boolean comparison operators (&#60;, ==, &#62;, &#62;=, !=, &#60;=). 
        /// The suggested idiom for performing these comparisons is: (x.compareTo(y) 'operator' 0), where operator is one of the six comparison operators.</para>
        /// </summary>
        /// <param name="Value">BigInteger to which this BigInteger is to be compared</param>
        /// <returns>-1, 0 or 1 as this BigInteger is numerically less than, equal to, or greater than Value</returns>
        public int CompareTo(BigInteger Value)
        {
            return _signum < Value._signum ? -1
                : _signum > Value._signum ? 1
                : _signum == 0 ? 0
                : _signum * CompareNoLeadingZeroes(0, _magnitude, 0, Value._magnitude);
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this / Value)
        /// </summary>
        /// <param name="Value">Value by which this BigInteger is to be divided</param>
        /// <returns>this / Value</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if Signum = zero</exception>
        public BigInteger Divide(BigInteger Value)
        {
            if (Value._signum == 0)
                throw new ArithmeticException("Division by zero error");

            if (_signum == 0)
                return Zero;

            if (Value.QuickPow2Check()) // val is power of two
            {
                BigInteger result = this.Abs().ShiftRight(Value.Abs().BitLength - 1);
                return Value._signum == _signum ? result : result.Negate();
            }

            int[] mag = (int[])_magnitude.Clone();

            return new BigInteger(_signum * Value._signum, Divide(mag, Value._magnitude), true);
        }

        /// <summary>
        /// Returns an array of two BigIntegers containing (this / Value) followed by (this % Value)
        /// </summary>
        /// <param name="Value">Value by which this BigInteger is to be divided, and the remainder computed</param>
        /// <returns>An array of two BigIntegers: the quotient (this / Value) is the initial element, and the remainder (this % Value) is the final element</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if Signum = zero</exception>
        public BigInteger[] DivideAndRemainder(BigInteger Value)
        {
            if (Value._signum == 0)
                throw new ArithmeticException("Division by zero error");

            BigInteger[] biggies = new BigInteger[2];

            if (_signum == 0)
            {
                biggies[0] = Zero;
                biggies[1] = Zero;
            }
            else if (Value.QuickPow2Check()) // val is power of two
            {
                int e = Value.Abs().BitLength - 1;
                BigInteger quotient = this.Abs().ShiftRight(e);
                int[] remainder = this.LastNBits(e);

                biggies[0] = Value._signum == _signum ? quotient : quotient.Negate();
                biggies[1] = new BigInteger(_signum, remainder, true);
            }
            else
            {
                int[] remainder = (int[])_magnitude.Clone();
                int[] quotient = Divide(remainder, Value._magnitude);

                biggies[0] = new BigInteger(_signum * Value._signum, quotient, true);
                biggies[1] = new BigInteger(_signum, remainder, true);
            }

            return biggies;
        }

        /// <summary>
        /// Returns a BigInteger whose value is equivalent to this BigInteger with the designated bit flipped. (Computes (this ^ (1&#60;&#60; N)).)
        /// </summary>
        /// <param name="N">Index of bit to flip</param>
        /// <returns>this ^ (1&#60;&#60; N)</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if bit address (N) is less than zero</exception>
        public BigInteger FlipBit(int N)
        {
            if (N < 0)
                throw new ArithmeticException("Bit address less than zero");

            if (_signum > 0 && N < (BitLength - 1))
                return FlipExistingBit(N);

            return Xor(One.ShiftLeft(N));
        }

        /// <summary>
        /// Compares this BigInteger with the specified Object for equality
        /// </summary>
        /// <param name="Obj">Object to which this BigInteger is to be compared</param>
        /// <returns>true if and only if the specified Object is a BigInteger whose value is numerically equal to this BigInteger</returns>
        public override bool Equals(object Obj)
        {
            if (Obj == this)
                return true;

            BigInteger biggie = Obj as BigInteger;
            if (biggie == null)
                return false;

            if (biggie._signum != _signum || biggie._magnitude.Length != _magnitude.Length)
                return false;

            for (int i = 0; i < _magnitude.Length; i++)
            {
                if (biggie._magnitude[i] != _magnitude[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns a BigInteger whose value is the greatest common divisor of abs(this) and abs(val). Returns 0 if this==0 &#38; val==0
        /// </summary>
        /// <param name="Value">Value with which the GCD is to be computed</param>
        /// <returns>GCD(Abs(this), Abs(Value))</returns>
        public BigInteger Gcd(BigInteger Value)
        {
            if (Value._signum == 0)
                return Abs();

            if (_signum == 0)
                return Value.Abs();

            BigInteger r;
            BigInteger u = this;
            BigInteger v = Value;

            while (v._signum != 0)
            {
                r = u.Mod(v);
                u = v;
                v = r;
            }

            return u;
        }

        /// <summary>
        /// Returns the hash code for this BigInteger
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int hc = _magnitude.Length;

            if (_magnitude.Length > 0)
            {
                hc ^= _magnitude[0];

                if (_magnitude.Length > 1)
                    hc ^= _magnitude[_magnitude.Length - 1];
            }

            return _signum < 0 ? ~hc : hc;
        }

        /// <summary>
        /// <para>Returns the index of the rightmost (lowest-order) one bit in this BigInteger (the number of zero bits to the right of the rightmost one bit). 
        /// Returns -1 if this BigInteger contains no one bits. (Computes (this==0? -1 : log2(this &#38; -this)).)</para>
        /// </summary>
        /// <returns>Index of the rightmost one bit in this BigInteger</returns>
        public int GetLowestSetBit()
        {
            if (_signum == 0)
                return -1;

            int w = _magnitude.Length;

            while (--w > 0)
            {
                if (_magnitude[w] != 0)
                    break;
            }

            int word = (int)_magnitude[w];
            Debug.Assert(word != 0);

            int b = (word & 0x0000FFFF) == 0
                ? (word & 0x00FF0000) == 0
                    ? 7
                    : 15
                : (word & 0x000000FF) == 0
                    ? 23
                    : 31;

            while (b > 0)
            {
                if ((word << b) == int.MinValue)
                    break;

                b--;
            }

            return ((_magnitude.Length - w) * 32 - (b + 1));
        }

        /// <summary>
        /// Returns true if this BigInteger is probably prime, false if it's definitely composite. If certainty is ≤ 0, true is returned
        /// </summary>
        /// <param name="Certainty"><para>A measure of the uncertainty that the caller is willing to tolerate: 
        /// if the call returns true the probability that this BigInteger is prime exceeds (1 - 1/2certainty). 
        /// The execution time of this method is proportional to the value of this parameter.</para></param>
        /// <returns>true if this BigInteger is probably prime, false if it's definitely composite</returns>
        public bool IsProbablePrime(int Certainty)
        {
            if (Certainty <= 0)
                return true;

            BigInteger n = Abs();

            if (!n.TestBit(0))
                return n.Equals(Two);

            if (n.Equals(One))
                return false;

            return n.CheckProbablePrime(Certainty, _randomSource);
        }

        /// <summary>
        /// Returns the maximum of this BigInteger and Value
        /// </summary>
        /// <param name="Value">Value with which the maximum is to be computed</param>
        /// <returns>The BigInteger whose value is the greater of this and Value. If they are equal, either may be returned</returns>
        public BigInteger Max(BigInteger Value)
        {
            return CompareTo(Value) > 0 ? this : Value;
        }

        /// <summary>
        /// Returns the minimum of this BigInteger and val
        /// </summary>
        /// <param name="Value">Value with which the minimum is to be computed</param>
        /// <returns>The BigInteger whose value is the lesser of this BigInteger and Value. If they are equal, either may be returned</returns>
        public BigInteger Min(BigInteger Value)
        {
            return CompareTo(Value) < 0 ? this : Value;
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this mod m). This method differs from remainder in that it always returns a non-negative BigInteger
        /// </summary>
        /// <param name="M">The modulus</param>
        /// <returns>this mod M</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if Modulus (M) is less than 1</exception>
        public BigInteger Mod(BigInteger M)
        {
            if (M._signum < 1)
                throw new ArithmeticException("Modulus must be positive");

            BigInteger biggie = Remainder(M);

            return (biggie._signum >= 0 ? biggie : biggie.Add(M));
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this-1 mod m)
        /// </summary>
        /// <param name="M">The modulus</param>
        /// <returns>this-1 mod M</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if Modulus (M) is less than 1</exception>
        public BigInteger ModInverse(BigInteger M)
        {
            if (M._signum < 1)
                throw new ArithmeticException("Modulus must be positive");

            BigInteger x = new BigInteger();
            BigInteger gcd = ExtEuclid(this.Mod(M), M, x, null);

            if (!gcd.Equals(One))
                throw new ArithmeticException("Numbers not relatively prime.");

            if (x._signum < 0)
            {
                x._signum = 1;
                //x = m.Subtract(x);
                x._magnitude = DoSubBigLil(M._magnitude, x._magnitude);
            }

            return x;
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this exponent mod m). (Unlike pow, this method permits negative exponents.)
        /// </summary>
        /// <param name="Exponent">The exponent</param>
        /// <param name="M">The modulus</param>
        /// <returns>this exponent mod M</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if Modulus (M) is less than 1</exception>
        public BigInteger ModPow(BigInteger Exponent, BigInteger M)
        {
            if (M._signum < 1)
                throw new ArithmeticException("Modulus must be positive");

            if (M.Equals(One))
                return Zero;

            if (Exponent._signum == 0)
                return One;

            if (_signum == 0)
                return Zero;

            int[] zVal = null;
            int[] yAccum = null;
            int[] yVal;

            // Montgomery exponentiation is only possible if the modulus is odd,
            // but AFAIK, this is always the case for crypto algo's
            bool useMonty = ((M._magnitude[M._magnitude.Length - 1] & 1) == 1);
            long mQ = 0;
            if (useMonty)
            {
                mQ = M.GetMQuote();

                // tmp = this * R mod m
                BigInteger tmp = ShiftLeft(32 * M._magnitude.Length).Mod(M);
                zVal = tmp._magnitude;

                useMonty = (zVal.Length <= M._magnitude.Length);

                if (useMonty)
                {
                    yAccum = new int[M._magnitude.Length + 1];
                    if (zVal.Length < M._magnitude.Length)
                    {
                        int[] longZ = new int[M._magnitude.Length];
                        zVal.CopyTo(longZ, longZ.Length - zVal.Length);
                        zVal = longZ;
                    }
                }
            }

            if (!useMonty)
            {
                if (_magnitude.Length <= M._magnitude.Length)
                {
                    //zAccum = new int[m.magnitude.Length * 2];
                    zVal = new int[M._magnitude.Length];
                    _magnitude.CopyTo(zVal, zVal.Length - _magnitude.Length);
                }
                else
                {
                    // in normal practice we'll never see this...
                    BigInteger tmp = Remainder(M);

                    //zAccum = new int[m.magnitude.Length * 2];
                    zVal = new int[M._magnitude.Length];
                    tmp._magnitude.CopyTo(zVal, zVal.Length - tmp._magnitude.Length);
                }

                yAccum = new int[M._magnitude.Length * 2];
            }

            yVal = new int[M._magnitude.Length];

            // from LSW to MSW
            for (int i = 0; i < Exponent._magnitude.Length; i++)
            {
                int v = Exponent._magnitude[i];
                int bits = 0;

                if (i == 0)
                {
                    while (v > 0)
                    {
                        v <<= 1;
                        bits++;
                    }

                    //
                    // first time in initialise y
                    //
                    zVal.CopyTo(yVal, 0);

                    v <<= 1;
                    bits++;
                }

                while (v != 0)
                {
                    if (useMonty)
                    {
                        // Montgomery square algo doesn't exist, and a normal
                        // square followed by a Montgomery reduction proved to
                        // be almost as heavy as a Montgomery mulitply.
                        MultiplyMonty(yAccum, yVal, yVal, M._magnitude, mQ);
                    }
                    else
                    {
                        Square(yAccum, yVal);
                        Remainder(yAccum, M._magnitude);
                        Array.Copy(yAccum, yAccum.Length - yVal.Length, yVal, 0, yVal.Length);
                        ZeroOut(yAccum);
                    }
                    bits++;

                    if (v < 0)
                    {
                        if (useMonty)
                        {
                            MultiplyMonty(yAccum, yVal, zVal, M._magnitude, mQ);
                        }
                        else
                        {
                            Multiply(yAccum, yVal, zVal);
                            Remainder(yAccum, M._magnitude);
                            Array.Copy(yAccum, yAccum.Length - yVal.Length, yVal, 0,
                                yVal.Length);
                            ZeroOut(yAccum);
                        }
                    }

                    v <<= 1;
                }

                while (bits < 32)
                {
                    if (useMonty)
                    {
                        MultiplyMonty(yAccum, yVal, yVal, M._magnitude, mQ);
                    }
                    else
                    {
                        Square(yAccum, yVal);
                        Remainder(yAccum, M._magnitude);
                        Array.Copy(yAccum, yAccum.Length - yVal.Length, yVal, 0, yVal.Length);
                        ZeroOut(yAccum);
                    }
                    bits++;
                }
            }

            if (useMonty)
            {
                // Return y * R^(-1) mod m by doing y * 1 * R^(-1) mod m
                ZeroOut(zVal);
                zVal[zVal.Length - 1] = 1;
                MultiplyMonty(yAccum, yVal, zVal, M._magnitude, mQ);
            }

            BigInteger result = new BigInteger(1, yVal, true);

            return Exponent._signum > 0 ? result : result.ModInverse(M);
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this * Value)
        /// </summary>
        /// <param name="Value">Value to be multiplied by this BigInteger</param>
        /// <returns>this * Value</returns>
        public BigInteger Multiply(BigInteger Value)
        {
            if (_signum == 0 || Value._signum == 0)
                return Zero;

            if (Value.QuickPow2Check()) // val is power of two
            {
                BigInteger result = this.ShiftLeft(Value.Abs().BitLength - 1);
                return Value._signum > 0 ? result : result.Negate();
            }

            if (this.QuickPow2Check()) // this is power of two
            {
                BigInteger result = Value.ShiftLeft(this.Abs().BitLength - 1);
                return _signum > 0 ? result : result.Negate();
            }

            int resLength = (this.BitLength + Value.BitLength) / BitsPerInt + 1;
            int[] res = new int[resLength];

            if (Value == this)
                Square(res, _magnitude);
            else
                Multiply(res, _magnitude, Value._magnitude);

            return new BigInteger(_signum * Value._signum, res, true);
        }

        /// <summary>
        /// Returns a BigInteger whose value is (-this)
        /// </summary>
        /// <returns>~this</returns>
        public BigInteger Negate()
        {
            if (_signum == 0)
                return this;

            return new BigInteger(-_signum, _magnitude, false);
        }

        /// <summary>
        /// <para>Returns the first integer greater than this BigInteger that is probably prime. 
        /// The probability that the number returned by this method is composite does not exceed 2-100. 
        /// This method will never skip over a prime when searching: if it returns p, there is no prime q such that this &#60; q &#60; p.</para>
        /// </summary>
        /// <returns>The first integer greater than this BigInteger that is probably prime</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if Signum is less than zero</exception>
        public BigInteger NextProbablePrime()
        {
            if (_signum < 0)
                throw new ArithmeticException("Cannot be called on value < 0");

            if (CompareTo(Two) < 0)
                return Two;

            BigInteger n = Inc().SetBit(0);

            while (!n.CheckProbablePrime(100, _randomSource))
            {
                n = n.Add(Two);
            }

            return n;
        }

        /// <summary>
        /// Returns a BigInteger whose value is (~this). (This method returns a negative value if and only if this BigInteger is non-negative.)
        /// </summary>
        /// <returns>~this</returns>
        public BigInteger Not()
        {
            return Inc().Negate();
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this | val). (This method returns a negative BigInteger if and only if either this or val is negative.)
        /// </summary>
        /// <param name="Value">Value to be OR'ed with this BigInteger</param>
        /// <returns>this | Value</returns>
        public BigInteger Or(BigInteger Value)
        {
            if (_signum == 0)
                return Value;

            if (Value._signum == 0)
                return this;

            int[] aMag = _signum > 0 ? _magnitude : Add(One)._magnitude;
            int[] bMag = Value._signum > 0 ? Value._magnitude : Value.Add(One)._magnitude;

            bool resultNeg = _signum < 0 || Value._signum < 0;
            int resultLength = System.Math.Max(aMag.Length, bMag.Length);
            int[] resultMag = new int[resultLength];

            int aStart = resultMag.Length - aMag.Length;
            int bStart = resultMag.Length - bMag.Length;

            for (int i = 0; i < resultMag.Length; ++i)
            {
                int aWord = i >= aStart ? aMag[i - aStart] : 0;
                int bWord = i >= bStart ? bMag[i - bStart] : 0;

                if (_signum < 0)
                    aWord = ~aWord;

                if (Value._signum < 0)
                    bWord = ~bWord;

                resultMag[i] = aWord | bWord;

                if (resultNeg)
                    resultMag[i] = ~resultMag[i];
            }

            BigInteger result = new BigInteger(1, resultMag, true);

            if (resultNeg)
                result = result.Not();

            return result;
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this pow exponent). Note that exponent is an integer rather than a BigInteger
        /// </summary>
        /// <param name="Exponent">Exponent to which this BigInteger is to be raised</param>
        /// <returns>this pow Exponent</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if Exponent is less than zero</exception>
        public BigInteger Pow(int Exponent)
        {
            if (Exponent < 0)
                throw new ArithmeticException("Negative exponent");

            if (Exponent == 0)
                return One;

            if (_signum == 0 || Equals(One))
                return this;

            BigInteger y = One;
            BigInteger z = this;

            do
            {
                if ((Exponent & 0x1) == 1)
                    y = y.Multiply(z);

                Exponent >>= 1;

                if (Exponent == 0)
                    break;

                z = z.Multiply(z);
            } while (true);

            return y;
        }

        /// <summary>
        /// <para>Returns a positive BigInteger that is probably prime, with the specified bitLength. 
        /// The probability that a BigInteger returned by this method is composite does not exceed 2(-100)</para>
        /// </summary>
        /// <param name="BitLength">BitLength of the returned BigInteger</param>
        /// <param name="Rnd">Source of SecureRandom bits used to select candidates to be tested for primality</param>
        /// <returns>A BigInteger of BitLength bits that is probably prime</returns>
        public static BigInteger ProbablePrime(int BitLength, SecureRandom Rnd)
        {
            return new BigInteger(BitLength, 100, Rnd);
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this % Value)
        /// </summary>
        /// <param name="Value">Value by which this BigInteger is to be divided, and the remainder computed</param>
        /// <returns>this % Value</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if Signum is zero</exception>
        public BigInteger Remainder(BigInteger Value)
        {
            if (Value._signum == 0)
                throw new ArithmeticException("Division by zero error");

            if (_signum == 0)
                return Zero;

            // For small values, use fast remainder method
            if (Value._magnitude.Length == 1)
            {
                int val = Value._magnitude[0];

                if (val > 0)
                {
                    if (val == 1)
                        return Zero;

                    int rem = Remainder(val);

                    return rem == 0 ? Zero : new BigInteger(_signum, new int[] { rem }, false);
                }
            }

            if (CompareNoLeadingZeroes(0, _magnitude, 0, Value._magnitude) < 0)
                return this;

            int[] result;
            if (Value.QuickPow2Check())  // n is power of two
            {
                // TODO Move before small values branch above?
                result = LastNBits(Value.Abs().BitLength - 1);
            }
            else
            {
                result = (int[])_magnitude.Clone();
                result = Remainder(result, Value._magnitude);
            }

            return new BigInteger(_signum, result, true);
        }


        /// <summary>
        /// <para>Returns a BigInteger whose value is equivalent to this BigInteger with the designated bit set. (Computes (this | (1 &#60;&#60; N)).)</para>
        /// </summary>
        /// <param name="N">Index of bit to set</param>
        /// <returns>this | (1 &#60;&#60; N)</returns>
        /// 
        /// <exception cref="System.ArithmeticException">Thrown if bit address (N) is less than zero</exception>
        public BigInteger SetBit(int N)
        {
            if (N < 0)
                throw new ArithmeticException("Bit address less than zero");

            if (TestBit(N))
                return this;

            if (_signum > 0 && N < (BitLength - 1))
                return FlipExistingBit(N);

            return Or(One.ShiftLeft(N));
        }

        /// <summary>
        /// <para>Returns a BigInteger whose value is (this &#60;&#60; N). 
        /// The shift distance, n, may be negative, in which case this method performs a right shift. (Computes floor(this * 2n).)</para>
        /// </summary>
        /// <param name="N">Shift distance in bits</param>
        /// <returns>this &#60;&#60; N</returns>
        public BigInteger ShiftLeft(int N)
        {
            if (_signum == 0 || _magnitude.Length == 0)
                return Zero;

            if (N == 0)
                return this;

            if (N < 0)
                return ShiftRight(-N);

            BigInteger result = new BigInteger(_signum, ShiftLeft(_magnitude, N), true);

            if (_nBits != -1)
                result._nBits = _signum > 0 ? _nBits : _nBits + N;

            if (_nBitLength != -1)
                result._nBitLength = _nBitLength + N;

            return result;
        }

        /// <summary>
        /// <para>Returns a BigInteger whose value is (this &#62;&#62; N). Sign extension is performed. 
        /// The shift distance, n, may be negative, in which case this method performs a left shift. (Computes floor(this / 2n).)</para>
        /// </summary>
        /// <param name="N">Shift distance in bits</param>
        /// <returns>this &#62;&#62; N</returns>
        public BigInteger ShiftRight(int N)
        {
            if (N == 0)
                return this;

            if (N < 0)
                return ShiftLeft(-N);

            if (N >= BitLength)
                return (_signum < 0 ? One.Negate() : Zero);

            int resultLength = (BitLength - N + 31) >> 5;
            int[] res = new int[resultLength];
            int numInts = N >> 5;
            int numBits = N & 31;

            if (numBits == 0)
            {
                Array.Copy(_magnitude, 0, res, 0, res.Length);
            }
            else
            {
                int numBits2 = 32 - numBits;

                int magPos = _magnitude.Length - 1 - numInts;
                for (int i = resultLength - 1; i >= 0; --i)
                {
                    res[i] = (int)((uint)_magnitude[magPos--] >> numBits);

                    if (magPos >= 0)
                        res[i] |= _magnitude[magPos] << numBits2;
                }
            }

            Debug.Assert(res[0] != 0);

            return new BigInteger(_signum, res, false);
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this - Value)
        /// </summary>
        /// <param name="Value">Value to be subtracted from this BigInteger</param>
        /// <returns>this - Value</returns>
        public BigInteger Subtract(BigInteger Value)
        {
            if (Value._signum == 0)
                return this;

            if (_signum == 0)
                return Value.Negate();

            if (_signum != Value._signum)
                return Add(Value.Negate());

            int compare = CompareNoLeadingZeroes(0, _magnitude, 0, Value._magnitude);

            if (compare == 0)
                return Zero;

            BigInteger bigun, lilun;

            if (compare < 0)
            {
                bigun = Value;
                lilun = this;
            }
            else
            {
                bigun = this;
                lilun = Value;
            }

            return new BigInteger(_signum * compare, DoSubBigLil(bigun._magnitude, lilun._magnitude), true);
        }

        /// <summary>
        /// Returns true if and only if the designated bit is set. (Computes ((this &amp; (1 &amp;&amp; N)) != 0).)
        /// </summary>
        /// 
        /// <param name="N">Index of bit to test</param>
        /// <returns>true if and only if the designated bit is set</returns>
        ///
        /// <exception cref="System.ArithmeticException">Thrown if bit position (N) is less than zero</exception>
        public bool TestBit(int N)
        {
            if (N < 0)
                throw new ArithmeticException("Bit position must not be negative");

            if (_signum < 0)
                return !Not().TestBit(N);

            int wordNum = N / 32;

            if (wordNum >= _magnitude.Length)
                return false;

            int word = _magnitude[_magnitude.Length - 1 - wordNum];

            return ((word >> (N % 32)) & 1) > 0;
        }

        /// <summary>
        /// <para>Returns a byte array containing the two's-complement representation of this BigInteger. 
        /// The byte array will be in big-endian byte-order: the most significant byte is in the zeroth element. 
        /// The array will contain the minimum number of bytes required to represent this BigInteger, including at least one sign bit, which is (ceil((this.bitLength() + 1)/8)). 
        /// (This representation is compatible with the (byte[]) constructor.)</para>
        /// </summary>
        /// <returns>A byte array containing the two's-complement representation of this BigInteger</returns>
        public byte[] ToByteArray()
        {
            return ToByteArray(false);
        }

        /// <summary>
        /// Returns an unsigned byte array containing the two's-complement representation of this BigInteger
        /// </summary>
        /// <returns>A byte array containing the two's-complement representation of this BigInteger</returns>
        public byte[] ToByteArrayUnsigned()
        {
            return ToByteArray(true);
        }

        /// <summary>
        /// <para>Returns the decimal String representation of this BigInteger. 
        /// The digit-to-character mapping provided by Character.forDigit is used., and a minus sign is prepended if appropriate.</para>
        /// </summary>
        /// <returns>Decimal String representation of this BigInteger</returns>
        public override string ToString()
        {
            return ToString(10);
        }

        /// <summary>
        /// Returns the String representation of this BigInteger in the given radix
        /// </summary>
        /// <param name="Radix">Radix of the String representation</param>
        /// <returns>String representation of this BigInteger in the given radix</returns>
        /// 
        /// <exception cref="System.FormatException">Thrown if bases other than 2, 10, 16 are used</exception>
        public string ToString(int Radix)
        {
            switch (Radix)
            {
                case 2:
                case 10:
                case 16:
                    break;
                default:
                    throw new FormatException("Only bases 2, 10, 16 are allowed");
            }

            // NB: Can only happen to internally managed instances
            if (_magnitude == null)
                return "null";

            if (_signum == 0)
                return "0";

            Debug.Assert(_magnitude.Length > 0);

            StringBuilder sb = new StringBuilder();

            if (Radix == 16)
            {
                sb.Append(_magnitude[0].ToString("x"));

                for (int i = 1; i < _magnitude.Length; i++)
                    sb.Append(_magnitude[i].ToString("x8"));
            }
            else if (Radix == 2)
            {
                sb.Append('1');

                for (int i = BitLength - 2; i >= 0; --i)
                    sb.Append(TestBit(i) ? '1' : '0');
            }
            else
            {
                // This is algorithm 1a from chapter 4.4 in Seminumerical Algorithms, slow but it works
                IList S = new ArrayList();
                BigInteger bs = ValueOf(Radix);

                // The sign is handled seperatly.
                // Notice however that for this to work, radix 16 _MUST_ be a special case,
                // unless we want to enter a recursion well. In their infinite wisdom, why did not
                // the Sun engineers made a c'tor for BigIntegers taking a BigInteger as parameter?
                // (Answer: Becuase Sun's BigIntger is clonable, something bouncycastle's isn't.)
                // BigInteger u = new BigInteger(Abs().ToString(16), 16);
                BigInteger u = this.Abs();
                BigInteger b;

                while (u._signum != 0)
                {
                    b = u.Mod(bs);
                    if (b._signum == 0)
                        S.Add("0");
                    else // see how to interact with different bases
                        S.Add(b._magnitude[0].ToString("d"));

                    u = u.Divide(bs);
                }

                // Then pop the stack
                for (int i = S.Count - 1; i >= 0; --i)
                    sb.Append((string)S[i]);
            }

            string s = sb.ToString();

            Debug.Assert(s.Length > 0);

            // Strip leading zeros. (We know this number is not all zeroes though)
            if (s[0] == '0')
            {
                int nonZeroPos = 0;
                while (s[++nonZeroPos] == '0') { }

                s = s.Substring(nonZeroPos);
            }

            if (_signum == -1)
                s = "-" + s;

            return s;
        }

        /// <summary>
        /// <para>Returns a BigInteger whose value is equal to that of the specified long. 
        /// This "static factory method" is provided in preference to a (long) constructor because it allows for reuse of frequently used BigIntegers.</para>
        /// </summary>
        /// <param name="Value">Value of the BigInteger to return</param>
        /// <returns>A BigInteger with the specified value.</returns>
        public static BigInteger ValueOf(long Value)
        {
            switch (Value)
            {
                case 0:
                    return Zero;
                case 1:
                    return One;
                case 2:
                    return Two;
                case 3:
                    return Three;
                case 10:
                    return Ten;
            }

            return CreateValueOf(Value);
        }

        /// <summary>
        /// Returns a BigInteger whose value is (this ^ val). (This method returns a negative BigInteger if and only if exactly one of this and val are negative.)
        /// </summary>
        /// <param name="Value">Value to be XOR'ed with this BigInteger</param>
        /// <returns>this ^ Value</returns>
        public BigInteger Xor(BigInteger Value)
        {
            if (_signum == 0)
                return Value;

            if (Value._signum == 0)
                return this;

            int[] aMag = _signum > 0 ? _magnitude : Add(One)._magnitude;
            int[] bMag = Value._signum > 0 ? Value._magnitude : Value.Add(One)._magnitude;

            // TODO Can just replace with sign != value.sign?
            bool resultNeg = (_signum < 0 && Value._signum >= 0) || (_signum >= 0 && Value._signum < 0);
            int resultLength = System.Math.Max(aMag.Length, bMag.Length);
            int[] resultMag = new int[resultLength];
            int aStart = resultMag.Length - aMag.Length;
            int bStart = resultMag.Length - bMag.Length;

            for (int i = 0; i < resultMag.Length; ++i)
            {
                int aWord = i >= aStart ? aMag[i - aStart] : 0;
                int bWord = i >= bStart ? bMag[i - bStart] : 0;

                if (_signum < 0)
                    aWord = ~aWord;

                if (Value._signum < 0)
                    bWord = ~bWord;

                resultMag[i] = aWord ^ bWord;

                if (resultNeg)
                    resultMag[i] = ~resultMag[i];
            }

            BigInteger result = new BigInteger(1, resultMag, true);

            // TODO Optimise this case
            if (resultNeg)
                result = result.Not();

            return result;
        }

        #endregion

        #region Private Methods
        private static int[] AddMagnitudes(int[] A, int[] B)
        {
            // return a = a + b - b preserved.
            int tI = A.Length - 1;
            int vI = B.Length - 1;
            long m = 0;

            while (vI >= 0)
            {
                m += ((long)(uint)A[tI] + (long)(uint)B[vI--]);
                A[tI--] = (int)m;
                m = (long)((ulong)m >> 32);
            }

            if (m != 0)
                while (tI >= 0 && ++A[tI--] == 0) { }

            return A;
        }

        private BigInteger AddToMagnitude(int[] MagToAdd)
        {
            int[] big, small;
            if (_magnitude.Length < MagToAdd.Length)
            {
                big = MagToAdd;
                small = _magnitude;
            }
            else
            {
                big = _magnitude;
                small = MagToAdd;
            }

            // Conservatively avoid over-allocation when no overflow possible
            uint limit = uint.MaxValue;

            if (big.Length == small.Length)
                limit -= (uint)small[0];

            bool possibleOverflow = (uint)big[0] >= limit;

            int[] bigCopy;

            if (possibleOverflow)
            {
                bigCopy = new int[big.Length + 1];
                big.CopyTo(bigCopy, 1);
            }
            else
            {
                bigCopy = (int[])big.Clone();
            }

            bigCopy = AddMagnitudes(bigCopy, small);

            return new BigInteger(_signum, bigCopy, possibleOverflow);
        }

        private int CalcBitLength(int Index, int[] Magnitude)
        {
            do
            {
                if (Index >= Magnitude.Length)
                    return 0;

                if (Magnitude[Index] != 0)
                    break;

                ++Index;
            } while (true);

            // bit length for everything after the first int
            int bitLength = 32 * ((Magnitude.Length - Index) - 1);
            // and determine bitlength of first int
            int firstMag = Magnitude[Index];
            bitLength += BitLen(firstMag);

            // Check for negative powers of two
            if (_signum < 0 && ((firstMag & -firstMag) == firstMag))
            {
                do
                {
                    if (++Index >= Magnitude.Length)
                    {
                        --bitLength;
                        break;
                    }
                }
                while (Magnitude[Index] == 0);
            }

            return bitLength;
        }

        private bool CheckProbablePrime(int Certainty, SecureRandom SecRand)
        {
            Debug.Assert(Certainty > 0);
            Debug.Assert(CompareTo(Two) > 0);
            Debug.Assert(TestBit(0));

            // Try to reduce the penalty for really small numbers
            int numLists = System.Math.Min(BitLength - 1, _primeLists.Length);

            for (int i = 0; i < numLists; ++i)
            {
                int test = Remainder(_primeProducts[i]);
                int[] primeList = _primeLists[i];

                for (int j = 0; j < primeList.Length; ++j)
                {
                    int prime = primeList[j];
                    int qRem = test % prime;

                    if (qRem == 0) // We may find small numbers in the list
                        return BitLength < 16 && IntValue == prime;
                }
            }

            return RabinMillerTest(Certainty, SecRand);
        }

        private static int CompareTo(int XIndx, int[] X, int YIndx, int[] Y)
        {
            while (XIndx != X.Length && X[XIndx] == 0)
                XIndx++;

            while (YIndx != Y.Length && Y[YIndx] == 0)
                YIndx++;

            return CompareNoLeadingZeroes(XIndx, X, YIndx, Y);
        }

        private static int CompareNoLeadingZeroes(int XIndx, int[] X, int YIndx, int[] Y)
        {
            int diff = (X.Length - Y.Length) - (XIndx - YIndx);

            if (diff != 0)
                return diff < 0 ? -1 : 1;

            // lengths of magnitudes the same, test the magnitude values
            while (XIndx < X.Length)
            {
                uint v1 = (uint)X[XIndx++];
                uint v2 = (uint)Y[YIndx++];

                if (v1 != v2)
                    return v1 < v2 ? -1 : 1;
            }

            return 0;
        }

        private static BigInteger CreateUValueOf(ulong Value)
        {
            int msw = (int)(Value >> 32);
            int lsw = (int)Value;

            if (msw != 0)
                return new BigInteger(1, new int[] { msw, lsw }, false);

            if (lsw != 0)
            {
                BigInteger n = new BigInteger(1, new int[] { lsw }, false);
                // Check for a power of two
                if ((lsw & -lsw) == lsw)
                    n._nBits = 1;
                
                return n;
            }

            return Zero;
        }

        private static BigInteger CreateValueOf(long Value)
        {
            if (Value < 0)
            {
                if (Value == long.MinValue)
                    return CreateValueOf(~Value).Not();

                return CreateValueOf(-Value).Negate();
            }

            return CreateUValueOf((ulong)Value);
        }

        private int[] Divide(int[] X, int[] Y)
        {
            int xStart = 0;
            int yStart = 0;

            while (xStart < X.Length && X[xStart] == 0)
                ++xStart;

            while (yStart < Y.Length && Y[yStart] == 0)
                ++yStart;

            Debug.Assert(yStart < Y.Length);

            int xyCmp = CompareNoLeadingZeroes(xStart, X, yStart, Y);
            int[] count;

            if (xyCmp > 0)
            {
                int yBitLength = CalcBitLength(yStart, Y);
                int xBitLength = CalcBitLength(xStart, X);
                int shift = xBitLength - yBitLength;
                int[] iCount;
                int iCountStart = 0;
                int[] c;
                int cStart = 0;
                int cBitLength = yBitLength;

                if (shift > 0)
                {
                    iCount = new int[(shift >> 5) + 1];
                    iCount[0] = 1 << (shift % 32);
                    c = ShiftLeft(Y, shift);
                    cBitLength += shift;
                }
                else
                {
                    iCount = new int[] { 1 };
                    int len = Y.Length - yStart;
                    c = new int[len];
                    Array.Copy(Y, yStart, c, 0, len);
                }

                count = new int[iCount.Length];

                do
                {
                    if (cBitLength < xBitLength || CompareNoLeadingZeroes(xStart, X, cStart, c) >= 0)
                    {
                        Subtract(xStart, X, cStart, c);
                        AddMagnitudes(count, iCount);

                        while (X[xStart] == 0)
                        {
                            if (++xStart == X.Length)
                                return count;
                        }

                        //xBitLength = calcBitLength(xStart, x);
                        xBitLength = 32 * (X.Length - xStart - 1) + BitLen(X[xStart]);

                        if (xBitLength <= yBitLength)
                        {
                            if (xBitLength < yBitLength)
                                return count;

                            xyCmp = CompareNoLeadingZeroes(xStart, X, yStart, Y);

                            if (xyCmp <= 0)
                                break;
                        }
                    }

                    shift = cBitLength - xBitLength;

                    // NB: The case where c[cStart] is 1-bit is harmless
                    if (shift == 1)
                    {
                        uint firstC = (uint)c[cStart] >> 1;
                        uint firstX = (uint)X[xStart];

                        if (firstC > firstX)
                            ++shift;
                    }

                    if (shift < 2)
                    {
                        ShiftRightOneInPlace(cStart, c);
                        --cBitLength;
                        ShiftRightOneInPlace(iCountStart, iCount);
                    }
                    else
                    {
                        ShiftRightInPlace(cStart, c, shift);
                        cBitLength -= shift;
                        ShiftRightInPlace(iCountStart, iCount, shift);
                    }

                    //cStart = c.Length - ((cBitLength + 31) / 32);
                    while (c[cStart] == 0)
                        ++cStart;

                    while (iCount[iCountStart] == 0)
                        ++iCountStart;
                    
                } while (true);
            }
            else
            {
                count = new int[1];
            }

            if (xyCmp == 0)
            {
                AddMagnitudes(count, One._magnitude);
                Array.Clear(X, xStart, X.Length - xStart);
            }

            return count;
        }

        private static int[] DoSubBigLil(int[] BigMag, int[] LilMag)
        {
            int[] res = (int[])BigMag.Clone();

            return Subtract(0, res, 0, LilMag);
        }

        private static BigInteger ExtEuclid(BigInteger A, BigInteger B, BigInteger U1Out, BigInteger U2Out)
        {
            // Calculate the numbers u1, u2, and u3 such that:
            // u1 * a + u2 * b = u3 where u3 is the greatest common divider of a and b.
            // a and b using the extended Euclid algorithm (refer p. 323 of The Art of Computer Programming vol 2, 2nd ed).
            // This also seems to have the side effect of calculating some form of multiplicative inverse.
            // param a First number to calculate gcd for
            // param b Second number to calculate gcd for
            // param u1Out the return object for the u1 value
            // param u2Out the return object for the u2 value
            // return The greatest common divisor of a and b

            BigInteger u1 = One;
            BigInteger u3 = A;
            BigInteger v1 = Zero;
            BigInteger v3 = B;

            while (v3._signum > 0)
            {
                BigInteger[] q = u3.DivideAndRemainder(v3);
                BigInteger tmp = v1.Multiply(q[0]);
                BigInteger tn = u1.Subtract(tmp);

                u1 = v1;
                v1 = tn;
                u3 = v3;
                v3 = q[1];
            }

            if (U1Out != null)
            {
                U1Out._signum = u1._signum;
                U1Out._magnitude = u1._magnitude;
            }

            if (U2Out != null)
            {
                BigInteger tmp = u1.Multiply(A);
                tmp = u3.Subtract(tmp);
                BigInteger res = tmp.Divide(B);
                U2Out._signum = res._signum;
                U2Out._magnitude = res._magnitude;
            }

            return u3;
        }

        private static long FastExtEuclid(long A, long B, long[] UOut)
        {
            long u1 = 1;
            long u3 = A;
            long v1 = 0;
            long v3 = B;

            while (v3 > 0)
            {
                long q, tn;

                q = u3 / v3;
                tn = u1 - (v1 * q);
                u1 = v1;
                v1 = tn;
                tn = u3 - (v3 * q);
                u3 = v3;
                v3 = tn;
            }

            UOut[0] = u1;
            UOut[1] = (u3 - (u1 * A)) / B;

            return u3;
        }

        private static long FastModInverse(long V, long M)
        {
            if (M < 1)
                throw new ArithmeticException("Modulus must be positive");

            long[] x = new long[2];
            long gcd = FastExtEuclid(V, M, x);

            if (gcd != 1)
                throw new ArithmeticException("Numbers not relatively prime.");

            if (x[0] < 0)
                x[0] += M;

            return x[0];
        }

        private BigInteger FlipExistingBit(int N)
        {
            Debug.Assert(_signum > 0);
            Debug.Assert(N >= 0);
            Debug.Assert(N < BitLength - 1);

            int[] mag = (int[])_magnitude.Clone();
            mag[mag.Length - 1 - (N >> 5)] ^= (1 << (N & 31)); // Flip bit

            return new BigInteger(_signum, mag, false);
        }

        private static int GetByteLength(int BitCount)
        {
            return (BitCount + BitsPerByte - 1) / BitsPerByte;
        }

        private long GetMQuote()
        {
            // Calculate mQuote = -m^(-1) mod b with b = 2^32 (32 = word size)
            Debug.Assert(_signum > 0);

            if (_mQuote != -1)
                return _mQuote; // already calculated

            if (_magnitude.Length == 0 || (_magnitude[_magnitude.Length - 1] & 1) == 0)
                return -1; // not for even numbers

            long v = (((~_magnitude[_magnitude.Length - 1]) | 1) & 0xffffffffL);
            _mQuote = FastModInverse(v, 0x100000000L);

            return _mQuote;
        }

        private BigInteger Inc()
        {
            if (_signum == 0)
                return One;

            if (_signum < 0)
                return new BigInteger(-1, DoSubBigLil(_magnitude, One._magnitude), true);

            return AddToMagnitude(One._magnitude);
        }

        private int[] LastNBits(int N)
        {
            if (N < 1)
                return _zeroMagnitude;

            int numWords = (N + BitsPerInt - 1) / BitsPerInt;
            numWords = System.Math.Min(numWords, _magnitude.Length);
            int[] result = new int[numWords];

            Array.Copy(_magnitude, _magnitude.Length - numWords, result, 0, numWords);

            int hiBits = N % 32;

            if (hiBits != 0)
                result[0] &= ~(-1 << hiBits);

            return result;
        }

        private static int[] MakeMagnitude(byte[] Bytes, int Offset, int Length)
        {
            int end = Offset + Length;

            // strip leading zeros
            int firstSignificant;

            for (firstSignificant = Offset; firstSignificant < end && Bytes[firstSignificant] == 0; firstSignificant++) { }

            if (firstSignificant >= end)
                return _zeroMagnitude;

            int nInts = (end - firstSignificant + 3) / BytesPerInt;
            int bCount = (end - firstSignificant) % BytesPerInt;

            if (bCount == 0)
                bCount = BytesPerInt;

            if (nInts < 1)
                return _zeroMagnitude;

            int[] mag = new int[nInts];
            int v = 0;
            int magnitudeIndex = 0;

            for (int i = firstSignificant; i < end; ++i)
            {
                v <<= 8;
                v |= Bytes[i] & 0xff;
                bCount--;
                if (bCount <= 0)
                {
                    mag[magnitudeIndex] = v;
                    magnitudeIndex++;
                    bCount = BytesPerInt;
                    v = 0;
                }
            }

            if (magnitudeIndex < mag.Length)
                mag[magnitudeIndex] = v;

            return mag;
        }

        private static int[] Multiply(int[] X, int[] Y, int[] Z)
        {
            // return x with x = y * z - x is assumed to have enough space.
            int i = Z.Length;

            if (i < 1)
                return X;

            int xBase = X.Length - Y.Length;

            do
            {
                long a = Z[--i] & IMASK;
                long val = 0;

                for (int j = Y.Length - 1; j >= 0; j--)
                {
                    val += a * (Y[j] & IMASK) + (X[xBase + j] & IMASK);

                    X[xBase + j] = (int)val;

                    val = (long)((ulong)val >> 32);
                }

                --xBase;

                if (i < 1)
                {
                    if (xBase >= 0)
                        X[xBase] = (int)val;
                    else
                        Debug.Assert(val == 0);

                    break;
                }

                X[xBase] = (int)val;
            } while (true);

            return X;
        }

        private static void MultiplyMonty(int[] A, int[] X, int[] Y, int[] M, long MQuote)
        {
            // Montgomery multiplication: a = x * y * R^(-1) mod m
            // Based algorithm 14.36 of Handbook of Applied Cryptography.
            // m, x, y should have length n
            // a should have length (n + 1)
            // b = 2^32, R = b^n
            // The result is put in x
            // NOTE: the indices of x, y, m, a different in HAC and in Java
            
            if (M.Length == 1)
            {
                X[0] = (int)MultiplyMontyNIsOne((uint)X[0], (uint)Y[0], (uint)M[0], (ulong)MQuote);
                return;
            }

            int n = M.Length;
            int nMinus1 = n - 1;
            long y_0 = Y[nMinus1] & IMASK;

            // 1. a = 0 (Notation: a = (a_{n} a_{n-1} ... a_{0})_{b} )
            Array.Clear(A, 0, n + 1);

            // 2. for i from 0 to (n - 1) do the following:
            for (int i = n; i > 0; i--)
            {
                long x_i = X[i - 1] & IMASK;
                // 2.1 u = ((a[0] + (x[i] * y[0]) * mQuote) mod b
                long u = ((((A[n] & IMASK) + ((x_i * y_0) & IMASK)) & IMASK) * MQuote) & IMASK;
                // 2.2 a = (a + x_i * y + u * m) / b
                long prod1 = x_i * y_0;
                long prod2 = u * (M[nMinus1] & IMASK);
                long tmp = (A[n] & IMASK) + (prod1 & IMASK) + (prod2 & IMASK);
                long carry = (long)((ulong)prod1 >> 32) + (long)((ulong)prod2 >> 32) + (long)((ulong)tmp >> 32);

                for (int j = nMinus1; j > 0; j--)
                {
                    prod1 = x_i * (Y[j - 1] & IMASK);
                    prod2 = u * (M[j - 1] & IMASK);
                    tmp = (A[j] & IMASK) + (prod1 & IMASK) + (prod2 & IMASK) + (carry & IMASK);
                    carry = (long)((ulong)carry >> 32) + (long)((ulong)prod1 >> 32) + (long)((ulong)prod2 >> 32) + (long)((ulong)tmp >> 32);
                    A[j + 1] = (int)tmp; // division by b
                }

                carry += (A[0] & IMASK);
                A[1] = (int)carry;
                A[0] = (int)((ulong)carry >> 32); // OJO!!!!!
            }

            // 3. if x >= m the x = x - m
            if (CompareTo(0, A, 0, M) >= 0)
                Subtract(0, A, 0, M);

            // put the result in x
            Array.Copy(A, 1, X, 0, n);
        }

        private static uint MultiplyMontyNIsOne(uint X, uint Y, uint M, ulong MQuote)
        {
            ulong um = M;
            ulong prod1 = (ulong)X * (ulong)Y;
            ulong u = (prod1 * MQuote) & UIMASK;
            ulong prod2 = u * um;
            ulong tmp = (prod1 & UIMASK) + (prod2 & UIMASK);
            ulong carry = (prod1 >> 32) + (prod2 >> 32) + (tmp >> 32);

            if (carry > um)
                carry -= um;

            return (uint)(carry & UIMASK);
        }

        private bool QuickPow2Check()
        {
            return _signum > 0 && _nBits == 1;
        }

        internal bool RabinMillerTest(int Certainty, SecureRandom SecRand)
        {
            Debug.Assert(Certainty > 0);
            Debug.Assert(BitLength > 2);
            Debug.Assert(TestBit(0));

            // let n = 1 + d . 2^s
            BigInteger n = this;
            BigInteger nMinusOne = n.Subtract(One);
            int s = nMinusOne.GetLowestSetBit();
            BigInteger r = nMinusOne.ShiftRight(s);

            Debug.Assert(s >= 1);

            do
            {
                // TODO Make a method for SecureRandom BigIntegers in range 0 < x < n)
                // - Method can be optimized by only replacing examined bits at each trial
                BigInteger a;
                do
                {
                    a = new BigInteger(n.BitLength, SecRand);
                }
                while (a.CompareTo(One) <= 0 || a.CompareTo(nMinusOne) >= 0);

                BigInteger y = a.ModPow(r, n);

                if (!y.Equals(One))
                {
                    int j = 0;
                    while (!y.Equals(nMinusOne))
                    {
                        if (++j == s)
                            return false;

                        y = y.ModPow(Two, n);

                        if (y.Equals(One))
                            return false;
                    }
                }

                Certainty -= 2; // composites pass for only 1/4 possible 'a'
            }
            while (Certainty > 0);

            return true;
        }

        private int Remainder(int M)
        {
            Debug.Assert(M > 0);

            long acc = 0;

            for (int pos = 0; pos < _magnitude.Length; ++pos)
            {
                long posVal = (uint)_magnitude[pos];
                acc = (acc << 32 | posVal) % M;
            }

            return (int)acc;
        }

        private int[] Remainder(int[] X, int[] Y)
        {
            // return x = x % y - done in place (y value preserved)
            int xStart = 0;
            int yStart = 0;

            while (xStart < X.Length && X[xStart] == 0)
                ++xStart;

            while (yStart < Y.Length && Y[yStart] == 0)
                ++yStart;

            Debug.Assert(yStart < Y.Length);

            int xyCmp = CompareNoLeadingZeroes(xStart, X, yStart, Y);

            if (xyCmp > 0)
            {
                int yBitLength = CalcBitLength(yStart, Y);
                int xBitLength = CalcBitLength(xStart, X);
                int shift = xBitLength - yBitLength;
                int[] c;
                int cStart = 0;
                int cBitLength = yBitLength;

                if (shift > 0)
                {
                    c = ShiftLeft(Y, shift);
                    cBitLength += shift;
                    Debug.Assert(c[0] != 0);
                }
                else
                {
                    int len = Y.Length - yStart;
                    c = new int[len];
                    Array.Copy(Y, yStart, c, 0, len);
                }

                do
                {
                    if (cBitLength < xBitLength || CompareNoLeadingZeroes(xStart, X, cStart, c) >= 0)
                    {
                        Subtract(xStart, X, cStart, c);

                        while (X[xStart] == 0)
                        {
                            if (++xStart == X.Length)
                                return X;
                        }

                        xBitLength = 32 * (X.Length - xStart - 1) + BitLen(X[xStart]);

                        if (xBitLength <= yBitLength)
                        {
                            if (xBitLength < yBitLength)
                                return X;

                            xyCmp = CompareNoLeadingZeroes(xStart, X, yStart, Y);

                            if (xyCmp <= 0)
                                break;
                        }
                    }

                    shift = cBitLength - xBitLength;

                    // NB: The case where c[cStart] is 1-bit is harmless
                    if (shift == 1)
                    {
                        uint firstC = (uint)c[cStart] >> 1;
                        uint firstX = (uint)X[xStart];
                        if (firstC > firstX)
                            ++shift;
                    }

                    if (shift < 2)
                    {
                        ShiftRightOneInPlace(cStart, c);
                        --cBitLength;
                    }
                    else
                    {
                        ShiftRightInPlace(cStart, c, shift);
                        cBitLength -= shift;
                    }

                    while (c[cStart] == 0)
                        ++cStart;
                    
                } while (true);
            }

            if (xyCmp == 0)
                Array.Clear(X, xStart, X.Length - xStart);

            return X;
        }

        private static int[] ShiftLeft(int[] Magnitude, int N)
        {
            // do a left shift - this returns a new array.
            int nInts = (int)((uint)N >> 5);
            int nBits = N & 0x1f;
            int magLen = Magnitude.Length;
            int[] newMag;

            if (nBits == 0)
            {
                newMag = new int[magLen + nInts];
                Magnitude.CopyTo(newMag, 0);
            }
            else
            {
                int i = 0;
                int nBits2 = 32 - nBits;
                int highBits = (int)((uint)Magnitude[0] >> nBits2);

                if (highBits != 0)
                {
                    newMag = new int[magLen + nInts + 1];
                    newMag[i++] = highBits;
                }
                else
                {
                    newMag = new int[magLen + nInts];
                }

                int m = Magnitude[0];

                for (int j = 0; j < magLen - 1; j++)
                {
                    int next = Magnitude[j + 1];

                    newMag[i++] = (m << nBits) | (int)((uint)next >> nBits2);
                    m = next;
                }

                newMag[i] = Magnitude[magLen - 1] << nBits;
            }

            return newMag;
        }

        private static void ShiftRightInPlace(int Start, int[] Magnitude, int N)
        {
            // do a right shift - this does it in place.
            int nInts = (int)((uint)N >> 5) + Start;
            int nBits = N & 0x1f;
            int magEnd = Magnitude.Length - 1;

            if (nInts != Start)
            {
                int delta = (nInts - Start);

                for (int i = magEnd; i >= nInts; i--)
                    Magnitude[i] = Magnitude[i - delta];
                
                for (int i = nInts - 1; i >= Start; i--)
                    Magnitude[i] = 0;
            }

            if (nBits != 0)
            {
                int nBits2 = 32 - nBits;
                int m = Magnitude[magEnd];

                for (int i = magEnd; i > nInts; --i)
                {
                    int next = Magnitude[i - 1];

                    Magnitude[i] = (int)((uint)m >> nBits) | (next << nBits2);
                    m = next;
                }

                Magnitude[nInts] = (int)((uint)Magnitude[nInts] >> nBits);
            }
        }

        private static void ShiftRightOneInPlace(int Start, int[] Magnitude)
        {
            // do a right shift by one - this does it in place.
            int i = Magnitude.Length;
            int m = Magnitude[i - 1];

            while (--i > Start)
            {
                int next = Magnitude[i - 1];
                Magnitude[i] = ((int)((uint)m >> 1)) | (next << 31);
                m = next;
            }

            Magnitude[Start] = (int)((uint)Magnitude[Start] >> 1);
        }

        private static int[] Square(int[] W, int[] X)
        {
            // return w with w = x * x - w is assumed to have enough space.
            // Note: this method allows w to be only (2 * x.Length - 1) words if result will fit
            // if (w.Length != 2 * x.Length) throw new ArgumentException("no I don't think so...");

            ulong u1, u2, c;
            int wBase = W.Length - 1;

            for (int i = X.Length - 1; i != 0; i--)
            {
                ulong v = (ulong)(uint)X[i];

                u1 = v * v;
                u2 = u1 >> 32;
                u1 = (uint)u1;
                u1 += (ulong)(uint)W[wBase];

                W[wBase] = (int)(uint)u1;
                c = u2 + (u1 >> 32);

                for (int j = i - 1; j >= 0; j--)
                {
                    --wBase;
                    u1 = v * (ulong)(uint)X[j];
                    u2 = u1 >> 31; // multiply by 2!
                    u1 = (uint)(u1 << 1); // multiply by 2!
                    u1 += c + (ulong)(uint)W[wBase];
                    W[wBase] = (int)(uint)u1;
                    c = u2 + (u1 >> 32);
                }

                c += (ulong)(uint)W[--wBase];
                W[wBase] = (int)(uint)c;

                if (--wBase >= 0)
                    W[wBase] = (int)(uint)(c >> 32);
                else
                    Debug.Assert((uint)(c >> 32) == 0);
                
                wBase += i;
            }

            u1 = (ulong)(uint)X[0];
            u1 = u1 * u1;
            u2 = u1 >> 32;
            u1 = u1 & IMASK;
            u1 += (ulong)(uint)W[wBase];
            W[wBase] = (int)(uint)u1;

            if (--wBase >= 0)
                W[wBase] = (int)(uint)(u2 + (u1 >> 32) + (ulong)(uint)W[wBase]);
            else
                Debug.Assert((uint)(u2 + (u1 >> 32)) == 0);

            return W;
        }

        private static int[] Subtract(int XStart, int[] X, int YStart, int[] Y)
        {
            // returns x = x - y - we assume x is >= y
            Debug.Assert(YStart < Y.Length);
            Debug.Assert(X.Length - XStart >= Y.Length - YStart);

            int iT = X.Length;
            int iV = Y.Length;
            long m;
            int borrow = 0;

            do
            {
                m = (X[--iT] & IMASK) - (Y[--iV] & IMASK) + borrow;
                X[iT] = (int)m;

                // borrow = (m < 0) ? -1 : 0;
                borrow = (int)(m >> 63);
            }
            while (iV > YStart);

            if (borrow != 0)
                while (--X[--iT] == -1) { }

            return X;
        }

        private byte[] ToByteArray(bool Unsigned)
        {
            if (_signum == 0)
                return Unsigned ? _zeroEncoding : new byte[1];

            int nBits = (Unsigned && _signum > 0) ? BitLength : BitLength + 1;
            int nBytes = GetByteLength(nBits);
            byte[] bytes = new byte[nBytes];
            int magIndex = _magnitude.Length;
            int bytesIndex = bytes.Length;

            if (_signum > 0)
            {
                while (magIndex > 1)
                {
                    uint mag = (uint)_magnitude[--magIndex];
                    bytes[--bytesIndex] = (byte)mag;
                    bytes[--bytesIndex] = (byte)(mag >> 8);
                    bytes[--bytesIndex] = (byte)(mag >> 16);
                    bytes[--bytesIndex] = (byte)(mag >> 24);
                }

                uint lastMag = (uint)_magnitude[0];
                while (lastMag > byte.MaxValue)
                {
                    bytes[--bytesIndex] = (byte)lastMag;
                    lastMag >>= 8;
                }

                bytes[--bytesIndex] = (byte)lastMag;
            }
            else // sign < 0
            {
                bool carry = true;

                while (magIndex > 1)
                {
                    uint mag = ~((uint)_magnitude[--magIndex]);

                    if (carry)
                        carry = (++mag == uint.MinValue);

                    bytes[--bytesIndex] = (byte)mag;
                    bytes[--bytesIndex] = (byte)(mag >> 8);
                    bytes[--bytesIndex] = (byte)(mag >> 16);
                    bytes[--bytesIndex] = (byte)(mag >> 24);
                }

                uint lastMag = (uint)_magnitude[0];

                if (carry) // Never wraps because magnitude[0] != 0
                    --lastMag;

                while (lastMag > byte.MaxValue)
                {
                    bytes[--bytesIndex] = (byte)~lastMag;
                    lastMag >>= 8;
                }

                bytes[--bytesIndex] = (byte)~lastMag;

                if (bytesIndex > 0)
                    bytes[--bytesIndex] = byte.MaxValue;
            }

            return bytes;
        }

        private static void ZeroOut(int[] X)
        {
            Array.Clear(X, 0, X.Length);
        }
        #endregion
    }
}
