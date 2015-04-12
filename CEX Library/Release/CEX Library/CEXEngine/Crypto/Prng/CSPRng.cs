#region Directives
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
// An implementation of a Cryptographically Secure Psuedo Random Number Generator (RCSP). 
// Uses the <see href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</see> class to produce pseudo random output.
// Written by John Underhill, January 6, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// <h3>An implementation of a Cryptographically Secure PRNG using the RNGCryptoServiceProvider class.</h3>
    /// <para>Implements a random number generator using the RNGCryptoServiceProvider<cite>RNGCryptoServiceProvider</cite> class</para>
    /// </summary>
    /// 
    /// <example>
    /// <code>
    /// int x;
    /// using (IRandom rnd = new CSPRng())
    ///     x = rnd.Next();
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    ///     <revision date="2015/01/23" version="1.3.0.0" author="John Underhill">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <description><h4>Guiding Publications:</h4>:</description>
    /// <list type="number">
    /// <item><description>RNGCryptoServiceProvider<cite>RNGCryptoServiceProvider</cite> class documentation.</description></item>
    /// <item><description>NIST SP800-90B: <cite>SP800-90B</cite>Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST Fips 140-2: <cite>Fips 140-2</cite>Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>RFC 4086: <cite>RFC 4086</cite>Randomness Requirements for Security.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class CSPRng : IRandom, IDisposable
    {
        #region Constants
        private const string ALG_NAME = "CSPRng";
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private RNGCryptoServiceProvider _rngCrypto;
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
        public CSPRng()
        {
            _rngCrypto = new RNGCryptoServiceProvider();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CSPRng()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Fill an array with cryptographically secure pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>Random byte array</returns>
        public byte[] GetBytes(int Size)
        {
            byte[] data = new byte[Size];

            _rngCrypto.GetBytes(data);

            return data;
        }

        /// <summary>
        /// Fill an array with cryptographically secure pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Data">Array to fill with random bytes</param>
        public void GetBytes(byte[] Data)
        {
            _rngCrypto.GetBytes(Data);
        }

        /// <summary>
        /// Get a cryptographically secure pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public int Next()
        {
            return BitConverter.ToInt32(GetBytes(4), 0);
        }

        /// <summary>
        /// Get a cryptographically secure pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        public Int64 NextLong()
        {
            return BitConverter.ToInt64(GetBytes(8), 0);
        }

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
