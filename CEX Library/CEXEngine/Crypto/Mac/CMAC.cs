#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
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
// Implementation Details:
// An implementation of a Cipher based Message Authentication Code (CMAC).
// Written by John Underhill, January 10, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Mac
{
    /// <summary>
    /// <h5>CMAC: An implementation of a Cipher based Message Authentication Code: CMAC.</h5>
    /// <para>A CMAC as outlined in the NIST document: SP800-38B<cite>SP800-38B</cite></para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>IMac</c> interface:</description>
    /// <code>
    /// using (IMac mac = new CMAC(new RDX(), [DisposeEngine]))
    /// {
    ///     // initialize
    ///     mac.Initialize(KeyParams);
    ///     // get mac
    ///     Output = mac.ComputeMac(Input);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">VTDev.Libraries.CEXEngine.Crypto.Engines Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>MAC return size must be a divisible of 8.</description></item>
    /// <item><description>MAC return size can be no longer than the Cipher Block size.</description></item>
    /// <item><description>Valid Cipher block sizes are 8 and 16 byte wide.</description></item>
    /// <item><description>The <see cref="CMAC(IBlockCipher, int, bool)">Constructors</see> DisposeEngine parameter determines if Cipher engine is destroyed when <see cref="Dispose()"/> is called on this class; default is <c>true</c>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>NIST SP800-38B: <see href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">The CMAC Mode for Authentication</see>.</description></item>
    /// <item><description>RFC 4493: <see href="http://tools.ietf.org/html/rfc4493">The AES-CMAC Algorithm</see>.</description></item>
    /// <item><description>RFC 4494: <see href="http://tools.ietf.org/html/rfc4494">The AES-CMAC-96 Algorithm and Its Use with IPsec</see>.</description></item>
    /// <item><description>RFC 4493: <see href="http://tools.ietf.org/html/rfc4615">The AES-CMAC-PRF-128 Algorithm for the Internet Key Exchange Protocol (IKE)</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class CMAC : IMac
    {
        #region Constants
        private const string ALG_NAME = "CMAC";
        private const byte CONST_128 = (byte)0x87;
        private const byte CONST_64 = (byte)0x1b;
        #endregion

        #region Fields
        private int _blockSize = 0;
        private KeyParams _cipherKey;
        private ICipherMode _cipherMode;
        private bool _disposeEngine = true;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private int _macSize;
        private byte[] _msgCode;
        private byte[] _wrkBuffer;
        private int _wrkOffset;
        private byte[] _K1, _K2;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The Macs internal blocksize in bytes
        /// </summary>
        public int BlockSize
        {
            get { return _blockSize; }
            set { _blockSize = value; }
        }

        /// <summary>
        /// Get: The macs type name
        /// </summary>
        public Macs Enumeral
        {
            get { return Macs.CMAC; }
        }

        /// <summary>
        /// Get: Mac is ready to digest data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get: Size of returned mac in bytes
        /// </summary>
        public int MacSize
        {
            get { return _macSize; }
        }

        /// <summary>
        /// Get: Algorithm name
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
        /// <param name="Cipher">Instance of the block cipher</param>
        /// <param name="MacBits">Expected MAC return size in Bits; must be less or equal to Cipher Block size in bits</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Mac or block size is used</exception>
        public CMAC(IBlockCipher Cipher, int MacBits, bool DisposeEngine = true)
        {
            if ((MacBits % 8) != 0)
                throw new CryptoMacException("CMAC:Ctor", "MAC size must be multiple of 8!", new ArgumentOutOfRangeException());
            if (MacBits > (Cipher.BlockSize * 8))
                throw new CryptoMacException("CMAC:Ctor", String.Format("MAC size must be less or equal to {0}!", Cipher.BlockSize * 8), new ArgumentOutOfRangeException());
            if (Cipher.BlockSize != 8 && Cipher.BlockSize != 16)
                throw new CryptoMacException("CMAC:Ctor", "Block size must be either 64 or 128 bits!", new ArgumentException());

            _disposeEngine = DisposeEngine;
            _cipherMode = new CBC(Cipher);
            _blockSize = _cipherMode.BlockSize;
            _macSize = MacBits / 8;
            _msgCode = new byte[_blockSize];
            _wrkBuffer = new byte[_blockSize];
            _wrkOffset = 0;
        }

        private CMAC()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CMAC()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Update the buffer
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// <param name="InOffset">Offset within Input array</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
        public void BlockUpdate(byte[] Input, int InOffset, int Length)
        {
            if ((InOffset + Length) > Input.Length)
                throw new CryptoMacException("CMAC:BlockUpdate", "The Input buffer is too short!", new ArgumentOutOfRangeException());

            if (_wrkOffset == _blockSize)
            {
                _cipherMode.Transform(_wrkBuffer, 0, _msgCode, 0);
                _wrkOffset = 0;
            }

            int diff = _blockSize - _wrkOffset;
            if (Length > diff)
            {
                Buffer.BlockCopy(Input, InOffset, _wrkBuffer, _wrkOffset, diff);
                _cipherMode.Transform(_wrkBuffer, 0, _msgCode, 0);
                _wrkOffset = 0;
                Length -= diff;
                InOffset += diff;

                while (Length > _blockSize)
                {
                    _cipherMode.Transform(Input, InOffset, _msgCode, 0);
                    Length -= _blockSize;
                    InOffset += _blockSize;
                }
            }

            if (Length > 0)
            {
                Buffer.BlockCopy(Input, InOffset, _wrkBuffer, _wrkOffset, Length);
                _wrkOffset += Length;
            }
        }

        /// <summary>
        /// Get the Mac hash value
        /// </summary>
        /// 
        /// <param name="Input">Input data</param>
        /// 
        /// <returns>Mac Hash value</returns>
        public byte[] ComputeMac(byte[] Input)
        {
            if (!_isInitialized)
                throw new CryptoGeneratorException("CMAC:ComputeMac", "The Mac is not initialized!", new InvalidOperationException());

            byte[] hash = new byte[_macSize];

            BlockUpdate(Input, 0, Input.Length);
            DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Process the last block of data
        /// </summary>
        /// 
        /// <param name="Output">The hash value return</param>
        /// <param name="OutOffset">The offset in the data</param>
        /// 
        /// <returns>The number of bytes processed</returns>
        /// 
        /// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
        public int DoFinal(byte[] Output, int OutOffset)
        {
            if (Output.Length - OutOffset < _macSize)
                throw new CryptoMacException("CMAC:DoFinal", "The Output buffer is too short!", new ArgumentOutOfRangeException());

            if (_wrkOffset != _blockSize)
	        {
		        ISO7816 pad =  new ISO7816();
		        pad.AddPadding(_wrkBuffer, _wrkOffset);
                for (int i = 0; i < _msgCode.Length; i++)
                    _wrkBuffer[i] ^= _K2[i];
	        }
	        else
	        {
                for (int i = 0; i < _msgCode.Length; i++)
                    _wrkBuffer[i] ^= _K1[i];
	        }

	        _cipherMode.Transform(_wrkBuffer, 0, _msgCode, 0);
            Buffer.BlockCopy(_msgCode, 0, Output, OutOffset, _macSize);
	        Reset();

            return _macSize;
        }

        /// <summary>
        /// Initialize the Cipher MAC.
        /// <para>Uses the Key or IKM field, and optionally the IV field of the KeyParams class.</para>
        /// </summary>
        /// 
        /// <param name="MacKey">A byte array containing the cipher Key. 
        /// <para>Key size must be one of the <c>LegalKeySizes</c> of the underlying cipher.</para>
        /// </param>
        /// <param name="IV">A byte array containing the cipher Initialization Vector.
        /// <para>IV size must be the ciphers blocksize.</para></param>
        /// 
        /// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
        public void Initialize(byte[] MacKey, byte[] IV)
        {
            if (MacKey == null)
                throw new CryptoMacException("CMAC:Initialize", "Key can not be null!", new ArgumentNullException());

            if (IV == null)
                IV = new byte[_blockSize];
            if (IV.Length != _blockSize)
                Array.Resize<byte>(ref IV, _blockSize);

            _cipherKey =  new KeyParams(MacKey, IV);
	        _cipherMode.Initialize(true, _cipherKey);
            byte[] lu = new byte[_blockSize];
	        byte[] tmpz = new byte[_blockSize];
	        _cipherMode.Transform(tmpz, 0, lu, 0);
	        _K1 = GenerateSubkey(lu);
	        _K2 = GenerateSubkey(_K1);
	        _cipherMode.Initialize(true, _cipherKey);
	        _isInitialized = true;
        }

        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Reset()
        {
            _cipherMode.Initialize(true, _cipherKey);
            Array.Clear(_wrkBuffer, 0, _wrkBuffer.Length);
            _wrkOffset = 0;
        }

        /// <summary>
        /// Update the digest with a single byte
        /// </summary>
        /// 
        /// <param name="Input">Input byte</param>
        public void Update(byte Input)
        {
            if (_wrkOffset == _wrkBuffer.Length)
            {
                _cipherMode.Transform(_wrkBuffer, 0, _msgCode, 0);
                _wrkOffset = 0;
            }

            _wrkBuffer[_wrkOffset++] = Input;
        }
        #endregion

        #region Private Methods
        private byte[] GenerateSubkey(byte[] Input)
        {
            int firstBit = (Input[0] & 0xFF) >> 7;
            byte[] ret = new byte[Input.Length];

            for (int i = 0; i < Input.Length - 1; i++)
                ret[i] = (byte)((Input[i] << 1) + ((Input[i + 1] & 0xFF) >> 7));
            
            ret[Input.Length - 1] = (byte)(Input[Input.Length - 1] << 1);

            if (firstBit == 1)
                ret[Input.Length - 1] ^= Input.Length == _blockSize ? CONST_128 : CONST_64;
            
            return ret;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class, and dependant resources
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
                    if (_cipherMode != null && _disposeEngine)
                    {
                        _cipherMode.Dispose();
                        _cipherMode = null;
                    }
                    if (_msgCode != null)
                    {
                        Array.Clear(_msgCode, 0, _msgCode.Length);
                        _msgCode = null;
                    }
                    if (_wrkBuffer != null)
                    {
                        Array.Clear(_wrkBuffer, 0, _wrkBuffer.Length);
                        _wrkBuffer = null;
                    }
                    if (_K1 != null)
                    {
                        Array.Clear(_K1, 0, _K1.Length);
                        _K1 = null;
                    }
                    if (_K2 != null)
                    {
                        Array.Clear(_K2, 0, _K2.Length);
                        _K2 = null;
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
