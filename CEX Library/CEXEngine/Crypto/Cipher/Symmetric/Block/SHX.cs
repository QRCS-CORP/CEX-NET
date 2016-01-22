#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
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
// Principal Algorithms:
// Portions of this cipher based on Serpent written by Ross Anderson, Eli Biham and Lars Knudsen:
// Serpent <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</see>.
// 
// The sboxes are based on the work of Brian Gladman and Sam Simpson.
// <see href="http://fp.gladman.plus.com/cryptography_technology/serpent/">Specification</see>.
// Copyright: Dr B. R Gladman (gladman@seven77.demon.co.uk) and 
// Sam Simpson (s.simpson@mia.co.uk), 17th December 1998.
// 
// Implementation Details:
// An implementation based on the Serpent block cipher,
// using HKDF with a selectable Message Digest for expanded key generation.
// Serpent HKDF Extended (SHX)
// Written by John Underhill, November 15, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block
{
    /// <summary>
    /// <h5>SHX: A Serpent cipher extended with an (optional) HKDF powered Key Schedule.</h5>
    /// <para>SHX is a Serpent<cite>Serpent</cite> implementation that can use a standard configuration on key sizes up to 256 bits, 
    /// an extended key size of 512 bits, or unlimited key sizes greater than 64 bytes. 
    /// On <see cref="LegalKeySizes"/> larger than 64 bytes, an HKDF bytes generator is used to expand the <c>working key</c> integer array.
    /// In extended mode, the number of <c>transformation rounds</c> can be user assigned (through the constructor) to between 32 and 64 rounds.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using an <c>ICipherMode</c> interface:</description>
    /// <code>
    /// using (ICipherMode cipher = new CTR(new SHX()))
    /// {
    ///     // initialize for encryption
    ///     cipher.Initialize(true, new KeyParams(Key, IV));
    ///     // encrypt a block
    ///     cipher.Transform(Input, Output);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2014/09/18" version="1.2.0.0">Initial release using a fixed Digest key schedule generator</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Secondary release using an assignable Digest in the HKDF engine</revision>
    /// <revision date="2015/03/15" version="1.3.2.0">Added the IkmSize optional parameter to the constructor, and the DistributionCode property</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// <revision date="2016/01/21" version="1.5.0.0">Merged SPX and SHX implementations</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers">VTDev.Libraries.CEXEngine.Crypto.Enumeration BlockCiphers Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.CipherModes">VTDev.Libraries.CEXEngine.Crypto.Enumeration CipherModes Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Generator.HKDF">VTDev.Libraries.CEXEngine.Crypto.Generator HKDF Generator</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode ICipherMode Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest IDigest Interface</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description><see cref="HKDF">HKDF</see> Digest <see cref="Digests">engine</see> is definable through the <see cref="SHX(int, Digests)">Constructor</see> parameter: KeyEngine.</description></item>
    /// <item><description>Key Schedule is (optionally) powered by a Hash based Key Derivation Function using a definable <see cref="IDigest">Digest</see>.</description></item>
    /// <item><description>Minimum HKDF key size is (IKm + Salt) (N * Digest State Size) + (Digest Hash Size) in bytes.</description></item>
    /// <item><description>Valid block size is 16 bytes wide.</description></item>
    /// <item><description>Valid Rounds assignments are set at 32 in standard mode, and 32, 40, 48, 56, and 64 in extended mode.</description></item>
    /// </list>
    /// 
    /// <para>It also takes a user defined number of rounds between 32 (the standard number of rounds), all the way up to 128 rounds in 8 round sets. 
    /// A round count of 40 or 48 is more than sufficient, as theoretical attacks to date are only able to break up to 12 rounds; and would require an enormous amount of memory and processing power.
    /// The transform in SHX is identical to the Serpent implementation SPX, it process rounds by first moving the byte input array into 4 integers, then processing the rounds in a while loop. 
    /// Each round consists of an XOR of each state word (<math>Rn</math>) with a key, an S-Box transformation of those words, and then a linear transformation. 
    /// Each of the 8 S-Boxes are used in succession within a loop cycle. The final round XORs the last 4 keys with the state and shifts them back into the output byte array.</para>
    /// 
    /// <para>The key schedule in SHX powered by an HKDF<cite>RFC 5869</cite> generator, using a Digest HMAC<cite>RFC 2104</cite> (Hash based Message Authentication Code) as its random engine. 
    /// This is one of the strongest<cite>Fips 198-1</cite> methods available for generating pseudo-random keying material, and far superior in entropy dispersion to Rijndael, or even Serpents key schedule. HKDF uses up to three inputs; a nonce value called an information string, an Ikm (Input keying material), and a Salt value. 
    /// The HMAC RFC 2104, recommends a key size equal to the digest output, in the case of SHA512, 64 bytes, anything larger gets passed through the hash function to get the required 512 bit key size. 
    /// The Salt size is a minimum of the hash functions block size, with SHA-2 512 that is 128 bytes.</para>
    /// 
    /// <para>When using SHA-2 512, a minimum key size for SHX is 192 bytes, further blocks of salt can be added to the key so long as they align; ikm + (n * blocksize), ex. 192, 320, 448 bytes.. there is no upper maximum. 
    /// This means that you can create keys as large as you like so long as it falls on these boundaries, this effectively eliminates brute force as a means of attack on the cipher, even in quantum terms.</para> 
    /// 
    /// <para>The Digest that powers HKDF, can be any one of the Hash Digests implemented in the CEX library; Blake<cite>Blake</cite>, Keccak<cite>Keccak</cite>, SHA-2<cite>Fips 180-4</cite>, or Skein<cite>Skein</cite>.
    /// The default Digest Engine is SHA-2 512.</para>
    /// 
    /// <para>The legal key sizes are determined by a combination of the (Hash Size + a Multiplier * the Digest State Size); <math>klen = h + (n * s)</math>, this will vary between Digest implementations. 
    /// Correct key sizes can be determined at runtime using the <see cref="LegalKeySizes"/> property.</para>
    /// 
    /// <para>The number of diffusion rounds processed within the ciphers rounds function can also be defined; adding rounds creates a more diffused cipher output, making the resulting cipher-text more difficult to cryptanalyze. 
    /// SHX is capable of processing up to 128 rounds, that is four times the number of rounds used in a standard implementation of Serpent. 
    /// Valid rounds assignments can be found in the <see cref="LegalRounds"/> static property.</para>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Serpent: <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</see>.</description></item>
    /// <item><description>HMAC: <see href="http://tools.ietf.org/html/rfc2104">RFC 2104</see>.</description></item>
    /// <item><description>Fips: <see href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198.1</see>.</description></item>
    /// <item><description>HKDF: <see href="http://tools.ietf.org/html/rfc5869">RFC 5869</see>.</description></item>
    /// <item><description>NIST: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</see>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired in part by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class SHX : IBlockCipher
    {
        #region Constants
        private const string ALG_NAME = "SHX";
        private const int BLOCK_SIZE = 16;
        private const int ROUNDS32 = 32;
        private const int LEGAL_KEYS = 10;
        private const int MAX_ROUNDS = 128;
        private const int MAX_STDKEY = 64;
        private const int MIN_ROUNDS = 32;
        private const UInt32 PHI = 0x9E3779B9;
        #endregion

        #region Fields
        private int _dfnRounds = MIN_ROUNDS;
        private UInt32[] _expKey;
        // configurable nonce can create a unique distribution, can be byte(0)
        private byte[] _hkdfInfo = System.Text.Encoding.ASCII.GetBytes("SHX version 1 information string");
        private IDigest _keyEngine;
        private bool _isDisposed = false;
        private bool _isEncryption;
        private int _ikmSize = 0;
        private bool _isInitialized = false;
        private Digests _keyEngineType;
        private int[] _legalKeySizes = new int[LEGAL_KEYS];
        #endregion

        #region Properties
        /// <summary>
        /// Get: Unit block size of internal cipher.
        /// <para>Block size is 16 bytes wide.</para>
        /// </summary>
        public int BlockSize
        {
            get { return BLOCK_SIZE; }
        }

        /// <summary>
        /// Get/Set: Sets the Info value in the HKDF initialization parameters. 
        /// <para>Must be set before <see cref="Initialize(bool, KeyParams)"/> is called.
        /// Changing this code will create a unique distribution of the cipher.
        /// Code can be either a zero byte array, or a multiple of the HKDF digest engines return size.</para>
        /// </summary>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid distribution code is used</exception>
        public byte[] DistributionCode
        {
            get { return _hkdfInfo; }
            set
            {
                if (value == null)
                    throw new CryptoSymmetricException("SHX:DistributionCode", "Distribution Code can not be null!", new ArgumentNullException());

                _hkdfInfo = value;
            }
        }

        /// <summary>
        /// Get: The block ciphers type name
        /// </summary>
        public BlockCiphers Enumeral
        {
            get { return BlockCiphers.SHX; }
        }

        /// <summary>
        /// Get/Set: Specify the size of the HMAC key; extracted from the cipher key.
        /// <para>This property can only be changed before the Initialize function is called.</para>
        /// <para>Default is the digest return size; can only be a multiple of that length.
        /// Maximum size is the digests underlying block size; if the key
        /// is longer than this, the size will default to the block size.</para>
        /// </summary>
        public int IkmSize
        {
            get { return _ikmSize; }
            set
            {
                if (value == 0)
                    _ikmSize = _keyEngine.DigestSize;
                if (value < _keyEngine.DigestSize)
                    _ikmSize = _keyEngine.DigestSize;
                else if (value > _keyEngine.BlockSize)
                    _ikmSize = _keyEngine.BlockSize;
                else if (value % _keyEngine.DigestSize > 0)
                    _ikmSize = value - (value % _keyEngine.DigestSize);
                else
                    _ikmSize = _keyEngine.DigestSize;
            }
        }

        /// <summary>
        /// Get: Cipher is initialized for encryption, false for decryption.
        /// <para>Value set in <see cref="Initialize(bool, KeyParams)"/>.</para>
        /// </summary>
        public bool IsEncryption
        {
            get { return _isEncryption; }
            private set { _isEncryption = value; }
        }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        public bool IsInitialized
        {
            get { return _isInitialized; }
            private set { _isInitialized = value; }
        }

        /// <summary>
        /// Get: Available block sizes for this cipher
        /// </summary>
        public int[] LegalBlockSizes
        {
            get { return new int[] { 16 }; }
        }

        /// <summary>
        /// Get: Available Encryption Key Sizes in bytes
        /// </summary>
        public int[] LegalKeySizes
        {
            get { return _legalKeySizes; }
            private set { _legalKeySizes = value; }
        }

        /// <summary>
        /// Get: Available diffusion round assignments
        /// </summary>
        public int[] LegalRounds
        {
            get { return new int[] { 32, 40, 48, 56, 64, 80, 96, 128 }; }
        }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: The number of diffusion rounds processed by the transform
        /// </summary>
        public int Rounds
        {
            get { return _dfnRounds; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 32 rounds.</param>
        /// <param name="KeyEngine">The Key Schedule KDF digest engine; can be any one of the <see cref="Digests">Digest</see> implementations. The default engine is <see cref="SHA512"/>.</param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if an invalid rounds count is chosen</exception>
        public SHX(int Rounds = ROUNDS32, Digests KeyEngine = Digests.SHA512)
        {
            if (Rounds != 32 && Rounds != 40 && Rounds != 48 && Rounds != 56 && Rounds != 64 && Rounds != 80 && Rounds != 96 && Rounds != 128)
                throw new CryptoSymmetricException("SHX:CTor", "Invalid rounds size! Sizes supported are 32, 40, 48, 56, 64, 80, 96 and 128.", new ArgumentOutOfRangeException());

            _keyEngineType = KeyEngine;
            // set the hmac key size
            _ikmSize = _ikmSize == 0 ? GetIkmSize(KeyEngine) : _ikmSize;
            // add standard key lengths
            _legalKeySizes[0] = 16;
            _legalKeySizes[1] = 24;
            _legalKeySizes[2] = 32;
            _legalKeySizes[3] = 64;

            int dgtblock = GetSaltSize(KeyEngine);

            // hkdf extended key sizes
            for (int i = 4; i < _legalKeySizes.Length; ++i)
                _legalKeySizes[i] = (dgtblock * (i - 3)) + _ikmSize;

            _dfnRounds = Rounds;
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SHX()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a single block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
        /// Input and Output arrays must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        public void DecryptBlock(byte[] Input, byte[] Output)
        {
            Decrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Decrypt a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
        /// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            Decrypt16(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Encrypt a block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
        /// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        public void EncryptBlock(byte[] Input, byte[] Output)
        {
            Encrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Encrypt a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
        /// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            Encrypt16(Input, InOffset, Output, OutOffset);
        }

        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// 
        /// <param name="Encryption">Using Encryption or Decryption mode</param>
        /// <param name="KeyParam">Cipher key container.<para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
        /// 
        /// <exception cref="CryptoSymmetricException">Thrown if a null or invalid key is used</exception>
        public void Initialize(bool Encryption, KeyParams KeyParam)
        {
            if (KeyParam.Key == null)
                throw new CryptoSymmetricException("SHX:Initialize", "Invalid key! Key can not be null.", new ArgumentNullException());
            if (KeyParam.Key.Length > LegalKeySizes[3] && (KeyParam.Key.Length - GetIkmSize(_keyEngineType)) % GetSaltSize(_keyEngineType) != 0)
                throw new CryptoSymmetricException("SHX:Initialize", String.Format("Invalid key size! Key must be (length - IKm length: {0} bytes) + multiple of {1} block size.", GetIkmSize(_keyEngineType), GetSaltSize(_keyEngineType)), new ArgumentOutOfRangeException());

            for (int i = 0; i < LegalKeySizes.Length; ++i)
            {
                if (KeyParam.Key.Length == LegalKeySizes[i])
                    break;
                if (i == LegalKeySizes.Length - 1)
                    throw new CryptoSymmetricException("SHX:Initialize", String.Format("Invalid key size! Key must be at least {0}  bytes ({1} bit).", LegalKeySizes[0], LegalKeySizes[0] * 8), new ArgumentOutOfRangeException());
            }

            // get the kdf digest engine
            if (KeyParam.Key.Length > MAX_STDKEY)
                _keyEngine = GetKdfEngine(_keyEngineType);

            _isEncryption = Encryption;
            // expand the key
            _expKey = ExpandKey(KeyParam.Key);
            // ready to transform data
            _isInitialized = true;
        }

        /// <summary>
        /// Transform a block of bytes.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
        /// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt or Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        public void Transform(byte[] Input, byte[] Output)
        {
            if (_isEncryption)
                Encrypt16(Input, 0, Output, 0);
            else
                Decrypt16(Input, 0, Output, 0);
        }

        /// <summary>
        /// Transform a block of bytes with offset parameters.
        /// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
        /// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset in the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset in the Output array</param>
        public void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            if (_isEncryption)
                Encrypt16(Input, InOffset, Output, OutOffset);
            else
                Decrypt16(Input, InOffset, Output, OutOffset);
        }
        #endregion

        #region Key Schedule
        private UInt32[] ExpandKey(byte[] Key)
        {
            if (Key.Length > MAX_STDKEY)
            {
                // using hkdf expansion
                return SecureExpand(Key);
            }
            else
            {
                // standard serpent key expansion + k512
                return StandardExpand(Key);
            }
        }

        private UInt32[] SecureExpand(byte[] Key)
        {
            // expanded key size
            int keySize = 4 * (_dfnRounds + 1);

            // hkdf return array
            int keyBytes = keySize * 4;
            byte[] rawKey = new byte[keyBytes];
            int saltSize = Key.Length - _ikmSize;

            // salt must be divisible of hash blocksize
            if (saltSize % _keyEngine.BlockSize != 0)
                saltSize = saltSize - saltSize % _keyEngine.BlockSize;

            // hkdf input
            byte[] hkdfKey = new byte[_ikmSize];
            byte[] hkdfSalt = new byte[saltSize];

            // copy hkdf key and salt from user key
            Buffer.BlockCopy(Key, 0, hkdfKey, 0, _ikmSize);
            Buffer.BlockCopy(Key, _ikmSize, hkdfSalt, 0, saltSize);

            // HKDF generator expands array using an SHA512 HMAC
            using (HKDF gen = new HKDF(_keyEngine, false))
            {
                gen.Initialize(hkdfSalt, hkdfKey, _hkdfInfo);
                gen.Generate(rawKey);
            }

            // initialize working key
            uint[] expKey = new uint[keySize];
            // copy bytes to working key
            Buffer.BlockCopy(rawKey, 0, expKey, 0, keyBytes);

            return expKey;
        }

        private UInt32[] StandardExpand(byte[] Key)
        {
            int cnt = 0;
            int index = 0;
            int padSize = Key.Length < 32 ? 16 : Key.Length / 2;
            uint[] tmpKey = new uint[padSize];
            int offset = 0;

            // less than 512 is default rounds
            if (Key.Length < 64)
                _dfnRounds = ROUNDS32;

            int keySize = 4 * (_dfnRounds + 1);

            // step 1: reverse copy key to temp array
            for (offset = Key.Length; offset > 0; offset -= 4)
                tmpKey[index++] = IntUtils.BytesToBe32(Key, offset - 4);

            // pad small key
            if (index < 8)
                tmpKey[index] = 1;

            // initialize the key
            uint[] expKey = new uint[keySize];

            if (padSize == 16)
            {
                // 32 byte key
                // step 2: rotate k into w(k) ints
                for (int i = 8; i < 16; i++)
                    tmpKey[i] = IntUtils.RotateLeft((UInt32)(tmpKey[i - 8] ^ tmpKey[i - 5] ^ tmpKey[i - 3] ^ tmpKey[i - 1] ^ PHI ^ (i - 8)), 11);

                // copy to expanded key
                Array.Copy(tmpKey, 8, expKey, 0, 8);

                // step 3: calculate remainder of rounds with rotating primitive
                for (int i = 8; i < keySize; i++)
                    expKey[i] = IntUtils.RotateLeft((UInt32)(expKey[i - 8] ^ expKey[i - 5] ^ expKey[i - 3] ^ expKey[i - 1] ^ PHI ^ i), 11);
            }
            else
            {
                // *extended*: 64 byte key
                // step 3: rotate k into w(k) ints, with extended polynominal
                // Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
                for (int i = 16; i < 32; i++)
                    tmpKey[i] = IntUtils.RotateLeft((UInt32)(tmpKey[i - 16] ^ tmpKey[i - 13] ^ tmpKey[i - 11] ^ tmpKey[i - 10] ^ tmpKey[i - 8] ^ tmpKey[i - 5] ^ tmpKey[i - 3] ^ tmpKey[i - 1] ^ PHI ^ (i - 16)), 11);

                // copy to expanded key
                Array.Copy(tmpKey, 16, expKey, 0, 16);

                // step 3: calculate remainder of rounds with rotating primitive
                for (int i = 16; i < keySize; i++)
                    expKey[i] = IntUtils.RotateLeft((UInt32)(expKey[i - 16] ^ expKey[i - 13] ^ expKey[i - 11] ^ expKey[i - 10] ^ expKey[i - 8] ^ expKey[i - 5] ^ expKey[i - 3] ^ expKey[i - 1] ^ PHI ^ i), 11);
            }

            // step 4: create the working keys by processing with the Sbox and IP
            while (cnt < keySize - 4)
            {
                Sb3(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb2(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb1(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb0(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb7(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb6(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb5(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
                Sb4(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]); cnt += 4;
            }

            // last round
            Sb3(ref expKey[cnt], ref expKey[cnt + 1], ref expKey[cnt + 2], ref expKey[cnt + 3]);

            return expKey;
        }
        #endregion

        #region Rounds Processing
        private void Decrypt16(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int LRD = 4;
            int keyCtr = _expKey.Length;

            // input round
            uint R3 = _expKey[--keyCtr] ^ IntUtils.BytesToBe32(Input, InOffset);
            uint R2 = _expKey[--keyCtr] ^ IntUtils.BytesToBe32(Input, InOffset + 4);
            uint R1 = _expKey[--keyCtr] ^ IntUtils.BytesToBe32(Input, InOffset + 8);
            uint R0 = _expKey[--keyCtr] ^ IntUtils.BytesToBe32(Input, InOffset + 12);

            // process 8 round blocks
            do
            {
                Ib7(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib6(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib5(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib4(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib3(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib2(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib1(ref R0, ref R1, ref R2, ref R3);
                R3 ^= _expKey[--keyCtr];
                R2 ^= _expKey[--keyCtr];
                R1 ^= _expKey[--keyCtr];
                R0 ^= _expKey[--keyCtr];
                InverseTransform(ref R0, ref R1, ref R2, ref R3);

                Ib0(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr != LRD)
                {
                    R3 ^= _expKey[--keyCtr];
                    R2 ^= _expKey[--keyCtr];
                    R1 ^= _expKey[--keyCtr];
                    R0 ^= _expKey[--keyCtr];
                    InverseTransform(ref R0, ref R1, ref R2, ref R3);
                }
            }
            while (keyCtr != LRD);

            // last round
            IntUtils.Be32ToBytes(R3 ^ _expKey[--keyCtr], Output, OutOffset);
            IntUtils.Be32ToBytes(R2 ^ _expKey[--keyCtr], Output, OutOffset + 4);
            IntUtils.Be32ToBytes(R1 ^ _expKey[--keyCtr], Output, OutOffset + 8);
            IntUtils.Be32ToBytes(R0 ^ _expKey[--keyCtr], Output, OutOffset + 12);
        }

        private void Encrypt16(byte[] Input, int InOffset, byte[] Output, int OutOffset)
        {
            int LRD = _expKey.Length - 5;
            int keyCtr = -1;

            // input round
            uint R0 = IntUtils.BytesToBe32(Input, InOffset + 12);
            uint R1 = IntUtils.BytesToBe32(Input, InOffset + 8);
            uint R2 = IntUtils.BytesToBe32(Input, InOffset + 4);
            uint R3 = IntUtils.BytesToBe32(Input, InOffset);

            // process 8 round blocks
            do
            {
                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb0(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb1(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb2(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3); ;

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb3(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb4(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb5(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb6(ref R0, ref R1, ref R2, ref R3);
                LinearTransform(ref R0, ref R1, ref R2, ref R3);

                R0 ^= _expKey[++keyCtr];
                R1 ^= _expKey[++keyCtr];
                R2 ^= _expKey[++keyCtr];
                R3 ^= _expKey[++keyCtr];
                Sb7(ref R0, ref R1, ref R2, ref R3);

                // skip on last block
                if (keyCtr != LRD)
                    LinearTransform(ref R0, ref R1, ref R2, ref R3);
            }
            while (keyCtr != LRD);

            // last round
            IntUtils.Be32ToBytes(_expKey[++keyCtr] ^ R0, Output, OutOffset + 12);
            IntUtils.Be32ToBytes(_expKey[++keyCtr] ^ R1, Output, OutOffset + 8);
            IntUtils.Be32ToBytes(_expKey[++keyCtr] ^ R2, Output, OutOffset + 4);
            IntUtils.Be32ToBytes(_expKey[++keyCtr] ^ R3, Output, OutOffset);
        }
        #endregion

        #region SBox Calculations
        private void Sb0(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R0 ^ R3;
            UInt32 t2 = R2 ^ t1;
            UInt32 t3 = R1 ^ t2;
            R3 = (R0 & R3) ^ t3;
            UInt32 t4 = R0 ^ (R1 & t1);
            R2 = t3 ^ (R2 | t4);
            R0 = R3 & (t2 ^ t4);
            R1 = (~t2) ^ R0;
            R0 ^= (~t4);
        }

        private void Ib0(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R0;
            UInt32 t2 = R0 ^ R1;
            UInt32 t3 = R3 ^ (t1 | t2);
            UInt32 t4 = R2 ^ t3;
            R2 = t2 ^ t4;
            UInt32 t5 = t1 ^ (R3 & t2);
            R1 = t3 ^ (R2 & t5);
            R3 = (R0 & t3) ^ (t4 | R1);
            R0 = R3 ^ (t4 ^ t5);
        }

        private void Sb1(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ (~R0);
            UInt32 t2 = R2 ^ (R0 | t1);
            R2 = R3 ^ t2;
            UInt32 t3 = R1 ^ (R3 | t1);
            UInt32 t4 = t1 ^ R2;
            R3 = t4 ^ (t2 & t3);
            UInt32 t5 = t2 ^ t3;
            R1 = R3 ^ t5;
            R0 = t2 ^ (t4 & t5);
        }

        private void Ib1(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ R3;
            UInt32 t2 = R0 ^ (R1 & t1);
            UInt32 t3 = t1 ^ t2;
            R3 = R2 ^ t3;
            UInt32 t4 = R1 ^ (t1 & t2);
            R1 = t2 ^ (R3 | t4);
            UInt32 t5 = ~R1;
            UInt32 t6 = R3 ^ t4;
            R0 = t5 ^ t6;
            R2 = t3 ^ (t5 | t6);
        }

        private void Sb2(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R0;
            UInt32 t2 = R1 ^ R3;
            UInt32 t3 = t2 ^ (R2 & t1);
            UInt32 t4 = R2 ^ t1;
            UInt32 t5 = R1 & (R2 ^ t3);
            UInt32 t6 = t4 ^ t5;
            R2 = R0 ^ ((R3 | t5) & (t3 | t4));
            R1 = (t2 ^ t6) ^ (R2 ^ (R3 | t1));
            R0 = t3;
            R3 = t6;
        }

        private void Ib2(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ R3;
            UInt32 t2 = R0 ^ R2;
            UInt32 t3 = R2 ^ t1;
            UInt32 t4 = R0 | ~t1;
            R0 = t2 ^ (R1 & t3);
            UInt32 t5 = t1 ^ (t2 | (R3 ^ t4));
            UInt32 t6 = ~t3;
            UInt32 t7 = R0 | t5;
            R1 = t6 ^ t7;
            R2 = (R3 & t6) ^ (t2 ^ t7);
            R3 = t5;
        }

        private void Sb3(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R0 ^ R1;
            UInt32 t2 = R0 | R3;
            UInt32 t3 = R2 ^ R3;
            UInt32 t4 = (R0 & R2) | (t1 & t2);
            R2 = t3 ^ t4;
            UInt32 t5 = t4 ^ (R1 ^ t2);
            R0 = t1 ^ (t3 & t5);
            UInt32 t6 = R2 & R0;
            R3 = (R1 | R3) ^ (t3 ^ t6);
            R1 = t5 ^ t6;
        }

        private void Ib3(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ R2;
            UInt32 t2 = R0 ^ (R1 & t1);
            UInt32 t3 = R3 | t2;
            UInt32 t4 = R3 ^ (t1 | t3);
            R2 = (R2 ^ t2) ^ t4;
            UInt32 t5 = (R0 | R1) ^ t4;
            R0 = t1 ^ t3;
            R3 = t2 ^ (R0 & t5);
            R1 = R3 ^ (R0 ^ t5);
        }

        private void Sb4(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R0 ^ R3;
            UInt32 t2 = R2 ^ (R3 & t1);
            UInt32 t3 = R1 | t2;
            R3 = t1 ^ t3;
            UInt32 t4 = ~R1;
            UInt32 t5 = t2 ^ (t1 | t4);
            UInt32 t6 = t1 ^ t4;
            UInt32 t7 = (R0 & t5) ^ (t3 & t6);
            R1 = (R0 ^ t2) ^ (t6 & t7);
            R0 = t5;
            R2 = t7;
        }

        private void Ib4(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ (R0 & (R2 | R3));
            UInt32 t2 = R2 ^ (R0 & t1);
            UInt32 t3 = R3 ^ t2;
            UInt32 t4 = ~R0;
            UInt32 t5 = t1 ^ (t2 & t3);
            UInt32 t6 = R3 ^ (t3 | t4);
            R1 = t3;
            R0 = t5 ^ t6;
            R2 = (t1 & t6) ^ (t3 ^ t4);
            R3 = t5;
        }

        private void Sb5(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R0;
            UInt32 t2 = R0 ^ R1;
            UInt32 t3 = R0 ^ R3;
            UInt32 t4 = (R2 ^ t1) ^ (t2 | t3);
            UInt32 t5 = R3 & t4;
            UInt32 t6 = t5 ^ (t2 ^ t4);
            UInt32 t7 = t3 ^ (t1 | t4);
            R2 = (t2 | t5) ^ t7;
            R3 = (R1 ^ t5) ^ (t6 & t7);
            R0 = t4;
            R1 = t6;
        }

        private void Ib5(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R2;
            UInt32 t2 = R3 ^ (R1 & t1);
            UInt32 t3 = R0 & t2;
            UInt32 t4 = t3 ^ (R1 ^ t1);
            UInt32 t5 = R1 | t4;
            UInt32 t6 = t2 ^ (R0 & t5);
            UInt32 t7 = R0 | R3;
            R2 = (R1 & t7) ^ (t3 | (R0 ^ R2));
            R0 = t7 ^ (t1 ^ t5);
            R1 = t6;
            R3 = t4;
        }

        private void Sb6(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R0 ^ R3;
            UInt32 t2 = R1 ^ t1;
            UInt32 t3 = R2 ^ (~R0 | t1);
            R1 ^= t3;
            UInt32 t4 = t1 | R1;
            UInt32 t5 = R3 ^ (t1 | R1);
            R2 = t2 ^ (t3 & t5);
            UInt32 t6 = t3 ^ t5;
            R0 = R2 ^ t6;
            R3 = (~t3) ^ (t2 & t6);
        }

        private void Ib6(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = ~R0;
            UInt32 t2 = R0 ^ R1;
            UInt32 t3 = R2 ^ t2;
            UInt32 t4 = R3 ^ (R2 | t1);
            UInt32 t5 = t3 ^ t4;
            UInt32 t6 = t2 ^ (t3 & t4);
            UInt32 t7 = t4 ^ (R1 | t6);
            UInt32 t8 = R1 | t7;
            R0 = t6 ^ t8;
            R2 = (R3 & t1) ^ (t3 ^ t8);
            R1 = t5;
            R3 = t7;
        }

        private void Sb7(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R1 ^ R2;
            UInt32 t2 = R3 ^ (R2 & t1);
            UInt32 t3 = R0 ^ t2;
            R1 ^= (t3 & (R3 | t1));
            UInt32 t4 = t1 ^ (R0 & t3);
            UInt32 t5 = t3 ^ (t2 | R1);
            R2 = t2 ^ (t4 & t5);
            R0 = (~t5) ^ (t4 & R2);
            R3 = t4;
        }

        private void Ib7(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 t1 = R2 | (R0 & R1);
            UInt32 t2 = R3 & (R0 | R1);
            UInt32 t3 = t1 ^ t2;
            UInt32 t4 = R1 ^ t2;
            R1 = R0 ^ (t4 | (t3 ^ ~R3));
            UInt32 t8 = (R2 ^ t4) ^ (R3 | R1);
            R2 = (t1 ^ R1) ^ (t8 ^ (R0 & t3));
            R0 = t8;
            R3 = t3;
        }

        /// <remarks>
        /// Apply the linear transformation to the register set
        /// </remarks>
        private void LinearTransform(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 x0 = IntUtils.RotateLeft(R0, 13);
            UInt32 x2 = IntUtils.RotateLeft(R2, 3);
            UInt32 x1 = R1 ^ x0 ^ x2;
            UInt32 x3 = R3 ^ x2 ^ x0 << 3;

            R1 = IntUtils.RotateLeft(x1, 1);
            R3 = IntUtils.RotateLeft(x3, 7);
            R0 = IntUtils.RotateLeft(x0 ^ R1 ^ R3, 5);
            R2 = IntUtils.RotateLeft(x2 ^ R3 ^ (R1 << 7), 22);
        }

        /// <remarks>
        /// Apply the inverse of the linear transformation to the register set
        /// </remarks>
        private void InverseTransform(ref UInt32 R0, ref UInt32 R1, ref UInt32 R2, ref UInt32 R3)
        {
            UInt32 x2 = IntUtils.RotateRight(R2, 22) ^ R3 ^ (R1 << 7);
            UInt32 x0 = IntUtils.RotateRight(R0, 5) ^ R1 ^ R3;
            UInt32 x3 = IntUtils.RotateRight(R3, 7);
            UInt32 x1 = IntUtils.RotateRight(R1, 1);

            R3 = x3 ^ x2 ^ x0 << 3;
            R1 = x1 ^ x0 ^ x2;
            R2 = IntUtils.RotateRight(x2, 3);
            R0 = IntUtils.RotateRight(x0, 13);
        }
        #endregion

        #region Helpers
        private int GetIkmSize(Digests Engine)
        {
            switch (Engine)
            {
                case Digests.Blake256:
                case Digests.Keccak256:
                case Digests.SHA256:
                case Digests.Skein256:
                    return 32;
                case Digests.Blake512:
                case Digests.Keccak512:
                case Digests.SHA512:
                case Digests.Skein512:
                    return 64;
                case Digests.Skein1024:
                    return 128;
                default:
                    throw new CryptoSymmetricException("RHX:GetDigestSize", "The digest type is not supported!", new ArgumentException());
            }
        }

        private IDigest GetKdfEngine(Digests KeyEngine)
        {
            try
            {
                return DigestFromName.GetInstance(KeyEngine);
            }
            catch
            {
                throw new CryptoSymmetricException("RHX:GetKeyEngine", "The digest type is not supported!", new ArgumentException());
            }
        }

        private int GetSaltSize(Digests Engine)
        {
            switch (Engine)
            {
                case Digests.Blake256:
                case Digests.Skein256:
                    return 32;
                case Digests.Blake512:
                case Digests.SHA256:
                case Digests.Skein512:
                    return 64;
                case Digests.SHA512:
                case Digests.Skein1024:
                    return 128;
                case Digests.Keccak256:
                    return 136;
                case Digests.Keccak512:
                    return 72;
                default:
                    throw new CryptoSymmetricException("RHX:GetBlockSize", "The digest type is not supported!", new ArgumentException());
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
                    if (_keyEngine != null)
                    {
                        _keyEngine.Dispose();
                        _keyEngine = null;
                    }
                    if (_expKey != null)
                    {
                        Array.Clear(_expKey, 0, _expKey.Length);
                        _expKey = null;
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
