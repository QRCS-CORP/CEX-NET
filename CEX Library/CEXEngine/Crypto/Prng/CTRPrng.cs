#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// CTRPrng: An implementation of a Encryption Counter based Deterministic Random Number Generator
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IRandom</c> interface:</description>
    /// <code>
    /// int num;
    /// using (IRandom rnd = new CTRPrng([BlockCiphers], [SeedGenerators]))
    /// {
    ///     // get random int
    ///     num = rnd.Next([Minimum], [Maximum]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Seed"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Can be initialized with any block <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers">cipher</see>.</description></item>
    /// <item><description>Can use either a random seed generator for initialization, or a user supplied Seed array.</description></item>
    /// <item><description>Numbers generated with the same seed will produce the same random output.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
    /// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
    /// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the Codebook-based: Deterministic Random Bit Generator.</description></item>
    /// </list>
    /// </remarks>
    public sealed class CTRPrng : IRandom
    {
        #region Constants
        private const string ALG_NAME = "CTRPrng";
        private const int BUFFER_SIZE = 4096;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private IBlockCipher _rngEngine;
        private CTRDrbg _rngGenerator;
        private ISeed _seedGenerator;
        private BlockCiphers _engineType;
        private SeedGenerators _seedType;
        private byte[] _stateSeed;
        private byte[] _byteBuffer;
        private int _bufferIndex = 0;
        private int _bufferSize = 0;
        private int _keySize = 0;
        private object _objLock = new object();
        #endregion

        #region Properties
        /// <summary>
        /// Get: The prngs type name
        /// </summary>
        public Prngs Enumeral
        {
            get { return Prngs.CTRPrng; }
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
        /// 
        /// <param name="BlockEngine">The block cipher that powers the rng (default is RDX)</param>
        /// <param name="SeedEngine">The Seed engine used to create keyng material (default is CSPRsg)</param>
        /// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
        /// <param name="KeySize">The key size (in bytes) of the symmetric cipher; a <c>0</c> value will auto size the key</param>
        public CTRPrng(BlockCiphers BlockEngine = BlockCiphers.Rijndael, SeedGenerators SeedEngine = SeedGenerators.CSPRsg, int BufferSize = 4096, int KeySize = 0)
        {
            if (BufferSize < 64)
                throw new CryptoRandomException("CTRPrng:Ctor", "Buffer size must be at least 64 bytes!", new ArgumentNullException());

            _engineType = BlockEngine;
            _seedType = SeedEngine;
            _byteBuffer = new byte[BufferSize];
            _bufferSize = BufferSize;

            if (KeySize > 0)
                _keySize = KeySize;
            else
                _keySize = GetKeySize(BlockEngine);

            Reset();
        }

        /// <summary>
        /// Initialize the class with a Seed; note: the same seed will produce the same random output
        /// </summary>
        /// 
        /// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is key size + counter 16)</param>
        /// <param name="BlockEngine">The block cipher that powers the rng (default is RDX)</param>
        /// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if the seed is null or too small</exception>
        public CTRPrng(byte[] Seed, BlockCiphers BlockEngine = BlockCiphers.Rijndael, int BufferSize = 4096)
        {
            if (BufferSize < 64)
                throw new CryptoRandomException("CTRPrng:Ctor", "Buffer size must be at least 64 bytes!", new ArgumentNullException());
            if (Seed == null)
                throw new CryptoRandomException("CTRPrng:Ctor", "Seed can not be null!", new ArgumentNullException());
            if (GetKeySize(BlockEngine) < Seed.Length)
                throw new CryptoRandomException("CTRPrng:Ctor", String.Format("The state seed is too small! must be at least {0} bytes", GetKeySize(BlockEngine)), new ArgumentException());

            _engineType = BlockEngine;
            _stateSeed = Seed;
            _byteBuffer = new byte[BufferSize];
            _bufferSize = BufferSize;
            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~CTRPrng()
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
            byte[] data = new byte[Size];

            GetBytes(data);

            return data;
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Array to fill with random bytes</param>
        public void GetBytes(byte[] Output)
        {
            lock (_objLock)
            {
                if (_byteBuffer.Length - _bufferIndex < Output.Length)
                {
                    int bufSize = _byteBuffer.Length - _bufferIndex;
                    // copy remaining bytes
                    Buffer.BlockCopy(_byteBuffer, _bufferIndex, Output, 0, bufSize);
                    int rem = Output.Length - bufSize;

                    while (rem > 0)
                    {
                        // fill buffer
                        _rngGenerator.Generate(_byteBuffer);

                        if (rem > _byteBuffer.Length)
                        {
                            Buffer.BlockCopy(_byteBuffer, 0, Output, bufSize, _byteBuffer.Length);
                            bufSize += _byteBuffer.Length;
                            rem -= _byteBuffer.Length;
                        }
                        else
                        {
                            Buffer.BlockCopy(_byteBuffer, 0, Output, bufSize, rem);
                            _bufferIndex = rem;
                            rem = 0;
                        }
                    }
                }
                else
                {
                    Buffer.BlockCopy(_byteBuffer, _bufferIndex, Output, 0, Output.Length);
                    _bufferIndex += Output.Length;
                }
            }
        }

        /// <summary>
        /// Get a pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random int</returns>
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
        /// <returns>Random int</returns>
        public int Next(int Maximum)
        {
            byte[] rand;
            int[] num = new int[1];

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
        /// <returns>Random int</returns>
        public int Next(int Minimum, int Maximum)
        {
            int num = 0;
            while ((num = Next(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Get a pseudo random 64bit integer
        /// </summary>
        /// 
        /// <returns>Random long</returns>
        public long NextLong()
        {
            return BitConverter.ToInt64(GetBytes(8), 0);
        }

        /// <summary>
        /// Get a ranged pseudo random 64bit integer
        /// </summary>
        /// 
        /// <param name="Maximum">Maximum value</param>
        /// 
        /// <returns>Random long</returns>
        public long NextLong(long Maximum)
        {
            byte[] rand;
            long[] num = new long[1];

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
        /// <returns>Random long</returns>
        public long NextLong(long Minimum, long Maximum)
        {
            long num = 0;
            while ((num = NextLong(Maximum)) < Minimum) { }
            return num;
        }

        /// <summary>
        /// Reset the CTRPrng instance
        /// </summary>
        public void Reset()
        {
            if (_rngEngine != null)
            {
                _rngEngine.Dispose();
                _rngEngine = null;
            }
            if (_seedGenerator != null)
            {
                _seedGenerator.Dispose();
                _seedGenerator = null;
            }
            if (_rngGenerator != null)
            {
                _rngGenerator.Dispose();
                _rngGenerator = null;
            }

            _rngEngine = GetCipher(_engineType);
            _seedGenerator = GetSeedGenerator(_seedType);
            _rngGenerator = new CTRDrbg(_rngEngine, true, _keySize);

            if (_seedGenerator != null)
                _rngGenerator.Initialize(_seedGenerator.GetBytes(_rngEngine.BlockSize + _keySize));
            else
                _rngGenerator.Initialize(_stateSeed);

            _rngGenerator.Generate(_byteBuffer);
            _bufferIndex = 0;
        }
        #endregion

        #region Private Methods
        private byte[] GetBits(byte[] Data, long Maximum)
        {
            ulong[] val = new ulong[1];
            Buffer.BlockCopy(Data, 0, val, 0, Data.Length);
            int bits = Data.Length * 8;

            while (val[0] > (ulong)Maximum && bits > 0)
            {
                val[0] >>= 1;
                bits--;
            }

            byte[] ret = new byte[Data.Length];
            Buffer.BlockCopy(val, 0, ret, 0, Data.Length);

            return ret;
        }

        private byte[] GetByteRange(long Maximum)
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

        private IBlockCipher GetCipher(BlockCiphers RngEngine)
        {
            try
            {
                return BlockCipherFromName.GetInstance(RngEngine);
            }
            catch (Exception Ex)
            {
                throw new CryptoRandomException("CTRPrng:GetCipher", "The cipher could not be initialized!", Ex);
            }
        }

        private int GetKeySize(BlockCiphers CipherEngine)
        {
            return 32;
        }

        private ISeed GetSeedGenerator(SeedGenerators SeedEngine)
        {
            try
            {
                return SeedGeneratorFromName.GetInstance(SeedEngine);
            }
            catch (Exception Ex)
            {
                throw new CryptoRandomException("CTRPrng:GetSeedGenerator", "The seed generator could not be initialized!", Ex);
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
                    if (_rngGenerator != null)
                    {
                        _rngGenerator.Dispose();
                        _rngGenerator = null;
                    }
                    if (_seedGenerator != null)
                    {
                        _seedGenerator.Dispose();
                        _seedGenerator = null;
                    }
                    if (_byteBuffer != null)
                    {
                        Array.Clear(_byteBuffer, 0, _byteBuffer.Length);
                        _byteBuffer = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
