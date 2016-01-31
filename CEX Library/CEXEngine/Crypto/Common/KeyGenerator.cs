#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Common
{
    /// <summary>
    /// <h5>KeyGenerator: A helper class for generating cryptographically strong keying material.</h5>
    /// <para>Generates an array or a populated KeyParams class, using a definable Digest(Drbg) dual stage generator.
    /// The first stage of the generator gets seed material from the selected seed generator, the second hashes the seed and adds the result to the state array.
    /// An optional (random) counter array can be prepended to the seed array, sized between 4 and 16 bytes. 
    /// The counter is incremented and prepended to the seed value before each hash call. 
    /// If the CounterSize parameter is set to <c>0</c> in the constructor, or the default constructor is used, 
    /// the counter is created using the system default cryptographic service provider (CSPRsg).</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create an array of pseudo random keying material:</description>
    /// <code>
    /// byte[] rand;
    /// using (KeyGenerator gen = new KeyGenerator([SeedGenerator], [Digest], [Counter Size]))
    ///     // generate pseudo random bytes
    ///     rand = gen.Generate(Size);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2014/11/11" version="1.2.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Assignable digests and Prng parameters added</revision>
    /// <revision date="2016/01/09" version="1.5.0.0">Rework of counter/generator mechanisms</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng ">VTDev.Libraries.CEXEngine.Crypto.Prng Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom ">VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>SHA-2 Generates key material using a two stage Hmac_k(Prng()) process.</description></item>
    /// <item><description>Blake<cite>Blake</cite>, Keccak<cite>Keccak</cite>, and Skein<cite>Skein</cite> also use a two stage generation method; Hash(Prng()).</description></item>
    /// <item><description>Seed Generator can be any of the <see cref="SeedGenerators"/>.</description></item>
    /// <item><description>Hash can be any of the <see cref="Digests"/> digests.</description></item>
    /// <item><description>Default Seed Generator is CSPRsg<cite>RNGCryptoServiceProvider</cite>, default digest is SHA512.</description></item>
    /// <item><description>Resources are disposed of automatically.</description></item>
    /// </list>
    /// </remarks>
    public sealed class KeyGenerator : IDisposable
    {
        #region Constants
        private const int DEFCTR_SIZE = 32;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private IDigest _hashEngine;
        private ISeed _seedEngine;
        private Digests _dgtType;
        private SeedGenerators _seedType;
        private byte[] _ctrVector = null;
        private int _ctrLength = 0;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the Digests enumeration member
        /// </summary>
        public Digests HashEngine 
        {
            get { return _dgtType; }
            private set { _dgtType = value; } 
        }

        /// <summary>
        /// Get: Returns the Prng enumeration member
        /// </summary>
        public SeedGenerators SeedEngine 
        {
            get { return _seedType; }
            private set { _seedType = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class.
        /// <para>Initializes the class with default generators; SHA-2 512, and RNGCryptoServiceProvider.
        /// The digest counter mechanism is set to <c>O</c> (disabled) by default.</para>
        /// </summary>
        /// 
        /// <param name="SeedEngine">The <see cref="SeedGenerators">generator</see> that supplies the seed material to the hash function</param>
        /// <param name="DigestEngine">The <see cref="Digests">Digest</see> type used to post-process the pseudo random seed material</param>
        public KeyGenerator(SeedGenerators SeedEngine = SeedGenerators.CSPRsg, Digests DigestEngine = Digests.SHA512)
        {
            // default engines
            _seedType = SeedEngine;
            _dgtType = DigestEngine;
            _ctrLength = 0;

            // initialize the generators
            Reset();
        }

        /// <summary>
        /// Initialize the class and generators
        /// </summary>
        /// 
        /// <param name="SeedEngine">The <see cref="SeedGenerators">generator</see> that supplies the seed material to the hash function</param>
        /// <param name="DigestEngine">The <see cref="Digests">Digest</see> type used to post-process the pseudo random seed material</param>
        /// <param name="Counter">The user supplied counter variable in bytes; setting to a <c>0</c> value, produces a counter generated by the default random provider; valid values are <c>0</c>, or between <c>4-32</c> bytes</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if the counter is not <c>0</c>, or a value between <c>4</c> and <c>32</c></exception>
        public KeyGenerator(SeedGenerators SeedEngine, Digests DigestEngine, byte[] Counter)
        {
            if (Counter == null)
                Counter = new byte[DEFCTR_SIZE];

            if (Counter.Length > 32 || (Counter.Length < 4 && Counter.Length != 0))
                throw new CryptoGeneratorException("KeyGenerator:Ctor", "The counter size must be either 0, or between 4 and 32", new ArgumentException());

            _seedType = SeedEngine;
            _dgtType = DigestEngine;
            _ctrVector = Counter;
            _ctrLength = Counter.Length;

            // initialize the generators
            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~KeyGenerator()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a populated KeyParams class
        /// </summary>
        /// 
        /// <param name="KeySize">Size of Key to generate in bytes</param>
        /// <param name="IVSize">Size of IV to generate in bytes</param>
        /// <param name="IKMSize">Size of IKM to generate in bytes</param>
        /// 
        /// <returns>A populated <see cref="KeyParams"/> class</returns>
        public KeyParams GetKeyParams(int KeySize, int IVSize = 0, int IKMSize = 0)
        {
            KeyParams kp = new KeyParams();

            if (KeySize > 0)
                kp.Key = Generate(KeySize);
            if (IVSize > 0)
                kp.IV = Generate(IVSize);
            if (IKMSize > 0)
                kp.IKM = Generate(IKMSize);

            return kp;
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Data">Array to fill with random bytes</param>
        public void GetBytes(byte[] Data)
        {
            byte[] rand = Generate(Data.Length);
            Buffer.BlockCopy(rand, 0, Data, 0, rand.Length);
        }

        /// <summary>
        /// Return an array with pseudo random bytes
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
        /// Reset the seed <see cref="Prngs">PRNG</see> and the <see cref="Digests">Digest</see> engines
        /// </summary>
        public void Reset()
        {
            if (_seedEngine != null)
            {
                _seedEngine.Dispose();
                _seedEngine = null;
            }
            _seedEngine = SeedGeneratorFromName.GetInstance(SeedEngine);

            // reset hash engine
            if (_hashEngine != null)
            {
                _hashEngine.Dispose();
                _hashEngine = null;
            }
            _hashEngine = DigestFromName.GetInstance(HashEngine);

            // if absent, generate the initial counter
		    if (_ctrLength == 0)
		    {
			    _ctrLength = DEFCTR_SIZE;
			    _ctrVector = new byte[_ctrLength];
                using (CSPRsg pool =  new CSPRsg())
                    _ctrVector = pool.GetBytes(_ctrLength);
		    }
        }
        #endregion

        #region Private Methods
        private byte[] Generate(int Size)
        {
            byte[] key = new byte[Size];

            // get the first block
            byte[] rand = GetBlock();
            int blockSize = rand.Length;

            if (Size < blockSize)
            {
                Buffer.BlockCopy(rand, 0, key, 0, Size);
            }
            else
            {
                // copy first block
                Buffer.BlockCopy(rand, 0, key, 0, blockSize);

                int offset = blockSize;
                int alnSize = Size - (Size % blockSize);

                // fill the key array
                while (offset < alnSize)
                {
                    Buffer.BlockCopy(GetBlock(), 0, key, offset, blockSize);
                    offset += blockSize;
                }

                // process unaligned block
                if (alnSize < Size)
                    Buffer.BlockCopy(GetBlock(), 0, key, offset, Size - offset);
            }

            return key;
        }

        /// <remarks>
        /// Create keying material using a two stage generator
        /// </remarks>
        private byte[] GetBlock()
        {
            // generate seed; 2x input block size per NIST sp800-90b
            byte[] seed = _seedEngine.GetBytes((_hashEngine.BlockSize * 2) - _ctrLength);
            // increment the counter
            Increment(_ctrVector);
            // prepend the counter to the seed
            seed = VTDev.Libraries.CEXEngine.Utility.ArrayUtils.Concat(_ctrVector, seed);

            // special case for sha-2
            if (_dgtType == Digests.SHA256 || _dgtType == Digests.SHA512)
            {
                // hmac key size is digest hash size: rfc 2104
                byte[] key = _seedEngine.GetBytes(_hashEngine.DigestSize);

                // set hmac to *not* dispose of underlying digest
                using (HMAC mac = new HMAC(_hashEngine, key, false))
                    return mac.ComputeMac(seed);
            }
            else
            {
                // other implemented digests do not require hmac
                return _hashEngine.ComputeHash(seed);
            }
        }

        private void Increment(byte[] Counter)
        {
            int i = Counter.Length;
            while (--i >= 0 && ++Counter[i] == 0) { }
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
                    if (_ctrVector != null)
                    {
                        Array.Clear(_ctrVector, 0, _ctrVector.Length);
                        _ctrVector = null;
                    }
                    if (_hashEngine != null)
                    {
                        _hashEngine.Dispose();
                        _hashEngine = null;
                    }
                    if (_seedEngine != null)
                    {
                        _seedEngine.Dispose();
                        _seedEngine = null;
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
