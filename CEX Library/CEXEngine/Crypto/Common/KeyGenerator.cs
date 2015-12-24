#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Common
{
    /// <summary>
    /// <h3>A helper class for generating cryptographically strong keying material.</h3>
    /// <para>Generates an array or a populated KeyParams class, using a definable Digest(Prng) dual stage generator.
    /// The first stage of the generator gets seed material from the selected Prng, the second hashes the seed and adds the result to the state array.
    /// An optional (prng generated random) counter array can be prepended to the seed array, sized between 4 and 16 bytes. 
    /// The counter is incremented and prepended to the seed value before each hash call. 
    /// If the CounterSize parameter is set to <c>0</c> in the constructor, or the default constructor is used, 
    /// the entire (2* block size) seed is generated with the prng, and the counter is not used.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create an array of pseudo random keying material:</description>
    /// <code>
    /// byte[] rand;
    /// using (KeyGenerator gen = new KeyGenerator([Prng], [Digest], [Counter Size]))
    ///     // generate pseudo random bytes
    ///     rand = gen.Generate(Size);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2014/11/11" version="1.2.0.0">Initial release</revision>
    /// <revision date="2015/01/23" version="1.3.0.0">Assignable digests and Prng parameters added</revision>
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
    /// <item><description>Prng can be any of the <see cref="Prngs"/> generators.</description></item>
    /// <item><description>Hash can be any of the <see cref="Digests"/> digests.</description></item>
    /// <item><description>Default Prng is CSPRng<cite>RNGCryptoServiceProvider</cite>, default digest is SHA512.</description></item>
    /// <item><description>Resources are disposed of automatically.</description></item>
    /// </list>
    /// </remarks>
    public sealed class KeyGenerator : IDisposable
    {
        #region Constants
        /// <summary>
        /// The default size of the counter variable in bytes
        /// </summary>
        private const int DEFAULT_COUNTER_SIZE = 8;

        /// <summary>
        /// This size disables the 2nd stage digest counter, i.e. no counter is added to the digest seed
        /// </summary>
        private const int DISABLED_COUNTER_SIZE = 0;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private IDigest _hashEngine;
        private IRandom _seedEngine;
        private Digests _dgtType;
        private Prngs _rndType;
        private byte[] _ctrVector = null;
        private int _ctrLength = DISABLED_COUNTER_SIZE;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the length of the digest counter in bytes
        /// </summary>
        public int CounterLength 
        {
            get { return _ctrLength; }
            private set { _ctrLength = value; }
        }

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
        public Prngs SeedEngine 
        {
            get { return _rndType; }
            private set { _rndType = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class.
        /// <para>Initializes the class with default generators; SHA-2 512, and RNGCryptoServiceProvider.
        /// The digest counter mechanism is set to <c>O</c> (disabled) by default.</para>
        /// </summary>
        public KeyGenerator()
        {
            // default engines
            _rndType = Prngs.CSPRng;
            _dgtType = Digests.SHA512;

            // initialize the generators
            Reset();
        }

        /// <summary>
        /// Initialize the class and generators
        /// </summary>
        /// 
        /// <param name="SeedEngine">The <see cref="Prngs">Prng</see> that supplies the key and seed material to the hash function</param>
        /// <param name="HashEngine">The <see cref="Digests">Digest</see> type used to create the pseudo random keying material</param>
        /// <param name="CounterSize">The size of the counter variable in bytes; setting to a <c>0</c> value, inactivates the digest counter; valid values are <c>0</c>, or <c>4-16</c></param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if the counter is not <c>0</c>, or a value between <c>4</c> and <c>16</c></exception>
        public KeyGenerator(Prngs SeedEngine, Digests HashEngine, int CounterSize = 0)
        {
            if (CounterSize > 16 || CounterSize < 4 && CounterSize != 0)
                throw new CryptoGeneratorException("KeyGenerator:Ctor", "The counter size must be either 0, or between 4 and 16", new ArgumentException());

            _rndType = SeedEngine;
            _dgtType = HashEngine;
            _ctrLength = CounterSize;

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
        /// <param name="IVSize">Size of Optional IV in bytes</param>
        /// <param name="IKMSize">Size of Optional IKM in bytes</param>
        /// 
        /// <returns>A populated <see cref="KeyParams"/> class</returns>
        public KeyParams GetKeyParams(int KeySize, int IVSize = 0, int IKMSize = 0)
        {
            if (IVSize > 0 && IKMSize > 0)
                return new KeyParams(Generate(KeySize), Generate(IVSize), Generate(IKMSize));
            else if (IVSize > 0)
                return new KeyParams(Generate(KeySize), Generate(IVSize));
            else if (IKMSize > 0)
                return new KeyParams(Generate(KeySize), null, Generate(IKMSize));
            else
                return new KeyParams(Generate(KeySize));
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

            // select the prng
            switch (SeedEngine)
            {
                case Prngs.CSPRng:
                    _seedEngine = new CSPRng();
                    break;
                case Prngs.CTRPrng:
                    _seedEngine = new CTRPrng();
                    break;
                case Prngs.SP20Prng:
                    _seedEngine = new SP20Prng();
                    break;
                case Prngs.DGCPrng:
                    _seedEngine = new DGCPrng();
                    break;
                case Prngs.BBSG:
                    _seedEngine = new BBSG();
                    break;
                case Prngs.CCG:
                    _seedEngine = new CCG();
                    break;
                case Prngs.MODEXPG:
                    _seedEngine = new MODEXPG();
                    break;
                case Prngs.QCG1:
                    _seedEngine = new QCG1();
                    break;
                case Prngs.QCG2:
                    _seedEngine = new QCG2();
                    break;
                default:
                    throw new InvalidOperationException("The specified PRNG type is unrecognized!");
            }

            // create the initial counter value
            if (CounterLength > 0)
                _ctrVector = _seedEngine.GetBytes(CounterLength);

            // reset hash engine
            if (_hashEngine != null)
            {
                _hashEngine.Dispose();
                _hashEngine = null;
            }

            // select the digest
            switch (HashEngine)
            {
                case Digests.Blake256:
                    _hashEngine = new Blake256();
                    break;
                case Digests.Blake512:
                    _hashEngine = new Blake512();
                    break;
                case Digests.Keccak256:
                    _hashEngine = new Keccak256();
                    break;
                case Digests.Keccak512:
                    _hashEngine = new Keccak512();
                    break;
                case Digests.SHA256:
                    _hashEngine = new SHA256();
                    break;
                case Digests.SHA512:
                    _hashEngine = new SHA512();
                    break;
                case Digests.Skein256:
                    _hashEngine = new Skein256();
                    break;
                case Digests.Skein512:
                    _hashEngine = new Skein512();
                    break;
                case Digests.Skein1024:
                    _hashEngine = new Skein1024();
                    break;
                default:
                    throw new InvalidOperationException("The specified Digest type is unrecognized!");
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
        /// Create keying material using a two stage generator Increment
        /// </remarks>
        private byte[] GetBlock()
        {
            // generate seed; 2x input block size per NIST sp800-90b
            byte[] seed = _seedEngine.GetBytes((_hashEngine.BlockSize * 2) - DISABLED_COUNTER_SIZE);

            // counter is optional
            if (CounterLength > 0)
            {
                // increment the counter
                Increment(_ctrVector);
                // prepend the counter
                seed = VTDev.Libraries.CEXEngine.Utility.ArrayUtils.Concat(_ctrVector, seed);
            }

            if (_hashEngine.GetType().Equals(typeof(SHA512)) || _hashEngine.GetType().Equals(typeof(SHA256)))
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
