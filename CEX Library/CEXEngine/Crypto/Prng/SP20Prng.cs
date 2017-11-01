#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// SP20Prng: An implementation of a Encryption Counter based Deterministic Random Number Generator.
    /// <para>Uses the Salsa20 Key stream as a source of random input.</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example using an <c>IRandom</c> interface:</description>
    /// <code>
    /// int num;
    /// using (IRandom rnd = new SP20Prng([SeedGenerators], [BufferSize], [SeedSize], [RoundsCount]))
    /// {
    ///     // get random int
    ///     num = rnd.Next([Minimum], [Maximum]);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Valid Key sizes are 128, 256 (16 and 32 bytes).</description></item>
    /// <item><description>Block size is 64 bytes wide.</description></item>
    /// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
    /// <item><description>Parallel block size is 64,000 bytes by default; but is configurable.</description></item>
    /// </list>
    /// 
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Salsa20 <a href="http://www.ecrypt.eu.org/stream/salsa20pf.html">eSTREAM Phase 3</a>.</description></item>
    /// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/design.pdf">Design</a>.</description></item>
    /// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/security.pdf">Security</a>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class SP20Prng : IRandom
    {
        #region Constants
        private const string ALG_NAME = "SP20Prng";
        private const int BUFFER_SIZE = 4096;
        #endregion

        #region Fields
        private bool m_isDisposed = false;
        private SBG m_rngGenerator;
        private ISeed m_seedGenerator;
        private SeedGenerators m_seedType;
        private byte[] m_stateSeed;
        private byte[] m_byteBuffer;
        private int m_bufferIndex = 0;
        private int m_bufferSize = 0;
        private int m_keySize = 0;
        private int m_rndCount = 20;
        private object m_objLock = new object();
        #endregion

        #region Properties
        /// <summary>
        /// Get: The prngs type name
        /// </summary>
        public Prngs Enumeral
        {
            get { return Prngs.SP20Prng; }
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
        /// <param name="SeedEngine">The Seed engine used to create keyng material (default is CSPRsg)</param>
        /// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
        /// <param name="SeedSize">The size of the seed to generate in bytes; can be 24 for a 128 bit key or 40 for a 256 bit key</param>
        /// <param name="Rounds">The number of diffusion rounds to use when generating the key stream</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if the seed is null or invalid, or rounds count is out of range</exception>
        public SP20Prng(SeedGenerators SeedEngine = SeedGenerators.CSPRsg, int BufferSize = 4096, int SeedSize = 40, int Rounds = 20)
        {
            if (BufferSize < 64)
                throw new CryptoRandomException("SP20Prng:CTor", "Buffer size must be at least 64 bytes!", new ArgumentNullException());
            if (SeedSize != 24 && SeedSize != 40)
                throw new CryptoRandomException("SP20Prng:CTor", "Seed size must be 24 or 40 bytes (key + iv)!", new ArgumentException());
            if (Rounds < 10 || Rounds > 30 || Rounds % 2 > 0)
                throw new CryptoRandomException("SP20Prng:CTor", "Rounds must be an even number between 10 and 30!", new ArgumentOutOfRangeException());

            m_rndCount = Rounds;
            m_seedType = SeedEngine;
            m_byteBuffer = new byte[BufferSize];
            m_bufferSize = BufferSize;
            m_keySize = SeedSize;

            Reset();
        }

        /// <summary>
        /// Initialize the class with a Seed; note: the same seed will produce the same random output
        /// </summary>
        /// 
        /// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is key size + iv of 16 bytes)</param>
        /// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
        /// <param name="Rounds">The number of diffusion rounds to use when generating the key stream</param>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if the seed is null or invalid, or rounds count is out of range</exception>
        public SP20Prng(byte[] Seed, int BufferSize = 4096, int Rounds = 20)
        {
            if (Seed == null)
                throw new CryptoRandomException("SP20Prng:CTor", "The Seed can not be null!", new ArgumentNullException());
            if (BufferSize < 64)
                throw new CryptoRandomException("SP20Prng:CTor", "Buffer size must be at least 64 bytes!", new ArgumentNullException());
            if (Seed.Length != 24 && Seed.Length != 40)
                throw new CryptoRandomException("SP20Prng:CTor", "Seed size must be 24 or 40 bytes (key + iv)!", new ArgumentException());
            if (Rounds < 10 || Rounds > 30 || Rounds % 2 > 0)
                throw new CryptoRandomException("SP20Prng:CTor", "Rounds must be an even number between 10 and 30!", new ArgumentOutOfRangeException());

            m_keySize = Seed.Length;
            m_rndCount = Rounds;
            m_stateSeed = Seed;
            m_byteBuffer = new byte[BufferSize];
            m_bufferSize = BufferSize;

            Reset();
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~SP20Prng()
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
            lock (m_objLock)
            {
                if (m_byteBuffer.Length - m_bufferIndex < Output.Length)
                {
                    int bufSize = m_byteBuffer.Length - m_bufferIndex;
                    // copy remaining bytes
                    Buffer.BlockCopy(m_byteBuffer, m_bufferIndex, Output, 0, bufSize);
                    int rem = Output.Length - bufSize;

                    while (rem > 0)
                    {
                        // fill buffer
                        m_rngGenerator.Generate(m_byteBuffer);

                        if (rem > m_byteBuffer.Length)
                        {
                            Buffer.BlockCopy(m_byteBuffer, 0, Output, bufSize, m_byteBuffer.Length);
                            bufSize += m_byteBuffer.Length;
                            rem -= m_byteBuffer.Length;
                        }
                        else
                        {
                            Buffer.BlockCopy(m_byteBuffer, 0, Output, bufSize, rem);
                            m_bufferIndex = rem;
                            rem = 0;
                        }
                    }
                }
                else
                {
                    Buffer.BlockCopy(m_byteBuffer, m_bufferIndex, Output, 0, Output.Length);
                    m_bufferIndex += Output.Length;
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
            int max = (Int32.MaxValue - (Int32.MaxValue % Maximum));
            int x;
            int ret;

            do
            {
                x = Next();
                ret = x % Maximum;
            }
            while (x >= max || ret < 0);

            return ret;
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
            int range = (Maximum - Minimum + 1);
            int max = (Int32.MaxValue - (Int32.MaxValue % range));
            int x;
            int ret;

            do
            {
                x = Next();
                ret = x % range;
            }
            while (x >= max || ret < 0);

            return Minimum + ret;
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
            long max = (Int64.MaxValue - (Int64.MaxValue % Maximum));
            long x;
            long ret;

            do
            {
                x = NextLong();
                ret = x % Maximum;
            }
            while (x >= max || ret < 0);

            return ret;
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
            long range = (Maximum - Minimum + 1);
            long max = (Int64.MaxValue - (Int64.MaxValue % range));
            long x;
            long ret;

            do
            {
                x = NextLong();
                ret = x % range;
            }
            while (x >= max || ret < 0);

            return Minimum + ret;
        }

        /// <summary>
        /// Reset the SP20Prng instance
        /// </summary>
        public void Reset()
        {
            if (m_seedGenerator != null)
            {
                m_seedGenerator.Dispose();
                m_seedGenerator = null;
            }
            if (m_rngGenerator != null)
            {
                m_rngGenerator.Dispose();
                m_rngGenerator = null;
            }

            m_seedGenerator = GetSeedGenerator(m_seedType);
            m_rngGenerator = new SBG(m_rndCount);

            if (m_seedGenerator != null)
                m_rngGenerator.Initialize(m_seedGenerator.GetBytes(m_keySize));
            else
                m_rngGenerator.Initialize(m_stateSeed);

            m_rngGenerator.Generate(m_byteBuffer);
            m_bufferIndex = 0;
        }
        #endregion

        #region Private Methods
        private int GetKeySize()
        {
            return m_keySize;
        }

        private ISeed GetSeedGenerator(SeedGenerators SeedEngine)
        {
            try
            {
                return SeedGeneratorFromName.GetInstance(SeedEngine);
            }
            catch (Exception Ex)
            {
                throw new CryptoRandomException("SP20Prng:GetSeedGenerator", "The seed generator could not be initialized!", Ex);
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
            if (!m_isDisposed && Disposing)
            {
                try
                {
                    if (m_rngGenerator != null)
                    {
                        m_rngGenerator.Dispose();
                        m_rngGenerator = null;
                    }
                    if (m_seedGenerator != null)
                    {
                        m_seedGenerator.Dispose();
                        m_seedGenerator = null;
                    }
                    if (m_byteBuffer != null)
                    {
                        Array.Clear(m_byteBuffer, 0, m_byteBuffer.Length);
                        m_byteBuffer = null;
                    }
                    if (m_stateSeed != null)
                    {
                        Array.Clear(m_stateSeed, 0, m_stateSeed.Length);
                        m_stateSeed = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
