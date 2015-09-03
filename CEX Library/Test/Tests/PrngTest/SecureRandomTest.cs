#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.PrngTest
{
    /// <summary>
    /// Tests the SecureRandom and Prng access methods and return ranges
    /// </summary>
    public class SecureRandomTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "PRNG Test: Tests I/O, access methods, and expected return ranges.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All PRNG tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// Tests the SecureRandom access methods and return ranges
        /// </summary>
        /// <returns>Status</returns>
        public string Test()
        {
            try
            {
                SecRandTest();

                RandRangeTest(new BBSG(), 10);
                OnProgress(new TestEventArgs("Passed BBSG threshhold tests.."));
                RandRangeTest(new CCG(), 10);
                OnProgress(new TestEventArgs("Passed CCG threshhold tests.."));
                RandRangeTest(new CSPRng());
                OnProgress(new TestEventArgs("Passed CSPRng threshhold tests.."));
                RandRangeTest(new CTRPrng());
                OnProgress(new TestEventArgs("Passed CTRPrng threshhold tests.."));
                RandRangeTest(new DGCPrng());
                OnProgress(new TestEventArgs("Passed DGCPrng threshhold tests.."));
                RandRangeTest(new MODEXPG(), 10);
                OnProgress(new TestEventArgs("Passed MODEXPG threshhold tests.."));
                RandRangeTest(new QCG1(), 10);
                OnProgress(new TestEventArgs("Passed QCG1 threshhold tests.."));
                RandRangeTest(new QCG2(), 10);
                OnProgress(new TestEventArgs("Passed QCG2 threshhold tests.."));
                RandRangeTest(new SP20Prng(), 10);
                OnProgress(new TestEventArgs("Passed SP20Prng threshhold tests.."));


                byte[] pass, salt;
                CSPRng rand = new CSPRng();
                pass = rand.GetBytes(23);
                salt = rand.GetBytes(256);
                rand.Dispose();
                RandRangeTest(new PBPRng(new SHA512(), pass, salt));
                OnProgress(new TestEventArgs("Passed PBPRng threshhold tests.."));
                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Tests
        private void RandRangeTest(IRandom Rand, int Iterations = 1000)
        {
            byte[] data;
            int x;
            long y;
            int min, max;
            min = Rand.Next(33);
            max = Rand.Next(34, 111);

            for (int i = 0; i < Iterations; i++)
                data = Rand.GetBytes(i * 10);

            for (int i = 1; i < Iterations; i++)
            {
                x = Rand.Next(i * min, i * max);
                if (x > i * max)
                    throw new Exception(Rand.Name + ":Next returned a value above of the expected range.");
                if (x < i * min)
                    throw new Exception(Rand.Name + ":Next returned a value below of the expected range.");
                y = Rand.NextLong(i * min, i * max);
                if (y > i * max)
                    throw new Exception(Rand.Name + ":NextLong returned a value above of the expected range.");
                if (y < i * min)
                    throw new Exception(Rand.Name + ":NextLong returned a value below of the expected range.");
            }
        }

        private void SecRandTest()
        {
            using (SecureRandom rnd = new SecureRandom())
            {
                double x1 = 0.0;
                for (int i = 0; i < 1000; i++)
                {
                    x1 = rnd.NextDouble();
                    if (x1 > 1.0)
                        throw new Exception("SecureRandom: NextDouble returned a value outside of the expected range.");
                }

                short x2 = 0;
                for (int i = 0; i < 1000; i++)
                {
                    x2 = rnd.NextInt16(1, 6);
                    if (x2 > 6)
                        throw new Exception("SecureRandom: NextInt16 returned a value outside of the expected range.");
                    if (x2 < 1)
                        throw new Exception("SecureRandom: NextInt16 returned a value outside of the expected range.");
                }

                ushort x3 = 0;
                for (int i = 0; i < 1000; i++)
                {
                    x3 = rnd.NextUInt16(1, 52);
                    if (x3 > 52)
                        throw new Exception("SecureRandom: NextUInt16 returned a value outside of the expected range.");
                    if (x3 < 1)
                        throw new Exception("SecureRandom: NextUInt16 returned a value outside of the expected range.");
                }

                int x4 = 0;
                for (int i = 0; i < 1000; i++)
                {
                    x4 = rnd.NextInt32(3371, 16777216);
                    if (x4 > 16777216)
                        throw new Exception("SecureRandom: NextInt32 returned a value outside of the expected range.");
                    if (x4 < 3371)
                        throw new Exception("SecureRandom: NextInt32 returned a value outside of the expected range.");
                }

                uint x5 = 0;
                for (int i = 0; i < 1000; i++)
                {
                    x5 = rnd.NextUInt32(77721, 777216);
                    if (x5 > 777216)
                        throw new Exception("SecureRandom: NextUInt32 returned a value outside of the expected range.");
                    if (x5 < 77721)
                        throw new Exception("SecureRandom: NextUInt32 returned a value outside of the expected range.");
                }

                long x6 = 0;
                for (int i = 0; i < 1000; i++)
                {
                    x6 = rnd.NextInt64(2814749767, 281474976710653);
                    if (x6 > 281474976710656)
                        throw new Exception("SecureRandom: NextInt64 returned a value outside of the expected range.");
                    if (x6 < 2814749767)
                        throw new Exception("SecureRandom: NextInt64 returned a value outside of the expected range.");
                }

                ulong x7 = 0;
                for (int i = 0; i < 1000; i++)
                {
                    x7 = rnd.NextUInt64(5759403792, 72057594037927934);
                    if (x7 > 72057594037927936)
                        throw new Exception("SecureRandom: NextUInt64 returned a value outside of the expected range.");
                    if (x7 < 5759403792)
                        throw new Exception("SecureRandom: NextUInt64 returned a value outside of the expected range.");
                }
            }
        }
        #endregion
    }
}
