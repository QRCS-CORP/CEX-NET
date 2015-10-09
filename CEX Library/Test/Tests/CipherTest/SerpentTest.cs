#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// Serpent homepage:
    /// http://www.cs.technion.ac.il/~biham/Reports/Serpent/
    /// The full Nessie verified vector tests, including 100 and 1000 round Monte Carlo Tests:
    /// 128 bit key: http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors
    /// 192 bit key: http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors
    /// 256 bit key: http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors
    /// Throws exception on all failures.
    /// </summary>
    public class SerpentTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Serpent Nessie tests, with 100 and 1000 round Monte Carlo runs.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All Serpent tests have executed succesfully.";
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
        /// The full Nessie verified vector tests, (2865 tests in total).
        /// Throws on all failures.
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                byte[] cip = new byte[16];
                byte[] key = new byte[16];
                byte[] pln = new byte[16];
                byte[] mnt = new byte[16];
                int rcount = 0;

                // 128 bit keys
                string cipStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentcipher128;
                string keyStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentkey128;
                string plnStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentplain128;
                string mntStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentmonte100_128;
                string mnt1kStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentmonte1000_128;

                for (int i = 0; i < keyStr.Length; i += 32)
                {
                    // less monte carlo tests than vector
                    bool doMonte = i * 32 < mntStr.Length;

                    cip = HexConverter.Decode(cipStr.Substring(i, 32));
                    key = HexConverter.Decode(keyStr.Substring(i, 32));
                    pln = HexConverter.Decode(plnStr.Substring(i, 32));

                    // reversed endian order in Nessie test vectors
                    Array.Reverse(key);
                    Array.Reverse(cip);
                    Array.Reverse(pln);

                    if (doMonte)
                    {
                        mnt = HexConverter.Decode(mntStr.Substring(i, 32));
                        Array.Reverse(mnt);
                        // monte carlo 100 rounds
                        MonteCarloTest(key, pln, mnt);
                        rcount += 100;
                        // 1000 rounds
                        mnt = HexConverter.Decode(mnt1kStr.Substring(i, 32));
                        Array.Reverse(mnt);
                        MonteCarloTest(key, pln, mnt, 1000);
                        rcount += 1000;
                    }

                    // vector comparison
                    VectorTest(key, pln, cip);
                }
                OnProgress(new TestEventArgs(String.Format("128 bit key tests: Passed Monte Carlo {0} rounds and {1} vectors tests..", rcount, keyStr.Length / 32)));
                rcount = 0;

                // 192 bit keys
                cipStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentcipher192;
                keyStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentkey192;
                plnStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentplain192;
                mntStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentmonte100_192;
                mnt1kStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentmonte1000_192;

                for (int i = 0, j = 0; j < keyStr.Length; i += 32, j += 48)
                {
                    bool doMonte = i * 32 < mntStr.Length;

                    cip = HexConverter.Decode(cipStr.Substring(i, 32));
                    key = HexConverter.Decode(keyStr.Substring(j, 48));
                    pln = HexConverter.Decode(plnStr.Substring(i, 32));

                    Array.Reverse(key);
                    Array.Reverse(cip);
                    Array.Reverse(pln);

                    if (doMonte)
                    {
                        mnt = HexConverter.Decode(mntStr.Substring(i, 32));
                        Array.Reverse(mnt);
                        // monte carlo 100 rounds
                        MonteCarloTest(key, pln, mnt);
                        rcount += 100;
                        // 1000 rounds
                        mnt = HexConverter.Decode(mnt1kStr.Substring(i, 32));
                        Array.Reverse(mnt);
                        MonteCarloTest(key, pln, mnt, 1000);
                        rcount += 1000;
                    }

                    // vector comparison
                    VectorTest(key, pln, cip);
                }
                OnProgress(new TestEventArgs(String.Format("192 bit key tests: Passed Monte Carlo {0} rounds and {1} vectors tests..", rcount, keyStr.Length / 48)));
                rcount = 0;

                // 256 bit keys
                cipStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentcipher256;
                keyStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentkey256;
                plnStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentplain256;
                mntStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentmonte100_256;
                mnt1kStr = VTDev.Projects.CEX.Test.Properties.Resources.serpentmonte1000_256;

                for (int i = 0, j = 0; j < keyStr.Length; i += 32, j += 64)
                {
                    bool doMonte = i * 32 < mntStr.Length;

                    cip = HexConverter.Decode(cipStr.Substring(i, 32));
                    key = HexConverter.Decode(keyStr.Substring(j, 64));
                    pln = HexConverter.Decode(plnStr.Substring(i, 32));

                    Array.Reverse(key);
                    Array.Reverse(cip);
                    Array.Reverse(pln);

                    if (doMonte)
                    {
                        mnt = HexConverter.Decode(mntStr.Substring(i, 32));
                        Array.Reverse(mnt);
                        // monte carlo 100 rounds
                        MonteCarloTest(key, pln, mnt);
                        rcount += 100;
                        // 1000 rounds
                        mnt = HexConverter.Decode(mnt1kStr.Substring(i, 32));
                        Array.Reverse(mnt);
                        MonteCarloTest(key, pln, mnt, 1000);
                        rcount += 1000;
                    }

                    // vector comparison
                    VectorTest(key, pln, cip);
                }
                OnProgress(new TestEventArgs(String.Format("256 bit key tests: Passed Monte Carlo {0} rounds and {1} vectors tests..", rcount, keyStr.Length / 64)));
                rcount = 0;

                // 512 bit key encrypt/decrypt self-test
                KeyTest();
                OnProgress(new TestEventArgs("Passed 512 bit key self test.."));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Private
        private void KeyTest()
        {
            byte[] inBytes = new byte[16];
            byte[] outBytes = new byte[16];
            byte[] decBytes = new byte[16];
            byte[] key = new byte[64];

            for (int i = 0; i < 16; i++)
                inBytes[i] = (byte)i;
            for (int i = 0; i < 64; i++)
                key[i] = (byte)i;

            using (SPX engine = new SPX())
            {
                engine.Initialize(true, new KeyParams(key));
                engine.EncryptBlock(inBytes, outBytes);

                engine.Initialize(false, new KeyParams(key));
                engine.DecryptBlock(outBytes, decBytes);
            }

            if (Evaluate.AreEqual(inBytes, decBytes) == false)
                throw new Exception("Serpent: Decrypted arrays are not equal! Expected: " + HexConverter.ToString(inBytes) + " Received: " + HexConverter.ToString(decBytes));
        }

        private void MonteCarloTest(byte[] Key, byte[] Input, byte[] Output, int Count = 100)
        {
            byte[] outBytes = new byte[Input.Length];
            Array.Copy(Input, 0, outBytes, 0, outBytes.Length);

            using (SPX engine = new SPX())
            {
                engine.Initialize(true, new KeyParams(Key));

                for (int i = 0; i != Count; i++)
                    engine.Transform(outBytes, outBytes);
            }

            if (Evaluate.AreEqual(outBytes, Output) == false)
                throw new Exception("Serpent MonteCarlo: Arrays are not equal! Expected: " + HexConverter.ToString(Output) + " Received: " + HexConverter.ToString(outBytes));
        }

        private void VectorTest(byte[] Key, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Output.Length];

            using (SPX enc = new SPX())
            {
                enc.Initialize(true, new KeyParams(Key));
                enc.EncryptBlock(Input, outBytes);
            }

            if (Evaluate.AreEqual(Output, outBytes) == false)
                throw new Exception("SerpentVector: Encrypted arrays are not equal! Expected: " + HexConverter.ToString(Output) + " Received: " + HexConverter.ToString(outBytes));

            using (SPX dec = new SPX())
            {
                dec.Initialize(false, new KeyParams(Key));
                dec.DecryptBlock(Output, outBytes);
            }

            if (Evaluate.AreEqual(Input, outBytes) == false)
                throw new Exception("SerpentVector: Decrypted arrays are not equal! Expected: " + HexConverter.ToString(Input) + " Received: " + HexConverter.ToString(outBytes));
        }
        #endregion
    }
}
