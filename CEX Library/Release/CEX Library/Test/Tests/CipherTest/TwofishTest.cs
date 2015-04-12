#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Utility;
using VTDev.Projects.CEX.Test.Helper;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// Official TwoFish key vectors: https://www.schneier.com/twofish.html
    /// </summary>
    public class TwofishTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Official Twofish Known Answer Tests (over 60,000 rounds).";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All Twofish tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Vectors
        private static byte[] _plainText = Hex.Decode("00000000000000000000000000000000");
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// Official TwoFish key vectors
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                byte[] cip = new byte[16];
                byte[] key = new byte[16];

                // vector tests //
                // 128 bit keys
                string cipStr = VTDev.Projects.CEX.Test.Properties.Resources.twofishcipher_128;
                string keyStr = VTDev.Projects.CEX.Test.Properties.Resources.twofishkey_128;

                for (int i = 0; i < keyStr.Length; i += 32)
                {
                    cip = Hex.Decode(cipStr.Substring(i, 32));
                    key = Hex.Decode(keyStr.Substring(i, 32));

                    // vector comparison
                    VectorTest(key, _plainText, cip);
                }
                OnProgress(new TestEventArgs("Passed Twofish 128 bit key vector tests.."));

                // 192 bit keys
                cipStr = VTDev.Projects.CEX.Test.Properties.Resources.twofishcipher_192;
                keyStr = VTDev.Projects.CEX.Test.Properties.Resources.twofishkey_192;

                for (int i = 0, j = 0; j < keyStr.Length; i += 32, j += 48)
                {
                    cip = Hex.Decode(cipStr.Substring(i, 32));
                    key = Hex.Decode(keyStr.Substring(j, 48));

                    // vector comparison
                    VectorTest(key, _plainText, cip);
                }
                OnProgress(new TestEventArgs("Passed Twofish 192 bit key vector tests.."));

                // 256 bit keys
                cipStr = VTDev.Projects.CEX.Test.Properties.Resources.twofishcipher_256;
                keyStr = VTDev.Projects.CEX.Test.Properties.Resources.twofishkey_256;

                for (int i = 0, j = 0; j < keyStr.Length; i += 32, j += 64)
                {
                    cip = Hex.Decode(cipStr.Substring(i, 32));
                    key = Hex.Decode(keyStr.Substring(j, 64));

                    // vector comparison
                    VectorTest(key, _plainText, cip);
                }
                OnProgress(new TestEventArgs("Passed Twofish 256 bit key vector tests.."));

                // monte carlo tests: //
                // encrypt 10,000 rounds each
                key = new byte[16];
                byte[] output = Hex.Decode("282BE7E4FA1FBDC29661286F1F310B7E");
                // 128 key
                MonteCarloTest(key, _plainText, output);
                OnProgress(new TestEventArgs("Passed 10,000 round 128 bit key Monte Carlo encryption test.."));

                // 192 key
                key = new byte[24];
                output = Hex.Decode("9AB71D7F280FF79F0D135BBD5FAB7E37");
                MonteCarloTest(key, _plainText, output);
                OnProgress(new TestEventArgs("Passed 10,000 round 192 bit key Monte Carlo encryption test.."));

                // 256 key
                key = new byte[32];
                output = Hex.Decode("04F2F36CA927AE506931DE8F78B2513C");
                MonteCarloTest(key, _plainText, output);
                OnProgress(new TestEventArgs("Passed 10,000 round 256 bit key Monte Carlo encryption test.."));

                // decrypt 10,000 rounds
                key = new byte[16];
                output = Hex.Decode("21D3F7F6724513946B72CFAE47DA2EED");
                // 128 key
                MonteCarloTest(key, _plainText, output, false);
                OnProgress(new TestEventArgs("Passed 10,000 round 128 bit key Monte Carlo decryption test.."));

                // 192 key
                key = new byte[24];
                output = Hex.Decode("B4582FA55072FCFEF538F39072F234A9");
                MonteCarloTest(key, _plainText, output, false);
                OnProgress(new TestEventArgs("Passed 10,000 round 192 bit key Monte Carlo decryption test.."));

                // 256 key
                key = new byte[32];
                output = Hex.Decode("BC7D078C4872063869DEAB891FB42761");
                MonteCarloTest(key, _plainText, output, false);
                OnProgress(new TestEventArgs("Passed 10,000 round 256 bit key Monte Carlo decryption test.."));

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
        private void MonteCarloTest(byte[] Key, byte[] Input, byte[] Output, bool Encrypt = true, int Count = 10000)
        {
            byte[] outBytes = new byte[Input.Length];
            Array.Copy(Input, 0, outBytes, 0, outBytes.Length);

            using (TFX engine = new TFX())
            {
                engine.Initialize(Encrypt, new KeyParams(Key));

                for (int i = 0; i < Count; i++)
                    engine.Transform(outBytes, outBytes);
            }

            if (Compare.AreEqual(outBytes, Output) == false)
                throw new Exception("Twofish MonteCarlo: Arrays are not equal! Expected: " + Hex.ToString(Output) + "Received: " + Hex.ToString(outBytes));
        }

        private void VectorTest(byte[] Key, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Input.Length];

            using (TFX tfx = new TFX())
            {
                tfx.Initialize(true, new KeyParams(Key));
                tfx.EncryptBlock(Input, outBytes);
            }

            if (Compare.AreEqual(outBytes, Output) == false)
                throw new Exception("Twofish Vector: Encrypted arrays are not equal! Expected: " + Hex.ToString(Output) + "Received: " + Hex.ToString(outBytes));

            using (TFX tfx = new TFX())
            {
                tfx.Initialize(false, new KeyParams(Key));
                tfx.Transform(Output, outBytes);
            }

            if (Compare.AreEqual(outBytes, Input) == false)
                throw new Exception("Twofish Vector: Decrypted arrays are not equal! Expected: " + Hex.ToString(Input) + "Received: " + Hex.ToString(outBytes));
        }
        #endregion
    }
}
