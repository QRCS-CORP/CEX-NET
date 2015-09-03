#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.MacTest
{
    /// <summary>
    /// Tests used by Bouncy Castle:
    /// http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/test/CMacTest.java?av=f
    /// </summary>
    public class CMacTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "CMAC Known Answer Test Vectors for 128/192/256 bit Keys.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All CMAC tests have executed succesfully.";
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
        private static readonly byte[][] _keys = 
        {
            Hex.Decode("2b7e151628aed2a6abf7158809cf4f3c"),
            Hex.Decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
            Hex.Decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        };

        private static readonly byte[][] _input = 
        {
            Hex.Decode(""),
            Hex.Decode("6bc1bee22e409f96e93d7e117393172a"),
            Hex.Decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
            Hex.Decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
        };

        private static readonly byte[][] _expected = 
        {
            Hex.Decode("bb1d6929e95937287fa37d129b756746"),
            Hex.Decode("070a16b46b4d4144f79bdd9dd04a287c"),
            Hex.Decode("dfa66747de9ae63030ca32611497c827"),
            Hex.Decode("51f0bebf7e3b9d92fc49741779363cfe"),
            Hex.Decode("d17ddf46adaacde531cac483de7a9367"),
            Hex.Decode("9e99a7bf31e710900662f65e617c5184"),
            Hex.Decode("8a1de5be2eb31aad089a82e6ee908b0e"),
            Hex.Decode("a1d5df0eed790f794d77589659f39a11"),
            Hex.Decode("028962f61b7bf89efc6b551f4667d983"),
            Hex.Decode("28a7023f452e8f82bd4bf28d8c37c35c"),
            Hex.Decode("aaf3d8f1de5640c232f5b169b9c911e6"),
            Hex.Decode("e1992190549f6ed5696a2c056c315410")
        };
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary></summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                MacTest(_keys[0], _input[0], _expected[0]);
                MacTest(_keys[0], _input[1], _expected[1]);
                MacTest(_keys[0], _input[2], _expected[2]);
                MacTest(_keys[0], _input[3], _expected[3]);
                OnProgress(new TestEventArgs("Passed 128 bit key vector tests.."));

                MacTest(_keys[1], _input[0], _expected[4]);
                MacTest(_keys[1], _input[1], _expected[5]);
                MacTest(_keys[1], _input[2], _expected[6]);
                MacTest(_keys[1], _input[3], _expected[7]);
                OnProgress(new TestEventArgs("Passed 192 bit key vector tests.."));

                MacTest(_keys[2], _input[0], _expected[8]);
                MacTest(_keys[2], _input[1], _expected[9]);
                MacTest(_keys[2], _input[2], _expected[10]);
                MacTest(_keys[2], _input[3], _expected[11]);
                OnProgress(new TestEventArgs("Passed 256 bit key vector tests.."));

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
        private void MacTest(byte[] Key, byte[] Input, byte[] Expected)
        {
            byte[] hash = new byte[16];

            using (CMAC mac = new CMAC(new RDX(), 128))
            {
                mac.Initialize(new KeyParams(Key));
                mac.BlockUpdate(Input, 0, Input.Length);
                mac.DoFinal(hash, 0);
            }

            if (!Compare.AreEqual(Expected, hash))
                throw new Exception("CMAC is not equal! Expected: " + Hex.ToString(Expected) + "Received: " + Hex.ToString(hash));
        }
        #endregion
    }
}
