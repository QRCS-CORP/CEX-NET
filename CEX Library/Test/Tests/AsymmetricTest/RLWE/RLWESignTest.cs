using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Projects.CEX.Test.Tests;

namespace Test.Tests
{
    /// <summary>
    /// Test the validity of the signing operations
    /// </summary>
    public class RLWESignTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the RLWESign implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! RLWESign tests have executed succesfully.";
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
        /// Tests the validity of the RLWESign implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                TestSign();

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Private Methods
        private void TestSign()
        {
            RLWEParameters mpar = (RLWEParameters)RLWEParamSets.RLWEN512Q12289.DeepCopy();
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();

            using (RLWESign sgn = new RLWESign(mpar))
            {
                sgn.Initialize(akp.PublicKey);

                int sz = sgn.MaxPlainText;
                byte[] data = new byte[200];
                new VTDev.Libraries.CEXEngine.Crypto.Prng.CSPPrng().GetBytes(data);

                byte[] code = sgn.Sign(data, 0, data.Length);

                sgn.Initialize(akp.PrivateKey);
                if (!sgn.Verify(data, 0, data.Length, code))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
                OnProgress(new TestEventArgs("Passed byte sign and verify"));

                sgn.Initialize(akp.PublicKey);
                code = sgn.Sign(new MemoryStream(data));

                sgn.Initialize(akp.PrivateKey);
                if (!sgn.Verify(new MemoryStream(data), code))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
                OnProgress(new TestEventArgs("Passed stream sign and verify"));
            }
        }
        #endregion
    }
}
