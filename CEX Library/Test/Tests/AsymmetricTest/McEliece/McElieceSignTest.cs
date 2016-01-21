using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece;
using VTDev.Projects.CEX.Test.Tests;

namespace VTDev.Projects.CEX.Test.Tests.Asymmetric.McEliece
{
    /// <summary>
    /// Test the validity of the signing operations
    /// </summary>
    public class McElieceSignTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the MPKCSign implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! MPKCSign tests have executed succesfully.";
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
        /// Tests the validity of the MPKCSign implementation
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
            MPKCParameters mpar = (MPKCParameters)MPKCParamSets.MPKCFM11T40S256.DeepCopy();
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();

            using (MPKCSign sgn = new MPKCSign(mpar))
            {
                sgn.Initialize(akp.PublicKey);
                int sz = sgn.MaxPlainText - 1;
                byte[] data = new byte[320];
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
