using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW;

namespace VTDev.Projects.CEX.Test.Tests.Asymmetric.RNBW
{
    /// <summary>
    /// Test the validity of the Rainbow signing operations
    /// </summary>
    public class RNBWSignTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the RNBWSign implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! RNBWSign tests have executed succesfully.";
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
        /// Tests the validity of the RNBWSign implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                TestSign(RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N33L5));
                OnProgress(new TestEventArgs("N33L5 params Passed Key Generation, Sign, and Verify Tests.."));

                if (!System.Diagnostics.Debugger.IsAttached)
                {
                    TestSign(RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N49L5));
                    OnProgress(new TestEventArgs("N49L5 params Passed Key Generation, Sign, and Verify Tests.."));
                    TestSign(RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N54L5));
                    OnProgress(new TestEventArgs("N54L5 params Passed Key Generation, Sign, and Verify Tests.."));
                    TestSign(RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N58L5));
                    OnProgress(new TestEventArgs("N58L5 params Passed Key Generation, Sign, and Verify Tests.."));
                    TestSign(RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N60L5));
                    OnProgress(new TestEventArgs("N60L5 params Passed Key Generation, Sign, and Verify Tests.."));
                    /*TestSign(RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N63L5));
                    OnProgress(new TestEventArgs("N63L5 params Passed Key Generation, Sign, and Verify Tests.."));
                    TestSign(RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N66L5));
                    OnProgress(new TestEventArgs("N66L5 params Passed Key Generation, Sign, and Verify Tests.."));*/
                }

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
        private void TestSign(RNBWParameters CipherParam)
        {
            RNBWKeyGenerator mkgen = new RNBWKeyGenerator(CipherParam);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] data = new byte[200];
            new VTDev.Libraries.CEXEngine.Crypto.Prng.CSPPrng().GetBytes(data);

            using (RNBWSign sgn = new RNBWSign(CipherParam))
            {
                // sign the array
                sgn.Initialize(akp.PrivateKey);
                byte[] code = sgn.Sign(data, 0, data.Length);
                // verify the signature
                sgn.Initialize(akp.PublicKey);
                if (!sgn.Verify(data, 0, data.Length, code))
                    throw new Exception("RLWESignTest: Sign operation failed!");

                // sign and test stream ctor
                sgn.Initialize(akp.PrivateKey);
                code = sgn.Sign(new MemoryStream(data));
                // verify the signature
                sgn.Initialize(akp.PublicKey);
                if (!sgn.Verify(new MemoryStream(data), code))
                    throw new Exception("RLWESignTest: Verify test failed!");
            }
        }
        #endregion
    }
}
