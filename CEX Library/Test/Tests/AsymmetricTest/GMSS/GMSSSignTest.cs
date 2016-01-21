using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS;

namespace VTDev.Projects.CEX.Test.Tests.Asymmetric.GMSS
{
    /// <summary>
    /// Test the validity of the GMSS signing operations
    /// </summary>
    public class GMSSSignTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the GMSSSign implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! GMSSSign tests have executed succesfully.";
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
        /// Tests the validity of the GMSSSign implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                TestSign(GMSSParamSets.FromName(GMSSParamSets.GMSSParamNames.N2P10));
                OnProgress(new TestEventArgs("N33L5 params Passed Key Generation, Sign, and Verify Tests.."));

                // too slow on debug..
                if (!System.Diagnostics.Debugger.IsAttached)
                {
                    TestSign(GMSSParamSets.FromName(GMSSParamSets.GMSSParamNames.N2P20));
                    OnProgress(new TestEventArgs("N49L5 params Passed Key Generation, Sign, and Verify Tests.."));
                    TestSign(GMSSParamSets.FromName(GMSSParamSets.GMSSParamNames.N2P40));
                    OnProgress(new TestEventArgs("N54L5 params Passed Key Generation, Sign, and Verify Tests.."));
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
        private void TestSign(GMSSParameters CipherParam)
        {
            GMSSKeyGenerator mkgen = new GMSSKeyGenerator(CipherParam);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] data = new byte[200];
            new VTDev.Libraries.CEXEngine.Crypto.Prng.CSPPrng().GetBytes(data);

            using (GMSSSign sgn = new GMSSSign(CipherParam))
            {
                // sign the array
                sgn.Initialize(akp.PrivateKey);
                byte[] code = sgn.Sign(data, 0, data.Length);
                // verify the signature
                sgn.Initialize(akp.PublicKey);
                if (!sgn.Verify(data, 0, data.Length, code))
                    throw new Exception("RLWESignTest: Sign operation failed!");

                // get the next available key (private sub-key is used only once)
                GMSSPrivateKey nk = ((GMSSPrivateKey)akp.PrivateKey).NextKey();
                sgn.Initialize(nk);
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
