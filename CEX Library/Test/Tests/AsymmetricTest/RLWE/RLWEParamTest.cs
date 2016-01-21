using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Projects.CEX.Test.Tests;

namespace Test.Tests
{
    /// <summary>
    /// Test the validity of the Ring-LWE Parameters implementation
    /// </summary>
    public class RLWEParamTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the Ring-LWE Parameters implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Parameters tests have executed succesfully.";
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
        /// Tests the validity of the Ring-LWE Parameters implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                TestParams();
                OnProgress(new TestEventArgs("Passed parameters comparison tests"));

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
        private void TestParams()
        {
            RLWEParameters mpar = (RLWEParameters)RLWEParamSets.RLWEN256Q7681.DeepCopy();
            byte[] enc = mpar.ToBytes();

            using (RLWEParameters mpar2 = RLWEParameters.From(enc))
            {
                if (!mpar.Equals(mpar2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
            }
            OnProgress(new TestEventArgs("Passed parameters byte serialization"));

            MemoryStream mstr = mpar.ToStream();
            using (RLWEParameters mpar2 = RLWEParameters.From(mstr))
            {
                if (!mpar.Equals(mpar2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
            }
            OnProgress(new TestEventArgs("Passed parameters stream serialization"));
        }
        #endregion
    }
}
