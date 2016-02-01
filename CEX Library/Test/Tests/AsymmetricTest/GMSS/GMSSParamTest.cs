using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS;

namespace VTDev.Projects.CEX.Test.Tests.Asymmetric.GMSS
{
    /// <summary>
    /// Test the validity of the GMSS Parameters implementation
    /// </summary>
    public class GMSSParamTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the GMSS Parameters implementation";
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
        /// Tests the validity of the GMSS Parameters implementation
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
            GMSSParameters mpar = GMSSParamSets.GMSSN2P10;
            byte[] enc = mpar.ToBytes();

            using (GMSSParameters mpar2 = GMSSParameters.From(enc))
            {
                if (!mpar.Equals(mpar2))
                    throw new Exception("Parameters: public key comparison test failed!");
                if (mpar.GetHashCode() != mpar2.GetHashCode())
                    throw new Exception("Parameters: parameters hash test failed!");
            }
            OnProgress(new TestEventArgs("Passed parameters byte serialization"));

            MemoryStream mstr = mpar.ToStream();
            using (GMSSParameters mpar2 = GMSSParameters.From(mstr))
            {
                if (!mpar.Equals(mpar2))
                    throw new Exception("Parameters: public key comparison test failed!");
                if (mpar.GetHashCode() != mpar2.GetHashCode())
                    throw new Exception("Parameters: parameters hash test failed!");
            }
            OnProgress(new TestEventArgs("Passed parameters stream serialization"));
        }
        #endregion
    }
}
