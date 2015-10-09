#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.AsymmetricTest.NTRU.Encrypt
{
    /// <summary>
    /// Test the validity of the NtruParameters implementation
    /// </summary>
    public class NtruParametersTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the NtruParameters implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! NtruParameters tests have executed succesfully.";
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
        /// NtruParameters test
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                LoadSave();
                OnProgress(new TestEventArgs("Passed parameters load and save tests"));
                Clone();
                OnProgress(new TestEventArgs("Passed parameters clone tests"));

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
        public void LoadSave()
        {
            NTRUParameters param = (NTRUParameters)NTRUParamSets.EES1499EP1.DeepCopy();
            MemoryStream os = new MemoryStream();
            param.WriteTo(os);
            MemoryStream ins = new MemoryStream(os.ToArray());
            if (!Evaluate.Equals(param, new NTRUParameters(ins)))
                throw new Exception("NtruParameters: load and save test failed!");
        }

        public void Clone()
        {
            NTRUParameters param = NTRUParamSets.APR2011439;
            NTRUParameters param2 = (NTRUParameters)param.DeepCopy();
            if (!Evaluate.Equals(param, param2))
                throw new Exception("NtruParameters: cloned copy is not equal!");

            param = NTRUParamSets.APR2011439FAST;
            param2 = (NTRUParameters)param.DeepCopy();

            if (!Evaluate.Equals(param, param2)) 
                throw new Exception("NtruParameters: cloned copy is not equal!");

            param2.Digest = Digests.Blake512;
            if (Evaluate.Equals(param, param2))
                throw new Exception("NtruParameters: cloned copy is not equal!");
        }
        #endregion
    }
}