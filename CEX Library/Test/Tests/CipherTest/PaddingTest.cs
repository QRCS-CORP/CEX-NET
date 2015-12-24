#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
#endregion

namespace VTDev.Projects.CEX.Test.Tests
{
    /// <summary>
    /// Tests each Padding mode for valid output
    /// </summary>
    public class PaddingTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Cipher Padding output Tests.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Cipher Padding tests have executed succesfully.";
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
        /// Run the test
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                CompareOutput(new ISO7816());
                OnProgress(new TestEventArgs("PaddingTest: Passed ISO7816 comparison tests.."));
                CompareOutput(new PKCS7());
                OnProgress(new TestEventArgs("PaddingTest: Passed PKCS7 comparison tests.."));
                CompareOutput(new TBC());
                OnProgress(new TestEventArgs("PaddingTest: Passed TBC comparison tests.."));
                CompareOutput(new X923());
                OnProgress(new TestEventArgs("PaddingTest: Passed X923 comparison tests.."));

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
        void CompareOutput(IPadding Padding)
		{
			CSPRng rng = new CSPRng();
			byte[] fill =  new byte[16];
			rng.GetBytes(fill);
			const int BLOCK = 16;

			for (int i = 0; i < BLOCK; i++)
			{
				byte[] data = new byte[BLOCK];
				// fill with rand
				if (i > 0)
                    Array.Copy(fill, data, BLOCK - i);
				// pad array
				Padding.AddPadding(data, i);
				// verify length
				int plen = Padding.GetPaddingLength(data);

				if (plen != BLOCK - i)
                    throw new Exception("PaddingTest: Failed the padding value return check!");

				// test offset method
				if (i > 0 && i < 15)
				{
					plen = Padding.GetPaddingLength(data, i);

					if (plen != BLOCK - i)
                        throw new Exception("PaddingTest: Failed the offset padding value return check!");
				}
			}

            rng.Dispose();
		}
        #endregion
    }
}
