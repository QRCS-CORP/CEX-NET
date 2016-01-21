#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.MacTest
{
    /// <summary>
    /// VMAC implementation vector comparison tests.
	/// <para>Vector test used by the official documentation:
	/// <see href="http://vmpcfunction.com/vmpc_mac.pdf"/></para>
    /// </summary>
    public class VmpcMacTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "VMAC Known Answer Vector test.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All VMAC tests have executed succesfully.";
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
        private static readonly byte[] _expected = HexConverter.Decode("9BDA16E2AD0E284774A3ACBC8835A8326C11FAAD");
        private static readonly byte[] _key = HexConverter.Decode("9661410AB797D8A9EB767C21172DF6C7");
        private static readonly byte[] _iv = HexConverter.Decode("4B5C2F003E67F39557A8D26F3DA2B155");
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>Vector test used by Bouncy Castle</summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                MacTest();
                OnProgress(new TestEventArgs("Passed VMAC vector tests.."));
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
        private void MacTest()
        {
            byte[] data = new byte[256];
            byte[] hash = new byte[20];

            for (int i = 0; i < 256; i++)
                data[i] = (byte) i;

            using (VMAC mac = new VMAC())
            {
                mac.Initialize(_key, _iv);
                mac.BlockUpdate(data, 0, data.Length);
                mac.DoFinal(hash, 0);
            }

            if (!Evaluate.AreEqual(_expected, hash))
                throw new Exception("VMAC is not equal! Expected: " + HexConverter.ToString(_expected) + " Received: " + HexConverter.ToString(hash));
        }
        #endregion
    }
}
