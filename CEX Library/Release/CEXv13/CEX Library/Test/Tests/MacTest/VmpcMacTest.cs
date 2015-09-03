#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.MacTest
{
    /// <summary>
    /// Vector test used by Bouncy Castle:
    /// http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/test/VMPCMacTest.java?av=f
    /// </summary>
    public class VmpcMacTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "VMPCMAC Known Answer Vector test.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All VMPCMAC tests have executed succesfully.";
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
        private static readonly byte[] _expected = Hex.Decode("9BDA16E2AD0E284774A3ACBC8835A8326C11FAAD");
        private static readonly byte[] _key = Hex.Decode("9661410AB797D8A9EB767C21172DF6C7");
        private static readonly byte[] _iv = Hex.Decode("4B5C2F003E67F39557A8D26F3DA2B155");
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
        public string Test()
        {
            try
            {
                MacTest();
                OnProgress(new TestEventArgs("Passed VMPCMAC vector tests.."));
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

            using (VMPCMAC mac = new VMPCMAC())
            {
                mac.Initialize(new KeyParams(_key, _iv));
                mac.BlockUpdate(data, 0, data.Length);
                mac.DoFinal(hash, 0);
            }

            if (!Compare.AreEqual(_expected, hash))
                throw new Exception("VMPCMAC is not equal! Expected: " + Hex.ToString(_expected) + "Received: " + Hex.ToString(hash));
        }
        #endregion
    }
}
