#region Directives
using System;
using VTDev.Libraries.CEXEngine.Tools;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.Tools
{
    /// <summary>
    /// Tests the compression implementation
    /// </summary>
    public class CompressionTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Tests Compression methods and interfaces.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Compression tests have executed succesfully.";
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
        /// Test vectors from NIST tests in AES specification FIPS 197
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                TestCompression();
                OnProgress(new TestEventArgs("Passed all compression tests.."));

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
        private void TestCompression()
        {
            Compress cmp = new Compress();
            MemoryStream cstm;

            /*string folder = @"C:\Tests\Compression Test";
            cstm = cmp.CompressArchive(folder);
            cstm.Position = 0;
            cmp.DeCompressArchive(cstm, folder + @"\Out");*/

            byte[] data = new CSPRng().GetBytes(1000);
            cstm = cmp.CompressStream(new MemoryStream(data));
            cstm.Position = 0;
            MemoryStream cmp2 = cmp.DeCompressStream(cstm);
            cmp2.Position = 0;

            if (!Evaluate.AreEqual(data, cmp2.ToArray()))
                throw new Exception("CompressionTest: decompressed array is not equal!");

            cmp.CompressionFormat = Compress.CompressionFormats.GZip;
            cstm = cmp.CompressStream(new MemoryStream(data));
            cstm.Position = 0;
            cmp2 = cmp.DeCompressStream(cstm);
            cmp2.Position = 0;

            if (!Evaluate.AreEqual(data, cmp2.ToArray()))
                throw new Exception("CompressionTest: decompressed array is not equal!");
        }
        #endregion
    }
}
