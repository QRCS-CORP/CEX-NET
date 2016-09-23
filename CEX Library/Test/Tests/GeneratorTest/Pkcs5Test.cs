#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.GeneratorTest
{
    /// <summary>
    /// Tests Pkcs5 with SHA-2 vectors
    /// </summary>
    public class Pkcs5Test : ITest
    {
        #region Constants
        private const string DESCRIPTION = "KDF2 Drbg SHA-2 test vectors.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All KDF2 Drbg tests have executed succesfully.";
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
        private static readonly byte[][] _salt =
        {
            HexConverter.Decode("032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4"),
        };
        private static readonly byte[][] _output =
        {
            HexConverter.Decode("10a2403db42a8743cb989de86e668d168cbe6046e23ff26f741e87949a3bba1311ac179f819a3d18412e9eb45668f2923c087c1299005f8d5fd42ca257bc93e8fee0c5a0d2a8aa70185401fbbd99379ec76c663e9a29d0b70f3fe261a59cdc24875a60b4aacb1319fa11c3365a8b79a44669f26fba933d012db213d7e3b16349")
        };
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// Start the test
        /// </summary>
        /// 
        /// <returns>Status</returns>
        public string Run()
        {
            try
            {
                KDF2Test(_output[0].Length, _salt[0], _output[0]);
                OnProgress(new TestEventArgs("Passed KDF2 Drbg vector tests.."));

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
        private void KDF2Test(int Size, byte[] Salt, byte[] Output)
        {
            byte[] outBytes = new byte[Size];

            using (KDF2Drbg gen = new KDF2Drbg(new SHA256()))
            {
                gen.Initialize(Salt);
                gen.Generate(outBytes, 0, Size);
            }

            if (Evaluate.AreEqual(outBytes, Output) == false)
                throw new Exception("KDF2Drbg: Values are not equal! Expected: " + HexConverter.ToString(Output) + " Received: " + HexConverter.ToString(outBytes));
        }
        #endregion
    }
}
