#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.GeneratorTest
{
    /// <summary>
    /// Tests DGCDRBG KAT vectors
    /// </summary>
    public class DgcDrbgTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "DGCDRBG Known Answer Test Vectors.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All DGCDRBG tests have executed succesfully.";
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
        private static readonly byte[][] _seed = 
        { 
            new byte[] { 0, 0, 0, 0, 0, 0, 0, 0},
            HexConverter.Decode("81dcfafc885914057876")
        };

        private static readonly byte[][] _expected = 
        {
            HexConverter.Decode("587e2dfd597d086e47ddcd343eac983a5c913bef8c6a1a560a5c1bc3a74b0991"),
            HexConverter.Decode("bdab3ca831b472a2fa09bd1bade541ef16c96640a91fcec553679a136061de98")
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
        /// SHA-2 Vectors used by BouncY Castle
        /// </summary>
        /// 
        /// <returns>Status</returns>
        public string Run()
        {
            try
            {
                DGCDRBGTest(_seed[0], _expected[0]);
                DGCDRBGTest(_seed[1], _expected[1]);
                OnProgress(new TestEventArgs("Passed DGCDRBG vector tests.."));

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
        private void DGCDRBGTest(byte[] Seed, byte[] Expected)
        {
            DGC rGen = new DGC(new SHA256());

            byte[] output = new byte[32];

            rGen.Update(Seed);

            for (int i = 0; i != 1024; i++)
                rGen.Generate(output);

            if (Evaluate.AreEqual(Expected, output) == false)
                throw new Exception("DGCDRBG: Values are not equal! Expected: " + HexConverter.ToString(output) + " Received: " + HexConverter.ToString(Expected));
        }
        #endregion
    }
}
