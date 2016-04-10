#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// Test vectors from the NIST standard tests contained in the AES specification document FIPS 197:
    /// <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"></a>
    /// Monte Carlo AES tests from the Brian Gladman vector set:
    /// <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/"></a>
    /// </summary>
    public class AesFipsTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "NIST AES specification FIPS 197 Known Answer Tests.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! AES tests have executed succesfully.";
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
        private static readonly byte[][] _keys =
		{
            // fips
			HexConverter.Decode("80000000000000000000000000000000"),
			HexConverter.Decode("00000000000000000000000000000080"),
			HexConverter.Decode("000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
			HexConverter.Decode("80000000000000000000000000000000"),
			HexConverter.Decode("00000000000000000000000000000080"),
            HexConverter.Decode("000000000000000000000000000000000000000000000000"),
			HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
			HexConverter.Decode("80000000000000000000000000000000"),
            HexConverter.Decode("00000000000000000000000000000080"),
			HexConverter.Decode("000000000000000000000000000000000000000000000000"),
			HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
            // gladman
            HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("5F060D3716B345C253F6749ABAC10917"),
			HexConverter.Decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
            HexConverter.Decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("5F060D3716B345C253F6749ABAC10917"),
            HexConverter.Decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			HexConverter.Decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			HexConverter.Decode("00000000000000000000000000000000"),
            HexConverter.Decode("5F060D3716B345C253F6749ABAC10917"),
			HexConverter.Decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			HexConverter.Decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")
		};

        private static readonly byte[][] _plainText =
		{
			HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("80000000000000000000000000000000"),
            HexConverter.Decode("80000000000000000000000000000000"),
			HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("00000000000000000000000000000000"),
            HexConverter.Decode("80000000000000000000000000000000"),
			HexConverter.Decode("80000000000000000000000000000000"),
			HexConverter.Decode("00000000000000000000000000000000"),
            HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("80000000000000000000000000000000"),
			HexConverter.Decode("80000000000000000000000000000000"),
            // gladman
            HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("355F697E8B868B65B25A04E18D782AFA"),
			HexConverter.Decode("F3F6752AE8D7831138F041560631B114"),
            HexConverter.Decode("C737317FE0846F132B23C8C2A672CE22"),
			HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("355F697E8B868B65B25A04E18D782AFA"),
            HexConverter.Decode("F3F6752AE8D7831138F041560631B114"),
			HexConverter.Decode("C737317FE0846F132B23C8C2A672CE22"),
			HexConverter.Decode("00000000000000000000000000000000"),
            HexConverter.Decode("355F697E8B868B65B25A04E18D782AFA"),
			HexConverter.Decode("F3F6752AE8D7831138F041560631B114"),
			HexConverter.Decode("C737317FE0846F132B23C8C2A672CE22")
		};

        private static readonly byte[][] _cipherText =
		{
            // fips
			HexConverter.Decode("0EDD33D3C621E546455BD8BA1418BEC8"),
			HexConverter.Decode("172AEAB3D507678ECAF455C12587ADB7"),
			HexConverter.Decode("6CD02513E8D4DC986B4AFE087A60BD0C"),
            HexConverter.Decode("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			HexConverter.Decode("0EDD33D3C621E546455BD8BA1418BEC8"),
			HexConverter.Decode("172AEAB3D507678ECAF455C12587ADB7"),
            HexConverter.Decode("6CD02513E8D4DC986B4AFE087A60BD0C"),
			HexConverter.Decode("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			HexConverter.Decode("0EDD33D3C621E546455BD8BA1418BEC8"),
            HexConverter.Decode("172AEAB3D507678ECAF455C12587ADB7"),
			HexConverter.Decode("6CD02513E8D4DC986B4AFE087A60BD0C"),
			HexConverter.Decode("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
            // gladman
            HexConverter.Decode("C34C052CC0DA8D73451AFE5F03BE297F"),
			HexConverter.Decode("ACC863637868E3E068D2FD6E3508454A"),
			HexConverter.Decode("77BA00ED5412DFF27C8ED91F3C376172"),
            HexConverter.Decode("E58B82BFBA53C0040DC610C642121168"),
			HexConverter.Decode("C34C052CC0DA8D73451AFE5F03BE297F"),
			HexConverter.Decode("ACC863637868E3E068D2FD6E3508454A"),
            HexConverter.Decode("77BA00ED5412DFF27C8ED91F3C376172"),
			HexConverter.Decode("E58B82BFBA53C0040DC610C642121168"),
			HexConverter.Decode("C34C052CC0DA8D73451AFE5F03BE297F"),
            HexConverter.Decode("ACC863637868E3E068D2FD6E3508454A"),
			HexConverter.Decode("77BA00ED5412DFF27C8ED91F3C376172"),
			HexConverter.Decode("E58B82BFBA53C0040DC610C642121168")
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
        /// Test vectors from NIST tests in AES specification FIPS 197
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                for (int i = 0; i < 12; i++)
                    VectorTest(_keys[i], _plainText[i], _cipherText[i]);
                OnProgress(new TestEventArgs("Passed FIPS 197 Monte Carlo tests.."));

                for (int i = 12; i < _plainText.Length; i++)
                    MonteCarloTest(_keys[i], _plainText[i], _cipherText[i]);
                OnProgress(new TestEventArgs("Passed Extended Monte Carlo tests.."));

                return SUCCESS;
            }
            catch(Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Private
        private void VectorTest(byte[] Key, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Input.Length];

            using (RHX engine = new RHX())
            {
                engine.Initialize(true, new KeyParams(Key));
                engine.Transform(Input, outBytes);

                if (Evaluate.AreEqual(outBytes, Output) == false)
                    throw new Exception("AES: Encrypted arrays are not equal! Expected: " + HexConverter.ToString(Output) + " Received: " + HexConverter.ToString(outBytes));

                engine.Initialize(false, new KeyParams(Key));
                engine.Transform(Output, outBytes);

                if (Evaluate.AreEqual(outBytes, Input) == false)
                    throw new Exception("AES: Decrypted arrays are not equal! Expected: " + HexConverter.ToString(Input) + " Received: " + HexConverter.ToString(outBytes));
            }
        }

        private void MonteCarloTest(byte[] Key, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Input.Length];
            Array.Copy(Input, 0, outBytes, 0, outBytes.Length);

            using (RHX engine = new RHX())
            {
                engine.Initialize(true, new KeyParams(Key));

                for (int i = 0; i != 10000; i++)
                    engine.Transform(outBytes, outBytes);
            }

            if (Evaluate.AreEqual(outBytes, Output) == false)
                throw new Exception("AES MonteCarlo: Arrays are not equal! Expected: " + HexConverter.ToString(Output) + " Received: " + HexConverter.ToString(outBytes));

            using (RHX engine = new RHX())
            {
                engine.Initialize(false, new KeyParams(Key));

                for (int i = 0; i != 10000; i++)
                    engine.Transform(outBytes, outBytes);
            }

            if (Evaluate.AreEqual(outBytes, Input) == false)
                throw new Exception("AES MonteCarlo: Arrays are not equal! Expected: " + HexConverter.ToString(Input) + " Received: " + HexConverter.ToString(outBytes));
        }
        #endregion
    }
}
