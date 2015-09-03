using System;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Utility;

namespace VTDev.Projects.CEX
{
    /// <summary>
    /// Test vectors from the NIST standard tests contained in the AES specification document FIPS 197:
    /// <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"></a>
    /// Monte Carlo AES tests from the Brian Gladman's vector set:
    /// <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/"></a>
    /// </summary>
    public class AesFipsTest //: IVectorTest
    {
        #region Vectors
        private static readonly byte[][] _keys =
		{
            // fips
			Hex.Decode("80000000000000000000000000000000"),
			Hex.Decode("00000000000000000000000000000080"),
			Hex.Decode("000000000000000000000000000000000000000000000000"),
            Hex.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
			Hex.Decode("80000000000000000000000000000000"),
			Hex.Decode("00000000000000000000000000000080"),
            Hex.Decode("000000000000000000000000000000000000000000000000"),
			Hex.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
			Hex.Decode("80000000000000000000000000000000"),
            Hex.Decode("00000000000000000000000000000080"),
			Hex.Decode("000000000000000000000000000000000000000000000000"),
			Hex.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
            // gladman
            Hex.Decode("00000000000000000000000000000000"),
			Hex.Decode("5F060D3716B345C253F6749ABAC10917"),
			Hex.Decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
            Hex.Decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			Hex.Decode("00000000000000000000000000000000"),
			Hex.Decode("5F060D3716B345C253F6749ABAC10917"),
            Hex.Decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			Hex.Decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			Hex.Decode("00000000000000000000000000000000"),
            Hex.Decode("5F060D3716B345C253F6749ABAC10917"),
			Hex.Decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			Hex.Decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")
		};

        private static readonly byte[][] _plainText =
		{
			Hex.Decode("00000000000000000000000000000000"),
			Hex.Decode("00000000000000000000000000000000"),
			Hex.Decode("80000000000000000000000000000000"),
            Hex.Decode("80000000000000000000000000000000"),
			Hex.Decode("00000000000000000000000000000000"),
			Hex.Decode("00000000000000000000000000000000"),
            Hex.Decode("80000000000000000000000000000000"),
			Hex.Decode("80000000000000000000000000000000"),
			Hex.Decode("00000000000000000000000000000000"),
            Hex.Decode("00000000000000000000000000000000"),
			Hex.Decode("80000000000000000000000000000000"),
			Hex.Decode("80000000000000000000000000000000"),
            // gladman
            Hex.Decode("00000000000000000000000000000000"),
			Hex.Decode("355F697E8B868B65B25A04E18D782AFA"),
			Hex.Decode("F3F6752AE8D7831138F041560631B114"),
            Hex.Decode("C737317FE0846F132B23C8C2A672CE22"),
			Hex.Decode("00000000000000000000000000000000"),
			Hex.Decode("355F697E8B868B65B25A04E18D782AFA"),
            Hex.Decode("F3F6752AE8D7831138F041560631B114"),
			Hex.Decode("C737317FE0846F132B23C8C2A672CE22"),
			Hex.Decode("00000000000000000000000000000000"),
            Hex.Decode("355F697E8B868B65B25A04E18D782AFA"),
			Hex.Decode("F3F6752AE8D7831138F041560631B114"),
			Hex.Decode("C737317FE0846F132B23C8C2A672CE22")
		};

        private static readonly byte[][] _cipherText =
		{
            // fips
			Hex.Decode("0EDD33D3C621E546455BD8BA1418BEC8"),
			Hex.Decode("172AEAB3D507678ECAF455C12587ADB7"),
			Hex.Decode("6CD02513E8D4DC986B4AFE087A60BD0C"),
            Hex.Decode("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			Hex.Decode("0EDD33D3C621E546455BD8BA1418BEC8"),
			Hex.Decode("172AEAB3D507678ECAF455C12587ADB7"),
            Hex.Decode("6CD02513E8D4DC986B4AFE087A60BD0C"),
			Hex.Decode("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			Hex.Decode("0EDD33D3C621E546455BD8BA1418BEC8"),
            Hex.Decode("172AEAB3D507678ECAF455C12587ADB7"),
			Hex.Decode("6CD02513E8D4DC986B4AFE087A60BD0C"),
			Hex.Decode("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
            // gladman
            Hex.Decode("C34C052CC0DA8D73451AFE5F03BE297F"),
			Hex.Decode("ACC863637868E3E068D2FD6E3508454A"),
			Hex.Decode("77BA00ED5412DFF27C8ED91F3C376172"),
            Hex.Decode("E58B82BFBA53C0040DC610C642121168"),
			Hex.Decode("C34C052CC0DA8D73451AFE5F03BE297F"),
			Hex.Decode("ACC863637868E3E068D2FD6E3508454A"),
            Hex.Decode("77BA00ED5412DFF27C8ED91F3C376172"),
			Hex.Decode("E58B82BFBA53C0040DC610C642121168"),
			Hex.Decode("C34C052CC0DA8D73451AFE5F03BE297F"),
            Hex.Decode("ACC863637868E3E068D2FD6E3508454A"),
			Hex.Decode("77BA00ED5412DFF27C8ED91F3C376172"),
			Hex.Decode("E58B82BFBA53C0040DC610C642121168")
		};
        #endregion

        #region Public
        /// <summary>
        /// Test vectors from NIST tests in AES specification FIPS 197
        /// </summary>
        /// <returns>Success [bool]</returns>
        public bool Test()
        {
            try
            {
                for (int i = 0; i < 12; i++)
                    VectorTest(_keys[i], _plainText[i], _cipherText[i]);

                for (int i = 12; i < _plainText.Length; i++)
                    MonteCarloTest(_keys[i], _plainText[i], _cipherText[i]);

                return true;
            }
            catch(Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                return false;
            }
        }
        #endregion

        #region Private
        private void VectorTest(byte[] Key, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Input.Length];

            using (RDX engine = new RDX())
            {
                engine.Initialize(true, new KeyParams(Key));
                engine.Transform(Input, outBytes);

                if (Compare.AreEqual(outBytes, Output) == false)
                    throw new Exception("AESVector: Encrypted arrays are not equal!");

                engine.Initialize(false, new KeyParams(Key));
                engine.Transform(Output, outBytes);

                if (Compare.AreEqual(outBytes, Input) == false)
                    throw new Exception("AESVector: Decrypted arrays are not equal!");
            }
        }

        private void MonteCarloTest(byte[] Key, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Input.Length];
            Array.Copy(Input, 0, outBytes, 0, outBytes.Length);

            using (RDX engine = new RDX())
            {
                engine.Initialize(true, new KeyParams(Key));

                for (int i = 0; i != 10000; i++)
                    engine.Transform(outBytes, outBytes);
            }

            if (Compare.AreEqual(outBytes, Output) == false)
                throw new Exception("MonteCarlo: Arrays are not equal!");

            using (RDX engine = new RDX())
            {
                engine.Initialize(false, new KeyParams(Key));

                for (int i = 0; i != 10000; i++)
                    engine.Transform(outBytes, outBytes);
            }

            if (Compare.AreEqual(outBytes, Input) == false)
                throw new Exception("MonteCarlo: Arrays are not equal!");
        }
        #endregion
    }
}
