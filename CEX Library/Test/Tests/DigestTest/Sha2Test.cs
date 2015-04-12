#region Directives
using System;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.DigestTest
{
    /// <summary>
    /// NIST SHA-2 KAT vectors:
    /// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
    /// </summary>
    public class Sha2Test : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Tests SHA-2 256/512 with NIST KAT vectors.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All SHA-2 tests have executed succesfully.";
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
        private static readonly byte[,][] _expected =
		{
            {
			    HexConverter.Decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
			    HexConverter.Decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                HexConverter.Decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
			    HexConverter.Decode("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
            },
            {
			    HexConverter.Decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
			    HexConverter.Decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
                HexConverter.Decode("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"),
			    HexConverter.Decode("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
            }
		};

        private string[] _input =
		{
			"abc",
			"",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
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
        /// Tests SHA-2 256/512 with NIST provided KAT vectors.
        /// Throws on all failures.
        /// </summary>
        /// 
        /// <returns>Success [bool]</returns>
        public string Test()
        {
            try
            {
                DigestTest(new SHA256());
                OnProgress(new TestEventArgs("Passed SHA-2 256 bit digest vector tests.."));
                DigestTest(new SHA512());
                OnProgress(new TestEventArgs("Passed SHA-2 512 bit digest vector tests.."));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Tests
        private void DigestTest(IDigest Digest)
        {
            byte[] hash = new byte[Digest.DigestSize];
            int index = hash.Length == 64 ? 1 : 0;

            for (int i = 0; i < _input.Length; i++)
            {
                if (_input[i].Length != 0)
                {
                    byte[] data = Encoding.ASCII.GetBytes(_input[i]);
                    Digest.BlockUpdate(data, 0, data.Length);
                }

                Digest.DoFinal(hash, 0);

                if (Compare.AreEqual(_expected[index, i], hash) == false)
                    throw new Exception("SHA2Vector: Expected hash is not equal! Expected: " + HexConverter.ToString(_expected[index, i]) + " Received: " + HexConverter.ToString(hash));
            }
        }
        #endregion
    }
}
