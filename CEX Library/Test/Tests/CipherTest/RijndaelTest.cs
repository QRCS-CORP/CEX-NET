#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// Test vectors derived from Bouncy Castle RijndaelTest.cs and the Nessie unverified vectors:
    /// <a href="https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-256-256.unverified.test-vectors"></a>
    /// Tests support block sizes of 16 and 32 bytes.
    /// </summary>
    public class RijndaelTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Rijndael Known Answer Tests.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Rijndael tests have executed succesfully.";
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
			HexConverter.Decode("80000000000000000000000000000000"),
			HexConverter.Decode("00000000000000000000000000000080"),
			HexConverter.Decode("000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
			HexConverter.Decode("2b7e151628aed2a6abf7158809cf4f3c"),
            HexConverter.Decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5"),
			HexConverter.Decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe"),
            HexConverter.Decode("8000000000000000000000000000000000000000000000000000000000000000"),
			HexConverter.Decode("4000000000000000000000000000000000000000000000000000000000000000"),
			HexConverter.Decode("2000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("1000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000")
		};

        private static readonly byte[][] _plainText =
		{
			HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("00000000000000000000000000000000"),
			HexConverter.Decode("80000000000000000000000000000000"),
            HexConverter.Decode("80000000000000000000000000000000"),
			HexConverter.Decode("3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8"),
            HexConverter.Decode("3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8"),
			HexConverter.Decode("3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8"),
            HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
			HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
			HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("0000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("8000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("4000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("2000000000000000000000000000000000000000000000000000000000000000"),
            HexConverter.Decode("1000000000000000000000000000000000000000000000000000000000000000")
		};

        private static readonly byte[][] _cipherText =
		{
			HexConverter.Decode("0EDD33D3C621E546455BD8BA1418BEC8"),
			HexConverter.Decode("172AEAB3D507678ECAF455C12587ADB7"),
			HexConverter.Decode("6CD02513E8D4DC986B4AFE087A60BD0C"),
            HexConverter.Decode("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			HexConverter.Decode("7d15479076b69a46ffb3b3beae97ad8313f622f67fedb487de9f06b9ed9c8f19"),
            HexConverter.Decode("5d7101727bb25781bf6715b0e6955282b9610e23a43c2eb062699f0ebf5887b2"),
			HexConverter.Decode("a49406115dfb30a40418aafa4869b7c6a886ff31602a7dd19c889dc64f7e4e7a"),
            HexConverter.Decode("E62ABCE069837B65309BE4EDA2C0E149FE56C07B7082D3287F592C4A4927A277"),
			HexConverter.Decode("1F00B4DD622C0B2951F25970B0ED47A65F513112DACA242B5292CA314917BF94"),
			HexConverter.Decode("2AA9F4BE159F9F8777561281C1CC4FCD7435E6E855E222426C309838ABD5FFEE"),
            HexConverter.Decode("B4ADF28C3A85C337AA3150E3032B941AA49F12F911221DD91A62919CAD447CFB"),
            HexConverter.Decode("159A08E46E616E6E9978502010DAFF922EB362E77DCAAF02EAEB7354EB8B8DBA"),
            HexConverter.Decode("2756DDECD7558B198962F092D7BA3EEF45D9E287380AAB8E852658092AA9DFA1"),
            HexConverter.Decode("87B829FB7B0C16C408151D323FCB8B56EBC0573747D46C2B47BFD533ED3273C9"),
            HexConverter.Decode("DB462EEC713D4CC89607DCA35C4FE6E8D618C8BDACD3DD1C0A1B14E6CA8C23C6")
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
        /// Rijndael know answer Vector tests
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                for (int i = 0; i < _plainText.Length; i++)
                    VectorTest(_keys[i], _plainText[i], _cipherText[i]);
                OnProgress(new TestEventArgs("Passed 128 and 256 bit key tests.."));

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
        private void VectorTest(byte[] Key, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Input.Length];
            byte[] outBytes2 = new byte[Input.Length];

            using (RDX engine = new RDX(Input.Length))
            {
                engine.Initialize(true, new KeyParams(Key));
                engine.Transform(Input, outBytes);

                if (Evaluate.AreEqual(outBytes, Output) == false)
                    throw new Exception("Rijndael: Encrypted arrays are not equal! Expected: " + HexConverter.ToString(Output) + " Received: " + HexConverter.ToString(outBytes));

                engine.Initialize(false, new KeyParams(Key));
                engine.Transform(Output, outBytes);

                if (Evaluate.AreEqual(outBytes, Input) == false)
                    throw new Exception("Rijndael: Decrypted arrays are not equal! Expected: " + HexConverter.ToString(Input) + " Received: " + HexConverter.ToString(outBytes));
            }
        }
        #endregion
    }
}
