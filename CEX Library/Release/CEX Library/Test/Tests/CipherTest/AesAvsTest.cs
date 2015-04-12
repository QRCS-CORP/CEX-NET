#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// NIST Advanced Encryption Standard Algorithm Validation Suite (AESAVS)
    /// AESAVS certification vectors: http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf
    /// </summary>
    public class AesAvsTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "NIST Advanced Encryption Standard Algorithm Validation Suite (AESAVS) tests.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! AESAVS tests have executed succesfully.";
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
        /// The full range of ascending Key and Plaintext Vector KATs, 960 tests total. 
        /// Throws on all failures.
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            byte[] plainText = Hex.Decode("00000000000000000000000000000000");
            byte[] key;
            byte[] cipherText;

            try
            {
                string data = VTDev.Projects.CEX.Test.Properties.Resources.keyvect128;
                        
                for (int i = 0, j = 32; i < data.Length; i += 64, j += 64)
                {
                    key = Hex.Decode(data.Substring(i, 32));
                    cipherText = Hex.Decode(data.Substring(j, 32));

                    VectorTest(key, plainText, cipherText);
                }
                OnProgress(new TestEventArgs("Passed 128 bit key vectors test.."));

                data = VTDev.Projects.CEX.Test.Properties.Resources.keyvect192;

                for (int i = 0, j = 48; i < data.Length; i += 80, j += 80)
                {
                    key = Hex.Decode(data.Substring(i, 48));
                    cipherText = Hex.Decode(data.Substring(j, 32));

                    VectorTest(key, plainText, cipherText);
                }
                OnProgress(new TestEventArgs("Passed 192 bit key vectors test.."));

                data = VTDev.Projects.CEX.Test.Properties.Resources.keyvect256;

                for (int i = 0, j = 64; i < data.Length; i += 96, j += 96)
                {
                    key = Hex.Decode(data.Substring(i, 64));
                    cipherText = Hex.Decode(data.Substring(j, 32));

                    VectorTest(key, plainText, cipherText);
                }
                OnProgress(new TestEventArgs("Passed 256 bit key vectors test.."));

                key = Hex.Decode("00000000000000000000000000000000");
                data = VTDev.Projects.CEX.Test.Properties.Resources.plainvect128;

                for (int i = 0, j = 32; i < data.Length; i += 64, j += 64)
                {
                    plainText = Hex.Decode(data.Substring(i, 32));
                    cipherText = Hex.Decode(data.Substring(j, 32));

                    VectorTest(key, plainText, cipherText);
                }
                OnProgress(new TestEventArgs("Passed 128 bit plain-text vectors test.."));

                key = Hex.Decode("000000000000000000000000000000000000000000000000");
                data = VTDev.Projects.CEX.Test.Properties.Resources.plainvect192;

                for (int i = 0, j = 32; i < data.Length; i += 64, j += 64)
                {
                    plainText = Hex.Decode(data.Substring(i, 32));
                    cipherText = Hex.Decode(data.Substring(j, 32));

                    VectorTest(key, plainText, cipherText);
                }
                OnProgress(new TestEventArgs("Passed 192 bit plain-text vectors test.."));

                key = Hex.Decode("0000000000000000000000000000000000000000000000000000000000000000");
                data = VTDev.Projects.CEX.Test.Properties.Resources.plainvect256;

                for (int i = 0, j = 32; i < data.Length; i += 64, j += 64)
                {
                    plainText = Hex.Decode(data.Substring(i, 32));
                    cipherText = Hex.Decode(data.Substring(j, 32));

                    VectorTest(key, plainText, cipherText);
                }
                OnProgress(new TestEventArgs("Passed 256 bit plain-text vectors test.. 960/960 vectors passed"));

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
            using (RDX engine = new RDX())
            {
                byte[] outBytes = new byte[Input.Length];

                engine.Initialize(true, new KeyParams(Key));
                engine.Transform(Input, outBytes);

                if (Compare.AreEqual(outBytes, Output) == false)
                    throw new Exception("AESAVS: Encrypted arrays are not equal! Expected: " + Hex.ToString(Output) + " Received: " + Hex.ToString(outBytes));
            }
        }
        #endregion
    }
}
