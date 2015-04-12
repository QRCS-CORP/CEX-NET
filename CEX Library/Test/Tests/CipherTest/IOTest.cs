#region Directives
using System;
using System.IO;
using System.Security.Cryptography;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// Tests I/O and vector values
    /// </summary>
    public class IOTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "IO Tests initialization and data access methods.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! IO tests have executed succesfully.";
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
        internal static readonly string[] _cipherTests =
		{
			"000102030405060708090a0b0c0d0e0f",
			"00112233445566778899aabbccddeeff",
			"69c4e0d86a7b0430d8cdb78070b4c55a",
			"000102030405060708090a0b0c0d0e0f1011121314151617",
			"00112233445566778899aabbccddeeff",
			"dda97ca4864cdfe06eaf70a0ec0d7191",
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"00112233445566778899aabbccddeeff",
			"8ea2b7ca516745bfeafc49904b496089",
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
        /// I/O and KAT tests run on the base engine accessors
        /// </summary>
        /// <returns>State</returns>
        public string Test()
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            byte[] data = new byte[2048];
            IBlockCipher inCipher;
            IBlockCipher outCipher;

            try
            {
                inCipher = new RDX();
                outCipher = new RDX();
                // run the AES I/O test vectors
                for (int i = 0; i != _cipherTests.Length; i += 3)
                    TestIO(inCipher, outCipher, HexConverter.Decode(_cipherTests[i]), HexConverter.Decode(_cipherTests[i + 1]), HexConverter.Decode(_cipherTests[i + 2]));

                for (int i = 0; i != _cipherTests.Length; i += 3)
                    TestIO(inCipher, outCipher, HexConverter.Decode(_cipherTests[i]), HexConverter.Decode(_cipherTests[i + 1]), HexConverter.Decode(_cipherTests[i + 2]));

                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(key);
                    rng.GetBytes(data);
                }

                OnProgress(new TestEventArgs("Passed AES known vector method tests.."));

                // test transforms
                TestIO2(new RDX(), key, data);
                TestIO2(new SPX(), key, data);
                TestIO2(new TFX(), key, data);

                OnProgress(new TestEventArgs("Passed I/O initialization and access tests.."));

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
        private void TestIO(IBlockCipher InCipher, IBlockCipher OutCipher, byte[] Key, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Output.Length];
            byte[] inBytes = new byte[Input.Length];

            // 1: test initialization
            try
            {
                OutCipher.Initialize(true, new KeyParams(Key));
            }
            catch
            {
                throw new Exception(OutCipher.Name + ": IO-1E: Initialization Failure");
            }

            try
            {
                InCipher.Initialize(false, new KeyParams(Key));
            }
            catch
            {
                throw new Exception(InCipher.Name + ": IO-1D: Initialization Failure");
            }

            // 2: EncryptBlock
            try
            {
                OutCipher.EncryptBlock(Input, outBytes);
            }
            catch (IOException Ex)
            {
                throw new Exception(OutCipher.Name + ": IO-4: Processing Failure " + Ex.Message);
            }

            // not equal
            if (Compare.AreEqual(Output, outBytes) == false)
                throw new Exception(OutCipher.Name + ": IO-4: EncryptArray: Arrays are not equal!");

            // 3: DecryptBlock
            try
            {
                InCipher.DecryptBlock(outBytes, inBytes);
            }
            catch (Exception Ex)
            {
                throw new Exception(InCipher.Name + ": IO-D5: DecryptArray Failure " + Ex.Message);
            }

            if (Compare.AreEqual(Input, inBytes) == false)
                throw new Exception(InCipher.Name + ": IO-D5: Arrays are not equal!");

            // 4: EncryptBlock
            try
            {
                OutCipher.EncryptBlock(Input, 0, outBytes, 0);
            }
            catch (IOException Ex)
            {
                throw new Exception(OutCipher.Name + ": IO-6: Processing Failure " + Ex.Message);
            }

            // not equal
            if (Compare.AreEqual(Output, outBytes) == false)
                throw new Exception(OutCipher.Name + ": IO-6: EncryptArray: Arrays are not equal!");

            // 5: DecryptBlock
            try
            {
                InCipher.DecryptBlock(outBytes, 0, inBytes, 0);
            }
            catch (Exception Ex)
            {
                throw new Exception(InCipher.Name + ": IO-D7: DecryptArray Failure " + Ex.Message);
            }

            if (Compare.AreEqual(Input, inBytes) == false)
                throw new Exception(InCipher.Name + ": IO-D7: Arrays are not equal!");

        }

        private void TestIO2(IBlockCipher Cipher, byte[] Key, byte[] Input)
        {
            byte[] outBytes = new byte[Input.Length];
            byte[] inBytes = new byte[Input.Length];
            int blocks = Input.Length / 16;

            try
            {
                Cipher.Initialize(true, new KeyParams(Key));

                for (int i = 0; i < blocks; i++)
                    Cipher.Transform(Input, i * 16, outBytes, i * 16);

                Cipher.Initialize(false, new KeyParams(Key));

                for (int i = 0; i < blocks; i++)
                    Cipher.Transform(outBytes, i * 16, inBytes, i * 16);

                // equal
                if (Compare.AreEqual(Input, inBytes) == false)
                    throw new Exception(Cipher.Name + ": IO-2: Arrays are not equal!");
            }
            catch (Exception Ex)
            {
                throw Ex;
            }
        }
        #endregion

        #region RDX
        private byte[] DecryptRDX(byte[] Key, byte[] Data)
        {
            int blocks = Data.Length / 16;
            byte[] outputData = new byte[Data.Length];

            using (RDX transform = new RDX())
            {
                transform.Initialize(false, new KeyParams(Key));

                for (int i = 0; i < blocks; i++)
                    transform.Transform(Data, i * 16, outputData, i * 16);
            }

            return outputData;
        }

        private byte[] EncryptRDX(byte[] Key, byte[] Data)
        {
            int blocks = Data.Length / 16;
            byte[] outputData = new byte[Data.Length];

            using (RDX transform = new RDX())
            {
                transform.Initialize(true, new KeyParams(Key));

                for (int i = 0; i < blocks; i++)
                    transform.Transform(Data, i * 16, outputData, i * 16);
            }

            return outputData;
        }
        #endregion
    }
}
