#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.GeneratorTest
{
    /// <summary>
    /// RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF) 
    /// http://tools.ietf.org/html/rfc5869
    /// </summary>
    public class HkdfTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "HKDF RFC 5869 SHA-2 test vectors.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All HKDF tests have executed succesfully.";
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
            HexConverter.Decode("000102030405060708090a0b0c"),
            HexConverter.Decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
        };
        private static readonly byte[][] _ikm = 
        {
            HexConverter.Decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            HexConverter.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
            HexConverter.Decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        };
        private static readonly byte[][] _info = 
        {
            HexConverter.Decode("f0f1f2f3f4f5f6f7f8f9"),
            HexConverter.Decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            null
        };
        private static readonly byte[][] _output = 
        {
            HexConverter.Decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
            HexConverter.Decode("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
            HexConverter.Decode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
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
        /// Full set of SHA-2 test vectors from RFC 5869.
        /// Tests HMAC interface, SHA-2 256, combined SHA-2/HMAC implementation, and HKDF.
        /// </summary>
        /// 
        /// <returns>Status</returns>
        public string Test()
        {
            try
            {
                HKDFTest(42, _salt[0], _ikm[0], _info[0], _output[0]);
                HKDFTest(82, _salt[1], _ikm[1], _info[1], _output[1]);
                HKDFTest(42, new byte[0], _ikm[2], null, _output[2]);
                OnProgress(new TestEventArgs("Passed HKDF vector tests.."));

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
        private void HKDFTest(int Size, byte[] Salt, byte[] Key, byte[] Info, byte[] Output)
        {
            byte[] outBytes = new byte[Size];

            using (HKDF gen = new HKDF(new SHA256()))
            {
                gen.Initialize(Salt, Key, Info);
                gen.Generate(outBytes, 0, Size);
            }

            if (Compare.AreEqual(outBytes, Output) == false)
                throw new Exception("HKDF: Values are not equal! Expected: " + HexConverter.ToString(Output) + " Received: " + HexConverter.ToString(outBytes));

            using (HKDF gen = new HKDF(new SHA256HMAC()))
            {
                gen.Initialize(Salt, Key, Info);
                gen.Generate(outBytes, 0, Size);
            }

            if (Compare.AreEqual(outBytes, Output) == false)
                throw new Exception("HKDF: Values are not equal! Expected: " + HexConverter.ToString(Output) + " Received: " + HexConverter.ToString(outBytes));
        }
        #endregion
    }
}
