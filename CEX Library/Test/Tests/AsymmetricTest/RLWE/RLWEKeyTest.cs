using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Projects.CEX.Test.Tests;

namespace Test.Tests
{
    /// <summary>
    /// Test the validity of the EncryptionKey implementation
    /// </summary>
    public class RLWEKeyTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the EncryptionKey implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! EncryptionKey tests have executed succesfully.";
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
        /// Tests the validity of the EncryptionKey implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                TestEncode();
                OnProgress(new TestEventArgs("Passed encryption key comparison tests"));

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
        private void TestEncode()
        {
            RLWEParameters mpar = (RLWEParameters)RLWEParamSets.RLWEN256Q7681.DeepCopy();
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();

            RLWEPublicKey pub = (RLWEPublicKey)akp.PublicKey;
            byte[] enc = pub.ToBytes();
            using (RLWEPublicKey pub2 = RLWEPublicKey.From(enc))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
            }
            OnProgress(new TestEventArgs("Passed public key serialization"));

            MemoryStream pubstr = pub.ToStream();
            using (RLWEPublicKey pub2 = RLWEPublicKey.From(pubstr))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
            }
            pubstr.Dispose();
            OnProgress(new TestEventArgs("Passed public key stream test"));

            RLWEPrivateKey pri = (RLWEPrivateKey)akp.PrivateKey;
            enc = pri.ToBytes();
            using (RLWEPrivateKey pri2 = RLWEPrivateKey.From(enc))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
            }
            OnProgress(new TestEventArgs("Passed private key serialization"));

            MemoryStream pristr = pri.ToStream();
            using (RLWEPrivateKey pri2 = RLWEPrivateKey.From(pristr))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
            }
            pristr.Dispose();
            OnProgress(new TestEventArgs("Passed private key stream test"));

            using (RLWEEncrypt mpe = new RLWEEncrypt(mpar))
            {
                mpe.Initialize(akp.PublicKey);

                int sz = mpe.MaxPlainText;
                byte[] data = new byte[sz];
                new VTDev.Libraries.CEXEngine.Crypto.Prng.CSPRng().GetBytes(data);

                enc = mpe.Encrypt(data);

                mpe.Initialize(akp.PrivateKey);
                byte[] dec = mpe.Decrypt(enc);

                if (!Compare.AreEqual(dec, data))
                    throw new Exception("EncryptionKey: decryption failure!");
                OnProgress(new TestEventArgs("Passed encryption test"));
            }

            pri.Dispose();
            pub.Dispose();
        }
        #endregion
    }
}
