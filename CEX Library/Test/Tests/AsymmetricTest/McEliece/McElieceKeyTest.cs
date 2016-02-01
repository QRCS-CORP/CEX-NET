using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Projects.CEX.Test.Tests;

namespace VTDev.Projects.CEX.Test.Tests.Asymmetric.McEliece
{
    /// <summary>
    /// Test the validity of the EncryptionKey implementation
    /// </summary>
    public class McElieceKeyTest : ITest
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
        public string Run()
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
            MPKCParameters mpar = (MPKCParameters)MPKCParamSets.MPKCFM11T40S256.DeepCopy();
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();

            MPKCPublicKey pub = (MPKCPublicKey)akp.PublicKey;
            byte[] enc = pub.ToBytes();
            using (MPKCPublicKey pub2 = MPKCPublicKey.From(enc))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
                if (pub.GetHashCode() != pub2.GetHashCode())
                    throw new Exception("EncryptionKey: public key hash test failed!");
            }
            OnProgress(new TestEventArgs("Passed public key serialization"));

            MemoryStream pubstr = pub.ToStream();
            using (MPKCPublicKey pub2 = MPKCPublicKey.From(pubstr))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
                if (pub.GetHashCode() != pub2.GetHashCode())
                    throw new Exception("EncryptionKey: public key hash test failed!");
            }
            pubstr.Dispose();
            OnProgress(new TestEventArgs("Passed public key stream test"));

            MPKCPrivateKey pri = (MPKCPrivateKey)akp.PrivateKey;
            enc = pri.ToBytes();
            using (MPKCPrivateKey pri2 = new MPKCPrivateKey(enc))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
                if (pri.GetHashCode() != pri2.GetHashCode())
                    throw new Exception("EncryptionKey: private key hash test failed!");
            }
            OnProgress(new TestEventArgs("Passed private key serialization"));

            MemoryStream pristr = pri.ToStream();
            using (MPKCPrivateKey pri2 = MPKCPrivateKey.From(pristr))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
                if (pri.GetHashCode() != pri2.GetHashCode())
                    throw new Exception("EncryptionKey: private key hash test failed!");
            }
            pristr.Dispose();
            OnProgress(new TestEventArgs("Passed private key stream test"));

            using (MPKCEncrypt mpe = new MPKCEncrypt(mpar))
            {
                mpe.Initialize(akp.PublicKey);

                int sz = mpe.MaxPlainText - 1;
                byte[] data = new byte[sz];
                new VTDev.Libraries.CEXEngine.Crypto.Prng.CSPPrng().GetBytes(data);

                enc = mpe.Encrypt(data);

                mpe.Initialize(akp.PrivateKey);
                byte[] dec = mpe.Decrypt(enc);

                if (!Evaluate.AreEqual(dec, data))
                    throw new Exception("EncryptionKey: decryption failure!");
                OnProgress(new TestEventArgs("Passed encryption test"));
            }

            pri.Dispose();
            pub.Dispose();
        }
        #endregion
    }
}
