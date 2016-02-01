using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS;

namespace VTDev.Projects.CEX.Test.Tests.Asymmetric.GMSS
{
    /// <summary>
    /// Test the validity of the GMSS Encryption Key implementation
    /// </summary>
    public class GMSSKeyTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the GMSS Encryption Key implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Encryption Key tests have executed succesfully.";
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
            GMSSParameters mpar = GMSSParamSets.FromName(GMSSParamSets.GMSSParamNames.N2P10);
            GMSSKeyGenerator mkgen = new GMSSKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();

            GMSSPublicKey pub = (GMSSPublicKey)akp.PublicKey;
            byte[] enc = pub.ToBytes();
            using (GMSSPublicKey pub2 = GMSSPublicKey.From(enc))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
                if (pub.GetHashCode() != pub2.GetHashCode())
                    throw new Exception("EncryptionKey: public key hash test failed!");
            }

            OnProgress(new TestEventArgs("Passed public key serialization"));

            MemoryStream pubstr = pub.ToStream();
            using (GMSSPublicKey pub2 = GMSSPublicKey.From(pubstr))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
                if (pub.GetHashCode() != pub2.GetHashCode())
                    throw new Exception("EncryptionKey: public key hash test failed!");
            }
            pubstr.Dispose();
            OnProgress(new TestEventArgs("Passed public key stream test"));

            GMSSPrivateKey pri = (GMSSPrivateKey)akp.PrivateKey;
            enc = pri.ToBytes();
            using (GMSSPrivateKey pri2 = GMSSPrivateKey.From(enc))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
                if (pri.GetHashCode() != pri2.GetHashCode())
                    throw new Exception("EncryptionKey: private key hash test failed!");
            }
            OnProgress(new TestEventArgs("Passed private key serialization"));

            MemoryStream pristr = pri.ToStream();
            using (GMSSPrivateKey pri2 = GMSSPrivateKey.From(pristr))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
                if (pri.GetHashCode() != pri2.GetHashCode())
                    throw new Exception("EncryptionKey: private key hash test failed!");
            }
            pristr.Dispose();
            OnProgress(new TestEventArgs("Passed private key stream test"));

            pri.Dispose();
            pub.Dispose();
        }
        #endregion
    }
}
