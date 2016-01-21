using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW;

namespace VTDev.Projects.CEX.Test.Tests.Asymmetric.RNBW
{
    /// <summary>
    /// Test the validity of the Rainbow Encryption Key implementation
    /// </summary>
    public class RNBWKeyTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the Rainbow Encryption Key implementation";
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
            RNBWParameters mpar = RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N33L5);
            RNBWKeyGenerator mkgen = new RNBWKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();

            RNBWPublicKey pub = (RNBWPublicKey)akp.PublicKey;
            byte[] enc = pub.ToBytes();
            using (RNBWPublicKey pub2 = RNBWPublicKey.From(enc))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
            }
            OnProgress(new TestEventArgs("Passed public key serialization"));

            MemoryStream pubstr = pub.ToStream();
            using (RNBWPublicKey pub2 = RNBWPublicKey.From(pubstr))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
            }
            pubstr.Dispose();
            OnProgress(new TestEventArgs("Passed public key stream test"));

            RNBWPrivateKey pri = (RNBWPrivateKey)akp.PrivateKey;
            enc = pri.ToBytes();
            using (RNBWPrivateKey pri2 = RNBWPrivateKey.From(enc))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
            }
            OnProgress(new TestEventArgs("Passed private key serialization"));

            MemoryStream pristr = pri.ToStream();
            using (RNBWPrivateKey pri2 = RNBWPrivateKey.From(pristr))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
            }
            pristr.Dispose();
            OnProgress(new TestEventArgs("Passed private key stream test"));


            pri.Dispose();
            pub.Dispose();
        }
        #endregion
    }
}
