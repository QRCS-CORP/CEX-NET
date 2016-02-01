#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Projects.CEX.Test.Tests;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.AsymmetricTest.NTRU.Encrypt
{
    /// <summary>
    /// Test the validity of the EncryptionKey implementation
    /// </summary>
    public class NtruKeyTest : ITest
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
                Encode();
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
        private void Encode()
        {
            foreach (NTRUParameters param in new NTRUParameters[] 
            { 
                (NTRUParameters)NTRUParamSets.APR2011743.DeepCopy(), 
                (NTRUParameters)NTRUParamSets.APR2011743FAST.DeepCopy(), 
                (NTRUParameters)NTRUParamSets.EES1499EP1.DeepCopy()})
                    Encode(param);
        }

        private void Encode(NTRUParameters param)
        {
            NTRUKeyGenerator ntru = new NTRUKeyGenerator(param);
            NTRUKeyPair kp = (NTRUKeyPair)ntru.GenerateKeyPair();
            byte[] priv = ((NTRUPrivateKey)kp.PrivateKey).ToBytes();
            byte[] pub = ((NTRUPublicKey)kp.PublicKey).ToBytes();
            NTRUKeyPair kp2 = new NTRUKeyPair(new NTRUPublicKey(pub), new NTRUPrivateKey(priv));

            if (!Evaluate.Equals(kp.PublicKey, kp2.PublicKey))
                throw new Exception("EncryptionKey: public key comparison test failed!");
            if (kp.PublicKey.GetHashCode() != kp2.PublicKey.GetHashCode())
                throw new Exception("EncryptionKey: public key hash test failed!");
            if (!Evaluate.Equals(kp.PrivateKey, kp2.PrivateKey))
                throw new Exception("EncryptionKey: private key comparison test failed!");
            if (kp.PrivateKey.GetHashCode() != kp2.PrivateKey.GetHashCode())
                throw new Exception("EncryptionKey: private key hash test failed!");

            MemoryStream bos1 = new MemoryStream();
            MemoryStream bos2 = new MemoryStream();
            ((NTRUPrivateKey)kp.PrivateKey).WriteTo(bos1);
            ((NTRUPublicKey)kp.PublicKey).WriteTo(bos2);
            MemoryStream bis1 = new MemoryStream(bos1.ToArray());
            MemoryStream bis2 = new MemoryStream(bos2.ToArray());
            NTRUKeyPair kp3 = new NTRUKeyPair(new NTRUPublicKey(bis2), new NTRUPrivateKey(bis1));
            if (!Evaluate.Equals(kp.PublicKey, kp3.PublicKey))
                throw new Exception("EncryptionKey: public key comparison test failed!");
            if (kp.PublicKey.GetHashCode() != kp3.PublicKey.GetHashCode())
                throw new Exception("EncryptionKey: public key hash test failed!");
            if (!Evaluate.Equals(kp.PrivateKey, kp3.PrivateKey))
                throw new Exception("EncryptionKey: private key comparison test failed!");
            if (kp.PrivateKey.GetHashCode() != kp3.PrivateKey.GetHashCode())
                throw new Exception("EncryptionKey: private key hash test failed!");
        }
        #endregion
    }
}