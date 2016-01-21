using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Projects.CEX.Test.Tests;

namespace Test.Tests
{
    /// <summary>
    /// Test the validity of the CCA2 Encryption implementation
    /// </summary>
    public class RLWEEncryptionTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the Ring-LWE implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Encryption tests have executed succesfully.";
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
        /// Tests the validity of the Ring-LWE implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                TestKey();
                TestEncrypt((RLWEParameters)RLWEParamSets.RLWEN256Q7681.DeepCopy());
                TestEncrypt((RLWEParameters)RLWEParamSets.RLWEN512Q12289.DeepCopy());

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
        private void TestKey()
        {
            RLWEParameters encParams = (RLWEParameters)RLWEParamSets.RLWEN256Q7681.DeepCopy();
            RLWEKeyGenerator keyGen = new RLWEKeyGenerator(encParams);
            IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
            byte[] enc, dec, data;

            // encrypt an array
            using (RLWEEncrypt cipher = new RLWEEncrypt(encParams))
            {
                cipher.Initialize(keyPair.PublicKey);
                data = new byte[cipher.MaxPlainText];
                new CSPPrng().GetBytes(data);
                enc = cipher.Encrypt(data);
            }
            
            // decrypt the cipher text
            using (RLWEEncrypt cipher = new RLWEEncrypt(encParams))
            {
                cipher.Initialize(keyPair.PrivateKey);
                dec = cipher.Decrypt(enc);
            }

            if (!Evaluate.AreEqual(dec, data))
                throw new Exception("TestKey test: decryption failure!");
            OnProgress(new TestEventArgs("Passed sub-key test"));
        }

        private void TestEncrypt(RLWEParameters Param)
        {
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(Param);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] enc;

            using (RLWEEncrypt mpe = new RLWEEncrypt(Param))
            {
                mpe.Initialize(akp.PublicKey);

                int sz = mpe.MaxPlainText;
                byte[] data = new byte[sz];
                new CSPPrng().GetBytes(data);

                enc = mpe.Encrypt(data);

                mpe.Initialize(akp.PrivateKey);
                byte[] dec = mpe.Decrypt(enc);

                if (!Evaluate.AreEqual(dec, data))
                    throw new Exception("Encryption test: decryption failure!");
                OnProgress(new TestEventArgs(string.Format("Passed N:{0} Q:{1} encryption test", Param.N, Param.Q)));
            }
        }
        #endregion
    }
}
