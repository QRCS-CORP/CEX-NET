using System;
using System.Security.Cryptography;
using VTDev.Projects.CEX.Helpers;
using VTDev.Projects.CEX.Crypto.Helpers;

namespace VTDev.Projects.CEX.Tests
{
    public class SHAEquality : IVectorTest
    {
        #region Enums
        public enum ShaAlg
        {
            SHA256,
            SHA512
        }
        #endregion

        #region Properties
        /// <summary>
        /// Version of SHA
        /// </summary>
        public ShaAlg Implementation { get; set; }
        #endregion

        #region Constructor
        public SHAEquality(ShaAlg Engine)
        {
            this.Implementation = Engine;
        }
        #endregion

        #region Public
        /// <summary>
        /// Run the test
        /// </summary>
        /// <returns>Success [bool]</returns>
        public bool Test()
        {
            try
            {
                // equality comparison with Bouncy Castle version
                CompareBlocks(this.Implementation);

                return true;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                Logger.LogError("SHAEquality", message, Ex);
                return false;
            }
        }
        #endregion

        #region Private
        private void CompareBlocks(ShaAlg Algorithm)
        {
            if (Algorithm == ShaAlg.SHA256)
            {
                byte[] buffer = new byte[639];
                byte[] hash1 = new byte[32];
                byte[] hash2 = new byte[32];

                using (System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                    rng.GetBytes(buffer);

                // SHA256 //
                // test digest
                using (VTDev.Projects.CEX.Crypto.Digests.SHA256Digest sha1 = new VTDev.Projects.CEX.Crypto.Digests.SHA256Digest())
                    hash1 = sha1.ComputeHash(buffer);

                using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256Managed.Create())
                    hash2 = sha.ComputeHash(buffer);

                if (!Compare.AreEqual(hash1, hash2))
                    throw new Exception("SHA512 hash is not equal!");
            }
            else
            {
                // SHA512 //
                byte[] hash1 = new byte[64];
                byte[] hash2 = new byte[64];
                byte[] buffer = new byte[377];

                using (System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                    rng.GetBytes(buffer);

                // test digest
                using (VTDev.Projects.CEX.Crypto.Digests.SHA512Digest sha2 = new VTDev.Projects.CEX.Crypto.Digests.SHA512Digest())
                    hash1 = sha2.ComputeHash(buffer);

                using (System.Security.Cryptography.SHA512 sha = System.Security.Cryptography.SHA512Managed.Create())
                    hash2 = sha.ComputeHash(buffer);

                if (!Compare.AreEqual(hash1, hash2))
                    throw new Exception("SHA256 hash is not equal!");
            }
        }
        #endregion
    }
}
