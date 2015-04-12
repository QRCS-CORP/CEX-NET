using System;
using VTDev.Projects.CEX.Helpers;
using VTDev.Projects.CEX.Crypto.Macs;
using VTDev.Projects.CEX.Crypto.Digests;
using VTDev.Projects.CEX.Crypto.Helpers;

namespace VTDev.Projects.CEX.Tests
{
    public class HMACEquality : IVectorTest
    {
        #region Enums
        public enum HmacAlg
        {
            Sha256Hmac,
            Sha512Hmac
        }
        #endregion

        #region Properties
        public HmacAlg Algorithm { get; set; }
        #endregion

        #region Constructor
        public HMACEquality(HmacAlg Engine)
        {
            this.Algorithm = Engine;
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
                CompareBlocks(this.Algorithm);

                return true;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                Logger.LogError("SalsaEquality", message, Ex);
                return false;
            }
        }
        #endregion

        #region Private
        private void CompareBlocks(HmacAlg Algorithm)
        {
            if (Algorithm == HmacAlg.Sha256Hmac)
            {
                byte[] hashKey = new byte[32];
                byte[] buffer = new byte[640];
                byte[] hash1 = new byte[32];
                byte[] hash2 = new byte[32];

                using (System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                {
                    rng.GetBytes(hashKey);
                    rng.GetBytes(buffer);
                }

                using (System.Security.Cryptography.HMACSHA256 hmac = new System.Security.Cryptography.HMACSHA256(hashKey))
                    hash1 = hmac.ComputeHash(buffer);


                // test 1: HMAC interface
                HMAC hmac1 = new HMAC(new SHA256Digest());
                hmac1.Init(hashKey);
                hmac1.BlockUpdate(buffer, 0, buffer.Length);
                hmac1.DoFinal(hash2, 0);

                if (!Compare.AreEqual(hash2, hash1))
                    throw new Exception("hmac is not equal!");


                // test 2: class with dofinal
                using (SHA256HMAC hmac = new SHA256HMAC())
                {
                    hmac.Init(hashKey);
                    hmac.BlockUpdate(buffer, 0, buffer.Length);
                    hmac.DoFinal(hash2, 0);
                }

                if (!Compare.AreEqual(hash2, hash1))
                    throw new Exception("hmac1 is not equal!");


                // test 3: class with computemac
                using (SHA256HMAC hmac = new SHA256HMAC(hashKey))
                    hash2 = hmac.ComputeMac(buffer);

                if (!Compare.AreEqual(hash2, hash1))
                    throw new Exception("hmac2 is not equal!");
            }
            else
            {
                // SHA512 //
                byte[] hash1 = new byte[64];
                byte[] hash2 = new byte[64];
                byte[] hashKey = new byte[64];
                byte[] buffer = new byte[128];

                using (System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                {
                    rng.GetBytes(hashKey);
                    rng.GetBytes(buffer);
                }

                using (System.Security.Cryptography.HMACSHA512 hmac = new System.Security.Cryptography.HMACSHA512(hashKey))
                    hash1 = hmac.ComputeHash(buffer);


                // test 1: HMAC interface
                HMAC hmac1 = new HMAC(new SHA512Digest());
                hmac1.Init(hashKey);
                hmac1.BlockUpdate(buffer, 0, buffer.Length);
                hmac1.DoFinal(hash2, 0);

                if (!Compare.AreEqual(hash2, hash1))
                    throw new Exception("hmac1 is not equal!");


                // test 2: class with dofinal
                using (SHA512HMAC hmac = new SHA512HMAC())
                {
                    hmac.Init(hashKey);
                    hmac.BlockUpdate(buffer, 0, buffer.Length);
                    hmac.DoFinal(hash2, 0);
                }

                if (!Compare.AreEqual(hash2, hash1))
                    throw new Exception("hmac1 is not equal!");


                // test 3: class with computemac
                using (SHA512HMAC hmac = new SHA512HMAC(hashKey))
                    hash2 = hmac.ComputeMac(buffer);

                if (!Compare.AreEqual(hash2, hash1))
                    throw new Exception("hmac2 is not equal!");
            }
        }
        #endregion
    }
}
