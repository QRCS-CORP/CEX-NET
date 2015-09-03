using System;
using System.Security.Cryptography;
using VTDev.Projects.CEX.Crypto.Ciphers;
using VTDev.Projects.CEX.Crypto.Helpers;
using VTDev.Projects.CEX.Crypto.Tests.Ciphers;
using VTDev.Projects.CEX.Helpers;

namespace VTDev.Projects.CEX.Tests
{
    public class SalsaEquality : IVectorTest
    {
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
                CompareBlocks();

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
        private void CompareBlocks()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[32];
                byte[] iv = new byte[8];
                byte[] data = new byte[640];

                rng.GetBytes(key);
                rng.GetBytes(iv);
                rng.GetBytes(data);

                byte[] enc1 = SalsaA(key, iv, data);
                byte[] enc2 = SalsaB(key, iv, data);

                if (Compare.AreEqual(enc1, enc2) == false)
                    throw new Exception("Encrypted output is not equal!");

                byte[] dec1 = SalsaA(key, iv, enc1);

                if (Compare.AreEqual(data, dec1) == false)
                    throw new Exception("Decrypted output is not equal to input data!");
            }
        }

        private byte[] SalsaA(byte[] Key, byte[] Vector, byte[] Data)
        {
            int len = Data.Length;
            int ct = 0;
            byte[] output = new byte[len];

            using (Salsa20 salsa = new Salsa20())
            {
                salsa.Init(Key, Vector);

                while (ct < len)
                {
                    salsa.Transform(Data, ct, 64, output, ct);
                    ct += 64;
                }
            }

            return output;
        }

        private byte[] SalsaB(byte[] Key, byte[] Vector, byte[] Data)
        {
            int len = Data.Length;
            int ct = 0;
            byte[] output = new byte[len];
            Salsa20Engine salsa = new Salsa20Engine();

            salsa.Init(true, Key, Vector);

            while (ct < len)
            {
                salsa.ProcessBytes(Data, ct, 64, output, ct);
                ct += 64;
            }

            return output;
        }
        #endregion
    }
}
