using System;
using System.Security.Cryptography;
using VTDev.Projects.CEX.Crypto.Ciphers;
using VTDev.Projects.CEX.Crypto.Helpers;
using VTDev.Projects.CEX.Crypto.Tests.Ciphers;
using VTDev.Projects.CEX.Helpers;
using System.Text;
using VTDev.Projects.CEX.Tests.Ciphers;

namespace VTDev.Projects.CEX.Tests
{
    public class SerpentEquality : IVectorTest
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
                Logger.LogError("SerpentEquality", message, Ex);
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
                byte[] data = new byte[1600]; // 100 blocks

                rng.GetBytes(key);
                rng.GetBytes(data);

                byte[] enc1 = SerpentA(true, key, data);
                byte[] enc2 = SerpentB(key, data);

                if (Compare.AreEqual(enc1, enc2) == false)
                    throw new Exception("Encrypted output is not equal!");

                byte[] dec1 = SerpentA(false, key, enc1);

                if (Compare.AreEqual(data, dec1) == false)
                    throw new Exception("Decrypted output is not equal to input data!");
            }
        }

        private byte[] SerpentA(bool Encrypt, byte[] Key, byte[] Data)
        {
            int len = Data.Length;
            int ct = 0;
            byte[] output = new byte[len];

            using (SPX serent = new SPX())
            {
                serent.Init(Encrypt, Key);

                while (ct < len)
                {
                    serent.Transform(Data, ct, output, ct);
                    ct += 16;
                }
            }

            return output;
        }

        private byte[] SerpentB(byte[] Key, byte[] Data)
        {
            int len = Data.Length;
            int ct = 0;
            byte[] output = new byte[len];
            SerpentEngine serpent = new SerpentEngine();

            serpent.Init(true, Key);

            while (ct < len)
            {
                serpent.ProcessBlock(Data, ct, output, ct);
                ct += 16;
            }

            return output;
        }
        #endregion
    }
}
