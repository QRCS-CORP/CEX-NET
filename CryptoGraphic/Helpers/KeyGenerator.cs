using System;
using System.Security.Cryptography;

namespace VTDev.Projects.CEX.CryptoGraphic.Helpers
{
    internal static class KeyGenerator
    {
        #region Public
        /// <summary>
        /// Generate an encryption key
        /// </summary>
        /// <param name="KeySize">Key size [KeySizes]</param>
        /// <returns>P-rand array [byte[]]</returns>
        internal static byte[] GenerateKey(KeySizes KeySize)
        {
            switch (KeySize)
            {
                case KeySizes.K128:
                    return GetSeed16();
                case KeySizes.K192:
                    return GetSeed24();
                case KeySizes.K512:
                    return GetSeed64();
                default:
                    return GetSeed32();
            }
        }

        /// <summary>
        /// Generate an ecryption seed
        /// </summary>
        /// <returns>P-rand array [byte[]]</returns>
        internal static byte[] GenerateSeed96()
        {
            byte[] seed = new byte[96];
            Buffer.BlockCopy(GetSeed64(), 0, seed, 0, 64);
            Buffer.BlockCopy(GetSeed32(), 0, seed, 64, 32);

            return seed;
        }

        /// <summary>
        /// Generate an initialization vector
        /// </summary>
        /// <param name="IVSize">Vector size [IVSizes]</param>
        /// <returns>P-rand array [byte[]]</returns>
        internal static byte[] GenerateIV(IVSizes IVSize)
        {
            if (IVSize == IVSizes.V128)
                return GetSeed16();
            else
                return GetSeed32();
        }
        #endregion

        #region Private
        private static byte[] GetSeed64()
        {
            byte[] data = new byte[128];

            using (RNGCryptoServiceProvider rngRandom = new RNGCryptoServiceProvider())
                rngRandom.GetBytes(data);

            using (SHA512 sha512Hash = SHA512Managed.Create())
                return sha512Hash.ComputeHash(data);
        }

        private static byte[] GetSeed32()
        {
            byte[] data = new byte[64];

            using (RNGCryptoServiceProvider rngRandom = new RNGCryptoServiceProvider())
                rngRandom.GetBytes(data);

            using (SHA256 sha256Hash = SHA256Managed.Create())
                return sha256Hash.ComputeHash(data);
        }

        private static byte[] GetSeed24()
        {
            byte[] data = new byte[64];
            byte[] result = new byte[24];

            using (RNGCryptoServiceProvider rngRandom = new RNGCryptoServiceProvider())
                rngRandom.GetBytes(data);

            using (SHA256 sha256Hash = SHA256Managed.Create())
                Buffer.BlockCopy(sha256Hash.ComputeHash(data), 0, result, 0, 24);

            return result;
        }

        private static byte[] GetSeed16()
        {
            byte[] data = new byte[64];
            byte[] result = new byte[16];

            using (RNGCryptoServiceProvider rngRandom = new RNGCryptoServiceProvider())
                rngRandom.GetBytes(data);

            // copy first half of hash in
            using (SHA256 sha256Hash = SHA256Managed.Create())
                Buffer.BlockCopy(sha256Hash.ComputeHash(data), 0, result, 0, 16);

            return result;
        }
        #endregion
    }
}
