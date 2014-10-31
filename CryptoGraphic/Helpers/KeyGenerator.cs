using System;
using System.Security.Cryptography;

namespace VTDev.Projects.CEX.Cryptographic.Helpers
{
    internal static class KeyGenerator
    {
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

        /// <summary>
        /// Get a random seed value
        /// </summary>
        /// <returns>96 bytes of p-rand</returns>
        internal static byte[] GetSeed96()
        {
            byte[] seed = new byte[96];
            Buffer.BlockCopy(GetSeed64(), 0, seed, 0, 64);
            Buffer.BlockCopy(GetSeed32(), 0, seed, 64, 32);

            return seed;
        }

        /// <summary>
        /// Get a random seed value
        /// </summary>
        /// <returns>64 bytes of p-rand</returns>
        internal static byte[] GetSeed64()
        {
            byte[] data = new byte[128];
            byte[] key = new byte[128];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(data);
                rng.GetBytes(key);
            }

            using (HMACSHA512 hmac = new HMACSHA512(key))
                return hmac.ComputeHash(data);
        }

        /// <summary>
        /// Get a random seed value
        /// </summary>
        /// <returns>32 bytes of p-rand</returns>
        internal static byte[] GetSeed32()
        {
            byte[] data = new byte[64];
            byte[] key = new byte[64];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(data);
                rng.GetBytes(key);
            }

            using (HMACSHA256 hmac = new HMACSHA256(key))
                return hmac.ComputeHash(data);
        }

        /// <summary>
        /// Get a random seed value
        /// </summary>
        /// <returns>24 bytes of p-rand</returns>
        internal static byte[] GetSeed24()
        {
            byte[] data = new byte[64];
            byte[] key = new byte[64];
            byte[] res = new byte[24];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(data);
                rng.GetBytes(key);
            }

            using (HMACSHA256 hmac = new HMACSHA256(key))
                Buffer.BlockCopy(hmac.ComputeHash(data), 0, res, 0, 24);

            return res;
        }

        /// <summary>
        /// Get a random seed value
        /// </summary>
        /// <returns>16 bytes of p-rand</returns>
        internal static byte[] GetSeed16()
        {
            byte[] data = new byte[64];
            byte[] key = new byte[64];
            byte[] res = new byte[16];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(data);
                rng.GetBytes(key);
            }

            using (HMACSHA256 hmac = new HMACSHA256(key))
                Buffer.BlockCopy(hmac.ComputeHash(data), 0, res, 0, 16);

            return res;
        }
    }
}
