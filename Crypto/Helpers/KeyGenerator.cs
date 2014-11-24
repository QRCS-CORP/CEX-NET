using System;
using VTDev.Projects.CEX.Crypto.Macs;
using VTDev.Projects.CEX.Crypto.Digests;

namespace VTDev.Projects.CEX.Crypto.Helpers
{
    internal static class KeyGenerator
    {
        #region KeyParameter
        internal static KeyParams GetParams(int KeySize, int IVSize = 0, bool UseSHA3 = false)
        {
            if (IVSize > 0)
                return new KeyParams(Generate(KeySize, UseSHA3), Generate(IVSize, UseSHA3));
            else
                return new KeyParams(Generate(KeySize, UseSHA3));
        }
        #endregion

        #region Key Generators
        /// <summary>
        /// Generate a psuedo random byte array
        /// </summary>
        /// <param name="Size">Size of requested array</param>
        /// <param name="UseSHA3">Use an SHA-3 HMac or SHA-2 HMAC for extraction</param>
        /// <returns>Psuedo random bytes [byte[]]</returns>
        internal static byte[] Generate(int Size, bool UseSHA3 = false)
        {
            if (UseSHA3)
                return GenerateKeyNg(Size);
            else
                return GenerateKey(Size);
        }

        /// <summary>
        /// Generate an encryption key using an SHA-2 HMAC
        /// </summary>
        /// <param name="Size">Key size in bytes [byte[]]</param>
        /// <returns>P-rand array [byte[]]</returns>
        internal static byte[] GenerateKey(int Size)
        {
            byte[] key = new byte[Size];

            if (Size < 64)
            {
                Buffer.BlockCopy(GetSeed64(), 0, key, 0, Size);
            }
            else
            {
                int cnt = 0;
                int len = Size - (Size % 64);

                while (cnt < len)
                {
                    Buffer.BlockCopy(GetSeed64(), 0, key, cnt, 64);
                    cnt += 64;
                }

                if (len < Size)
                    Buffer.BlockCopy(GetSeed64(), 0, key, cnt, Size - cnt);
            }

            return key;
        }

        /// <summary>
        /// Generate an encryption key using an SHA-3 HMAC
        /// </summary>
        /// <param name="Size">Key size in bytes [byte[]]</param>
        /// <returns>P-rand array [byte[]]</returns>
        internal static byte[] GenerateKeyNg(int Size)
        {
            byte[] key = new byte[Size];

            if (Size < 64)
            {
                Buffer.BlockCopy(GetSeed64Ng(), 0, key, 0, Size);
            }
            else
            {
                int cnt = 0;
                int len = Size - (Size % 64);

                while (cnt < len)
                {
                    Buffer.BlockCopy(GetSeed64Ng(), 0, key, cnt, 64);
                    cnt += 64;
                }

                if (len < Size)
                    Buffer.BlockCopy(GetSeed64Ng(), 0, key, cnt, Size - cnt);
            }

            return key;
        }
        #endregion

        #region Seed Material
        /// <summary>
        /// Gets bytes p-rand from RNGCryptoServiceProvider
        /// </summary>
        /// <param name="Size">Size of request</param>
        /// <returns>P-Rand bytes [byte[]]</returns>
        internal static byte[] GetRngBytes(int Size)
        {
            byte[] data = new byte[Size];

            using (System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                rng.GetBytes(data);

            return data;
        }

        /// <summary>
        /// Get a random seed value
        /// </summary>
        /// <returns>64 bytes of p-rand</returns>
        internal static byte[] GetSeed64()
        {
            byte[] data = GetRngBytes(256);
            byte[] key = GetRngBytes(64);

            using (SHA512HMAC hmac = new SHA512HMAC(key))
                return hmac.ComputeMac(data);
        }

        /// <summary>
        /// Get a random seed value using an SHA3-512 HMAC
        /// </summary>
        /// <returns>64 bytes of p-rand</returns>
        internal static byte[] GetSeed64Ng()
        {
            byte[] data = GetRngBytes(144);    // 2x block per Nist sp800-90b
            byte[] key = GetRngBytes(64);      // key size per rfc 2104

            using (HMAC hmac = new HMAC(new SHA3Digest(512), key))
                return hmac.ComputeMac(data);
        }

        /// <summary>
        /// Get a random seed value
        /// </summary>
        /// <returns>32 bytes of p-rand</returns>
        internal static byte[] GetSeed32()
        {
            byte[] res = new byte[24];

            Buffer.BlockCopy(GetSeed64(), 0, res, 0, 32);

            return res;
        }

        /// <summary>
        /// Get a random seed value
        /// </summary>
        /// <returns>24 bytes of p-rand</returns>
        internal static byte[] GetSeed24()
        {
            byte[] res = new byte[24];

            Buffer.BlockCopy(GetSeed64(), 0, res, 0, 24);

            return res;
        }

        /// <summary>
        /// Get a random seed value
        /// </summary>
        /// <returns>16 bytes of p-rand</returns>
        internal static byte[] GetSeed16()
        {
            byte[] res = new byte[16];

            Buffer.BlockCopy(GetSeed64(), 0, res, 0, 16);

            return res;
        }
        #endregion
    }
}
