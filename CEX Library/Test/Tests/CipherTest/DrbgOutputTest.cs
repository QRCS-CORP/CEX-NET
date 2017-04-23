#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// Outputs expected values for the HX Ciphers
    /// </summary>
    public class DrbgOutputTest
    {
        #region Public Methods
        /// <summary>
        /// Outputs expected values for the SP20Drbg
        /// </summary>
        public string GetSP20Vector(int KeySize)
        {
            SBG spd = new SBG();
            byte[] key = new byte[KeySize];
            byte[] output = new byte[1024];
            for (int i = 0; i < KeySize; i++)
                key[i] = (byte)i;

            spd.Initialize(key);
            spd.Generate(output);

            while (output.Length > 32)
                output = Reduce(output);

            return HexConverter.ToString(output);
        }

        /// <summary>
        /// Outputs expected values for the SP20Drbg (key is 24 or 40)
        /// </summary>
        public string GetCTRVector()
        {
            CMG ctd = new CMG(new RHX());
            int ksze = 48;
            byte[] key = new byte[ksze];
            byte[] output = new byte[1024];

            for (int i = 0; i < ksze; i++)
                key[i] = (byte)i;

            ctd.Initialize(key);
            ctd.Generate(output);

            while (output.Length > 32)
                output = Reduce(output);

            return HexConverter.ToString(output);
        }

        /// <summary>
        /// Outputs expected values for the PBKDF2
        /// </summary>
        public string GetPBKDFVector(IDigest Engine, int Rounds = 100)
        {
            int keySize = Engine.BlockSize;
            PBKDF2 pbk = new PBKDF2(Engine, Rounds);
            byte[] salt = new byte[keySize];
            byte[] output = new byte[1024];

            for (int i = 0; i < salt.Length; i++)
                salt[i] = (byte)i;

            pbk.Initialize(salt);
            pbk.Generate(output);

            while (output.Length > 32)
                output = Reduce(output);

            return HexConverter.ToString(output);
        }
        #endregion

        #region Private
        private static byte[] Reduce(byte[] Seed)
        {
            int len = Seed.Length / 2;
            byte[] data = new byte[len];

            for (int i = 0; i < len; i++)
                data[i] = (byte)(Seed[i] ^ Seed[len + i]);

            return data;
        }
        #endregion
    }
}
