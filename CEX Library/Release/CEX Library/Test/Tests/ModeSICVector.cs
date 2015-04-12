using System;
using VTDev.Projects.CEX.Crypto.Ciphers;
using VTDev.Projects.CEX.Crypto.Helpers;
using VTDev.Projects.CEX.Crypto.Modes;
using VTDev.Projects.CEX.Helpers;

namespace VTDev.Projects.CEX.Tests
{
    /// <remarks>
    /// Test vectors based on NIST Special Publication 800-38A,
    /// "Recommendation for Block Cipher Modes of Operation"
    /// http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    /// </remarks>
    public class ModeSICVector : IVectorTest
    {
        #region Vectors
        private static readonly byte[][] _keys =
		{
			Hex.Decode("2b7e151628aed2a6abf7158809cf4f3c"),
			Hex.Decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
			Hex.Decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
		};

        private static readonly byte[][] _plainText =
		{
			Hex.Decode("6bc1bee22e409f96e93d7e117393172a"),
			Hex.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
			Hex.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
			Hex.Decode("f69f2445df4f9b17ad2b417be66c3710")
		};

        private static readonly byte[,][] _cipherText =
		{
			{
				Hex.Decode("874d6191b620e3261bef6864990db6ce"),
				Hex.Decode("9806f66b7970fdff8617187bb9fffdff"),
				Hex.Decode("5ae4df3edbd5d35e5b4f09020db03eab"),
				Hex.Decode("1e031dda2fbe03d1792170a0f3009cee")
			},
			{
				Hex.Decode("1abc932417521ca24f2b0459fe7e6e0b"),
				Hex.Decode("090339ec0aa6faefd5ccc2c6f4ce8e94"),
				Hex.Decode("1e36b26bd1ebc670d1bd1d665620abf7"),
				Hex.Decode("4f78a7f6d29809585a97daec58c6b050")
			},
			{
				Hex.Decode("601ec313775789a5b7a7f504bbf3d228"),
				Hex.Decode("f443e3ca4d62b59aca84e990cacaf5c5"),
				Hex.Decode("2b0930daa23de94ce87017ba2d84988d"),
				Hex.Decode("dfc9c58db67aada613c2dd08457941a6")
			}
		};
        #endregion

        #region Public
        /// <summary>
        /// Test vectors based on NIST Special Publication 800-38A
        /// </summary>
        /// <returns>Success [bool]</returns>
        public bool Test()
        {
            try
            {
                PerformTest();
                return true;
            }
            catch(Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                Logger.LogError("SICVector", message, Ex);
                return false;
            }
        }
        #endregion

        #region Helpers
        private void PerformTest()
        {
            byte[] iv = Hex.Decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");

            using (ICipherMode mode = new CTR(new RDX()))
            {
                // NIST vectors
                for (int i = 0; i != _keys.Length; i++)
                {
                    mode.Init(true, _keys[i], iv);

                    for (int j = 0; j != _plainText.Length; j++)
                    {
                        byte[] enc = new byte[16];
                        mode.Transform(_plainText[j], enc);

                        if (Compare.AreEqual(enc, _cipherText[i, j]) == false)
                            throw new Exception("SICTest encrypted arrays are not equal!");
                    }

                    // decrypt
                    mode.Init(false, _keys[i], iv);

                    for (int j = 0; j != _plainText.Length; j++)
                    {
                        byte[] dec = new byte[16];
                        mode.Transform(_cipherText[i, j], dec);

                        if (Compare.AreEqual(dec, _plainText[j]) == false)
                            throw new Exception("SICTest decrypted arrays are not equal!");
                    }
                }
            }
        }
        #endregion
    }
}
