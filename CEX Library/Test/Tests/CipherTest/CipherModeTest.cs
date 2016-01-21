#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// NIST Special Publication 800-38A:
    /// http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    /// </summary>
    public class CipherModeTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "NIST SP800-38A KATs testing CBC, CFB, CTR, ECB, and OFB modes.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Cipher Mode tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Vectors
        private static readonly byte[][] _keys =
		{
			HexConverter.Decode("2b7e151628aed2a6abf7158809cf4f3c"),//F.1/F.2/F.3/F.5 -128
			HexConverter.Decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),//F.1/F.2/F.3/F.5 -192
			HexConverter.Decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),//F.1/F.2/F.3/F.5 -256
		};

        private static readonly byte[][] _vectors =
		{
			HexConverter.Decode("000102030405060708090a0b0c0d0e0f"),//F.1/F.2/F.3
			HexConverter.Decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")//F.5
		};

        private static readonly byte[,][] _input =
		{
            {
                //ecb input
			    HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.1.1 ECB-AES128.Encrypt
                HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
            },
            {
                HexConverter.Decode("3ad77bb40d7a3660a89ecaf32466ef97"),//F.1.2 ECB-AES128.Decrypt
                HexConverter.Decode("f5d3d58503b9699de785895a96fdbaaf"),
                HexConverter.Decode("43b1cd7f598ece23881b00e3ed030688"),
                HexConverter.Decode("7b0c785e27e8ad3f8223207104725dd4")
            },
            {
			    HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.1.3 ECB-AES192.Encrypt
                HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
            },
            {
                HexConverter.Decode("bd334f1d6e45f25ff712a214571fa5cc"),//F.1.4 ECB-AES192.Decrypt
                HexConverter.Decode("974104846d0ad3ad7734ecb3ecee4eef"),
                HexConverter.Decode("ef7afd2270e2e60adce0ba2face6444e"),
                HexConverter.Decode("9a4b41ba738d6c72fb16691603c18e0e")
            },
            {
                HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.1.5 ECB-AES256.Encrypt
                HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
            },
            {
			    HexConverter.Decode("f3eed1bdb5d2a03c064b5a7e3db181f8"),//F.1.6 ECB-AES256.Decrypt
                HexConverter.Decode("591ccb10d410ed26dc5ba74a31362870"),
                HexConverter.Decode("b6ed21b99ca6f4f9f153e7b1beafed1d"),
                HexConverter.Decode("23304b7a39f9f3ff067d8d8f9e24ecc7")
            },
            //cbc input
            {
			    HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.2.1 CBC-AES128.Encrypt
                HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
            },
            {
			    HexConverter.Decode("7649abac8119b246cee98e9b12e9197d"),//F.2.2 CBC-AES128.Decrypt
                HexConverter.Decode("5086cb9b507219ee95db113a917678b2"),
                HexConverter.Decode("73bed6b8e3c1743b7116e69e22229516"),
                HexConverter.Decode("3ff1caa1681fac09120eca307586e1a7")
            },
            {
			    HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.2.3 CBC-AES192.Encrypt
                HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
            },
            {
                HexConverter.Decode("4f021db243bc633d7178183a9fa071e8"),//F.2.4 CBC-AES192.Decrypt
                HexConverter.Decode("b4d9ada9ad7dedf4e5e738763f69145a"),
                HexConverter.Decode("571b242012fb7ae07fa9baac3df102e0"),
                HexConverter.Decode("08b0e27988598881d920a9e64f5615cd")
            },
            {
			    HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.2.5 CBC-AES256.Encrypt
                HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
            },
            {
                HexConverter.Decode("f58c4c04d6e5f1ba779eabfb5f7bfbd6"),//F.2.6 CBC-AES256.Decrypt
                HexConverter.Decode("9cfc4e967edb808d679f777bc6702c7d"),
                HexConverter.Decode("39f23369a9d9bacfa530e26304231461"),
                HexConverter.Decode("b2eb05e2c39be9fcda6c19078c6a9d1b")
            },
            // cfb input
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.3.13 CFB128-AES128.Encrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
				HexConverter.Decode("3b3fd92eb72dad20333449f8e83cfb4a"),//F.3.14 CFB128-AES128.Decrypt
				HexConverter.Decode("c8a64537a0b3a93fcde3cdad9f1ce58b"),
				HexConverter.Decode("26751f67a3cbb140b1808cf187a4f4df"),
				HexConverter.Decode("c04b05357c5d1c0eeac4c66f9ff7f2e6")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.3.15 CFB128-AES192.Encrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("cdc80d6fddf18cab34c25909c99a4174"),//F.3.16 CFB128-AES192.Decrypt
				HexConverter.Decode("67ce7f7f81173621961a2b70171d3d7a"),
				HexConverter.Decode("2e1e8a1dd59b88b1c8e60fed1efac4c9"),
				HexConverter.Decode("c05f9f9ca9834fa042ae8fba584b09ff")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.3.17 CFB128-AES256.Encrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("dc7e84bfda79164b7ecd8486985d3860"),//F.3.18 CFB128-AES256.Decrypt
				HexConverter.Decode("39ffed143b28b1c832113c6331e5407b"),
				HexConverter.Decode("df10132415e54b92a13ed0a8267ae2f9"),
				HexConverter.Decode("75a385741ab9cef82031623d55b1e471")
			},
            // ofb input
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.4.1 OFB-AES128.Encrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710"),
			},
			{
				HexConverter.Decode("3b3fd92eb72dad20333449f8e83cfb4a"),//F.4.2 OFB-AES128.Decrypt
				HexConverter.Decode("7789508d16918f03f53c52dac54ed825"),
				HexConverter.Decode("9740051e9c5fecf64344f7a82260edcc"),
				HexConverter.Decode("304c6528f659c77866a510d9c1d6ae5e")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.4.3 OFB-AES192.Encrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("cdc80d6fddf18cab34c25909c99a4174"),//F.4.4 OFB-AES192.Decrypt
				HexConverter.Decode("fcc28b8d4c63837c09e81700c1100401"),
				HexConverter.Decode("8d9a9aeac0f6596f559c6d4daf59a5f2"),
				HexConverter.Decode("6d9f200857ca6c3e9cac524bd9acc92a")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.4.5 OFB-AES256.Encrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("dc7e84bfda79164b7ecd8486985d3860"),//F.4.6 OFB-AES256.Decrypt
				HexConverter.Decode("4febdc6740d20b3ac88f6ad82a4fb08d"),
				HexConverter.Decode("71ab47a086e86eedf39d1c5bba97c408"),
				HexConverter.Decode("0126141d67f37be8538f5a8be740e484")
			},
            {
                //ctr input
			    HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.5.1 CTR-AES128.Encrypt
                HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
            },
            {
                HexConverter.Decode("874d6191b620e3261bef6864990db6ce"),//F.5.2 CTR-AES128.Decrypt
                HexConverter.Decode("9806f66b7970fdff8617187bb9fffdff"),
                HexConverter.Decode("5ae4df3edbd5d35e5b4f09020db03eab"),
                HexConverter.Decode("1e031dda2fbe03d1792170a0f3009cee")
            },
            {
			    HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.5.3 CTR-AES192.Encrypt
                HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
            },
            {
                HexConverter.Decode("1abc932417521ca24f2b0459fe7e6e0b"),//F.5.4 CTR-AES192.Decrypt
                HexConverter.Decode("090339ec0aa6faefd5ccc2c6f4ce8e94"),
                HexConverter.Decode("1e36b26bd1ebc670d1bd1d665620abf7"),
                HexConverter.Decode("4f78a7f6d29809585a97daec58c6b050")
            },
            {
                HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.5.5 CTR-AES256.Encrypt
                HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
            },
            {
			    HexConverter.Decode("601ec313775789a5b7a7f504bbf3d228"),//F.5.6 CTR-AES256.Decrypt
                HexConverter.Decode("f443e3ca4d62b59aca84e990cacaf5c5"),
                HexConverter.Decode("2b0930daa23de94ce87017ba2d84988d"),
                HexConverter.Decode("dfc9c58db67aada613c2dd08457941a6")
            }
		};

        private static readonly byte[,][] _output =
		{
            //ecb output
            {
				HexConverter.Decode("3ad77bb40d7a3660a89ecaf32466ef97"),//F.1.1 ECB-AES128.Encrypt
				HexConverter.Decode("f5d3d58503b9699de785895a96fdbaaf"),
				HexConverter.Decode("43b1cd7f598ece23881b00e3ed030688"),
				HexConverter.Decode("7b0c785e27e8ad3f8223207104725dd4")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.1.2 ECB-AES128.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
				HexConverter.Decode("bd334f1d6e45f25ff712a214571fa5cc"),//F.1.3 ECB-AES192.Encrypt
				HexConverter.Decode("974104846d0ad3ad7734ecb3ecee4eef"),
				HexConverter.Decode("ef7afd2270e2e60adce0ba2face6444e"),
				HexConverter.Decode("9a4b41ba738d6c72fb16691603c18e0e")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.1.4 ECB-AES192.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("f3eed1bdb5d2a03c064b5a7e3db181f8"),//F.1.5 ECB-AES256.Encrypt
				HexConverter.Decode("591ccb10d410ed26dc5ba74a31362870"),
				HexConverter.Decode("b6ed21b99ca6f4f9f153e7b1beafed1d"),
				HexConverter.Decode("23304b7a39f9f3ff067d8d8f9e24ecc7")
			},
			{
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.1.6 ECB-AES256.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            //cbc output
			{
				HexConverter.Decode("7649abac8119b246cee98e9b12e9197d"),//F.2.1 CBC-AES128.Encrypt
				HexConverter.Decode("5086cb9b507219ee95db113a917678b2"),
				HexConverter.Decode("73bed6b8e3c1743b7116e69e22229516"),
				HexConverter.Decode("3ff1caa1681fac09120eca307586e1a7"),
			},
			{
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.2.2 CBC-AES128.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("4f021db243bc633d7178183a9fa071e8"),//F.2.3 CBC-AES192.Encrypt
				HexConverter.Decode("b4d9ada9ad7dedf4e5e738763f69145a"),
				HexConverter.Decode("571b242012fb7ae07fa9baac3df102e0"),
				HexConverter.Decode("08b0e27988598881d920a9e64f5615cd")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.2.4 CBC-AES192.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("f58c4c04d6e5f1ba779eabfb5f7bfbd6"),//F.2.5 CBC-AES256.Encrypt
				HexConverter.Decode("9cfc4e967edb808d679f777bc6702c7d"),
				HexConverter.Decode("39f23369a9d9bacfa530e26304231461"),
				HexConverter.Decode("b2eb05e2c39be9fcda6c19078c6a9d1b")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.2.6 CBC-AES256.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            // cfb output
            {
				HexConverter.Decode("3b3fd92eb72dad20333449f8e83cfb4a"),//F.3.13 CFB128-AES128.Encrypt
				HexConverter.Decode("c8a64537a0b3a93fcde3cdad9f1ce58b"),
				HexConverter.Decode("26751f67a3cbb140b1808cf187a4f4df"),
				HexConverter.Decode("c04b05357c5d1c0eeac4c66f9ff7f2e6")
			},
			{
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.3.14 CFB128-AES128.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("cdc80d6fddf18cab34c25909c99a4174"),//F.3.15 CFB128-AES192.Encrypt
				HexConverter.Decode("67ce7f7f81173621961a2b70171d3d7a"),
				HexConverter.Decode("2e1e8a1dd59b88b1c8e60fed1efac4c9"),
				HexConverter.Decode("c05f9f9ca9834fa042ae8fba584b09ff")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.3.16 CFB128-AES192.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("dc7e84bfda79164b7ecd8486985d3860"),//F.3.17 CFB128-AES256.Encrypt
				HexConverter.Decode("39ffed143b28b1c832113c6331e5407b"),
				HexConverter.Decode("df10132415e54b92a13ed0a8267ae2f9"),
				HexConverter.Decode("75a385741ab9cef82031623d55b1e471")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.3.6  CFB128-AES256.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            // ofb output
            {
				HexConverter.Decode("3b3fd92eb72dad20333449f8e83cfb4a"),//F.4.1 OFB-AES128.Encrypt
				HexConverter.Decode("7789508d16918f03f53c52dac54ed825"),
				HexConverter.Decode("9740051e9c5fecf64344f7a82260edcc"),
				HexConverter.Decode("304c6528f659c77866a510d9c1d6ae5e"),
			},
			{
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.4.2 OFB-AES128.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("cdc80d6fddf18cab34c25909c99a4174"),//F.4.3 OFB-AES192.Encrypt
				HexConverter.Decode("fcc28b8d4c63837c09e81700c1100401"),
				HexConverter.Decode("8d9a9aeac0f6596f559c6d4daf59a5f2"),
				HexConverter.Decode("6d9f200857ca6c3e9cac524bd9acc92a")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.4.4 OFB-AES192.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("dc7e84bfda79164b7ecd8486985d3860"),//F.4.5 OFB-AES256.Encrypt
				HexConverter.Decode("4febdc6740d20b3ac88f6ad82a4fb08d"),
				HexConverter.Decode("71ab47a086e86eedf39d1c5bba97c408"),
				HexConverter.Decode("0126141d67f37be8538f5a8be740e484")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.4.6 OFB-AES256.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            //ctr output
            {
				HexConverter.Decode("874d6191b620e3261bef6864990db6ce"),//F.5.1 CTR-AES128.Encrypt
				HexConverter.Decode("9806f66b7970fdff8617187bb9fffdff"),
				HexConverter.Decode("5ae4df3edbd5d35e5b4f09020db03eab"),
				HexConverter.Decode("1e031dda2fbe03d1792170a0f3009cee")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.5.2 CTR-AES128.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
				HexConverter.Decode("1abc932417521ca24f2b0459fe7e6e0b"),//F.5.3 CTR-AES192.Encrypt
				HexConverter.Decode("090339ec0aa6faefd5ccc2c6f4ce8e94"),
				HexConverter.Decode("1e36b26bd1ebc670d1bd1d665620abf7"),
				HexConverter.Decode("4f78a7f6d29809585a97daec58c6b050")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.5.4 CTR-AES192.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			},
            {
				HexConverter.Decode("601ec313775789a5b7a7f504bbf3d228"),//F.5.5 CTR-AES256.Encrypt
				HexConverter.Decode("f443e3ca4d62b59aca84e990cacaf5c5"),
				HexConverter.Decode("2b0930daa23de94ce87017ba2d84988d"),
				HexConverter.Decode("dfc9c58db67aada613c2dd08457941a6")
			},
            {
				HexConverter.Decode("6bc1bee22e409f96e93d7e117393172a"),//F.5.6 CTR-AES256.Decrypt
				HexConverter.Decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
				HexConverter.Decode("30c81c46a35ce411e5fbc1191a0a52ef"),
				HexConverter.Decode("f69f2445df4f9b17ad2b417be66c3710")
			}
		};
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// The full range of Vector KATs for CBC, CFB, CTR, ECB, and OFB modes.
        /// Throws on all failures.
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                // test modes with each key (128/192/256)
                CBCTest(_keys[0], _input, _output);
                CBCTest(_keys[1], _input, _output);
                CBCTest(_keys[2], _input, _output);
                OnProgress(new TestEventArgs("Passed CBC 128/192/256 bit key encryption and decryption tests.."));

                CFBTest(_keys[0], _input, _output);
                CFBTest(_keys[1], _input, _output);
                CFBTest(_keys[2], _input, _output);
                OnProgress(new TestEventArgs("Passed CFB 128/192/256 bit key encryption and decryption tests.."));

                CTRTest(_keys[0], _input, _output);
                CTRTest(_keys[1], _input, _output);
                CTRTest(_keys[2], _input, _output);
                OnProgress(new TestEventArgs("Passed CTR 128/192/256 bit key encryption and decryption tests.."));

                ECBTest(_keys[0], _input, _output);
                ECBTest(_keys[1], _input, _output);
                ECBTest(_keys[2], _input, _output);
                OnProgress(new TestEventArgs("Passed ECB 128/192/256 bit key encryption and decryption tests.."));

                OFBTest(_keys[0], _input, _output);
                OFBTest(_keys[1], _input, _output);
                OFBTest(_keys[2], _input, _output);
                OnProgress(new TestEventArgs("Passed OFB 128/192/256 bit key encryption and decryption tests.."));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Helpers
        private void ECBTest(byte[] Key, byte[,][] Input, byte[,][] Output)
        {
            byte[] outBytes = new byte[16];
            int index = 0;

            if (Key.Length == 24)
                index = 2;
            else if (Key.Length == 32)
                index = 4;

            using (ECB mode = new ECB(new RHX()))
            {
                mode.Initialize(true, new KeyParams(Key));

                for (int i = 0; i < 4; i++)
                {
                    mode.Transform(Input[index, i], outBytes);

                    if (Evaluate.AreEqual(outBytes, Output[index, i]) == false)
                        throw new Exception("ECB Mode: Encrypted arrays are not equal!");
                }
            }

            index++;

            using (ECB mode = new ECB(new RHX()))
            {
                mode.Initialize(false, new KeyParams(Key));

                for (int i = 0; i < 4; i++)
                {
                    mode.Transform(Input[index, i], outBytes);

                    if (Evaluate.AreEqual(outBytes, _output[index, i]) == false)
                        throw new Exception("ECB Mode: Decrypted arrays are not equal!");
                }
            }
        }

        private void CBCTest(byte[] Key, byte[,][] Input, byte[,][] Output)
        {
            byte[] outBytes = new byte[16];
            byte[] iv = _vectors[0];
            int index = 6;

            if (Key.Length == 24)
                index = 8;
            else if (Key.Length == 32)
                index = 10;

            using (CBC mode = new CBC(new RHX()))
            {
                mode.Initialize(true, new KeyParams(Key, iv));

                for (int i = 0; i < 4; i++)
                {
                    mode.Transform(Input[index, i], outBytes);

                    if (Evaluate.AreEqual(outBytes, Output[index, i]) == false)
                        throw new Exception("CBC Mode: Encrypted arrays are not equal!");
                }
            }

            index++;
            using (CBC mode = new CBC(new RHX()))
            {
                mode.Initialize(false, new KeyParams(Key, iv));

                for (int i = 0; i < 4; i++)
                {
                    mode.Transform(Input[index, i], outBytes);

                    if (Evaluate.AreEqual(outBytes, _output[index, i]) == false)
                        throw new Exception("CBC Mode: Decrypted arrays are not equal!");
                }
            }
        }

        private void CFBTest(byte[] Key, byte[,][] Input, byte[,][] Output)
        {
            byte[] outBytes = new byte[16];
            byte[] iv = _vectors[0];
            int index = 12;

            if (Key.Length == 24)
                index = 14;
            else if (Key.Length == 32)
                index = 16;

            using (CFB mode1 = new CFB(new RHX()))
            {
                mode1.Initialize(true, new KeyParams(Key, iv));

                for (int i = 0; i < 4; i++)
                {
                    mode1.Transform(Input[index, i], 0, outBytes, 0);

                    if (Evaluate.AreEqual(outBytes, Output[index, i]) == false)
                        throw new Exception("CFB Mode: Encrypted arrays are not equal!");
                }
            }

            index++;

            using (CFB mode2 = new CFB(new RHX()))
            {
                mode2.Initialize(false, new KeyParams(Key, iv));

                for (int i = 0; i < 4; i++)
                {
                    mode2.Transform(Input[index, i], outBytes);

                    if (Evaluate.AreEqual(outBytes, _output[index, i]) == false)
                        throw new Exception("CFB Mode: Decrypted arrays are not equal!");
                }
            }
        }

        private void OFBTest(byte[] Key, byte[,][] Input, byte[,][] Output)
        {
            byte[] outBytes = new byte[16];
            byte[] iv = _vectors[0];
            int index = 18;

            if (Key.Length == 24)
                index = 20;
            else if (Key.Length == 32)
                index = 22;

            using (OFB mode = new OFB(new RHX()))
            {
                mode.Initialize(true, new KeyParams(Key, iv));

                for (int i = 0; i < 4; i++)
                {
                    mode.Transform(Input[index, i], outBytes);

                    if (Evaluate.AreEqual(outBytes, Output[index, i]) == false)
                        throw new Exception("OFB Mode: Encrypted arrays are not equal!");
                }
            }

            index++;

            using (OFB mode = new OFB(new RHX()))
            {
                mode.Initialize(false, new KeyParams(Key, iv));

                for (int i = 0; i < 4; i++)
                {
                    mode.Transform(Input[index, i], outBytes);

                    if (Evaluate.AreEqual(outBytes, _output[index, i]) == false)
                        throw new Exception("OFB Mode: Decrypted arrays are not equal!");
                }
            }
        }

        private void CTRTest(byte[] Key, byte[,][] Input, byte[,][] Output)
        {
            byte[] outBytes = new byte[16];
            byte[] iv = _vectors[1];
            int index = 24;

            if (Key.Length == 24)
                index = 26;
            else if (Key.Length == 32)
                index = 28;

            using (CTR mode = new CTR(new RHX()))
            {
                mode.Initialize(true, new KeyParams(Key, iv));

                for (int i = 0; i < 4; i++)
                {
                    mode.Transform(Input[index, i], outBytes);

                    if (Evaluate.AreEqual(outBytes, Output[index, i]) == false)
                        throw new Exception("CTR Mode: Encrypted arrays are not equal!");
                }
            }

            index++;
            using (CTR mode = new CTR(new RHX()))
            {
                mode.Initialize(false, new KeyParams(Key, iv));

                for (int i = 0; i < 4; i++)
                {
                    mode.Transform(Input[index, i], outBytes);

                    if (Evaluate.AreEqual(outBytes, _output[index, i]) == false)
                        throw new Exception("CTR Mode: Decrypted arrays are not equal!");
                }
            }
        }
        #endregion
    }
}
