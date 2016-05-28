#region Directives
using System;
using Test.Tests;
using VTDev.Projects.CEX.Test;
using VTDev.Projects.CEX.Test.Tests;
using VTDev.Projects.CEX.Test.Tests.Asymmetric.GMSS;
using VTDev.Projects.CEX.Test.Tests.Asymmetric.McEliece;
using VTDev.Projects.CEX.Test.Tests.Asymmetric.RNBW;
using VTDev.Projects.CEX.Test.Tests.AsymmetricTest.NTRU.Encrypt;
using VTDev.Projects.CEX.Test.Tests.BigInt;
using VTDev.Projects.CEX.Test.Tests.CipherTest;
using VTDev.Projects.CEX.Test.Tests.DigestTest;
using VTDev.Projects.CEX.Test.Tests.GeneratorTest;
using VTDev.Projects.CEX.Test.Tests.MacTest;
using VTDev.Projects.CEX.Test.Tests.PrngTest;
using VTDev.Projects.CEX.Test.Tests.ProcessingTest;
using VTDev.Projects.CEX.Test.Tests.SeedTest;
using VTDev.Projects.CEX.Test.Tests.Tools;
#endregion

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            ConsoleUtils.SizeConsole(80, 60);
            ConsoleUtils.CenterConsole();
            Console.Title = "CEX Test Suite";
            Console.BufferHeight = 600;
            //GetHXVectors();

            Console.WriteLine("**********************************************");
            Console.WriteLine("* CEX Version 1.5                            *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.5.6                          *");
            Console.WriteLine("* Date:      May 28, 2016                    *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");

            Console.WriteLine("******TESTING BLOCK CIPHERS******");
            RunTest(new RijndaelTest());
            RunTest(new AesAvsTest());
            RunTest(new AesFipsTest());
            RunTest(new SerpentTest());
            RunTest(new TwofishTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING IO AND CIPHER MODES******");
            RunTest(new CipherModeTest());
            RunTest(new IOTest());
            RunTest(new ParallelModeTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING CIPHER PADDING MODES******");
            RunTest(new PaddingTest());

            Console.WriteLine("******TESTING STREAM CIPHERS******");
            RunTest(new ChaChaTest());
            RunTest(new SalsaTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING MESSAGE DIGESTS******");
            RunTest(new BlakeTest());
            RunTest(new KeccakTest());
            RunTest(new Sha2Test());
            RunTest(new SkeinTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING MESSAGE AUTHENTICATION CODE GENERATORS******");
            RunTest(new HMacTest());
            RunTest(new VmpcMacTest());
            RunTest(new CMacTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING CRYPTOGRAPHIC STREAM PROCESSORS******");
            RunTest(new CipherStreamTest());
            RunTest(new DigestStreamTest());
            RunTest(new MacStreamTest());
            RunTest(new KeyFactoryTest());
            RunTest(new FactoryStructureTest());

            Console.WriteLine("******TESTING DETERMINISTIC RANDOM BYTE GENERATORS******");
            RunTest(new HkdfTest());
            RunTest(new DgcDrbgTest());
            RunTest(new Pbkdf2Test());
            RunTest(new Pkcs5Test());
            Console.WriteLine("");

            Console.WriteLine("******TESTING PSEUDO RANDOM SEED GENERATORS******");
            RunTest(new ISCRsgTest());
            RunTest(new XSPRsgTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING PSEUDO RANDOM NUMBER GENERATORS******");
            RunTest(new SecureRandomTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING THE BIGINTEGER IMPLEMENTATION******");
            RunTest(new BigIntegerTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING COMPRESSION ENGINE******");
            RunTest(new CompressionTest());
            Console.WriteLine("");


            Console.WriteLine(">>> RING-LWE IMPLEMENTATION TESTS <<<");
            Console.WriteLine("");
            // encrypt
            Console.WriteLine("******TESTING ENCRYPTION AND DECRYPTION******");
            RunTest(new RLWEEncryptionTest());
            Console.WriteLine("");

            // serialization tests
            Console.WriteLine("******TESTING KEY SERIALIZATION******");
            RunTest(new RLWEKeyTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING PARAMETERS******");
            RunTest(new RLWEParamTest());
            Console.WriteLine("");

            // cca2 encryption
            Console.WriteLine("******TESTING SIGNING FUNCTIONS******");
            RunTest(new RLWESignTest());
            Console.WriteLine("");


            Console.WriteLine(">>> MCELIECE IMPLEMENTATION TESTS <<<");
            Console.WriteLine("");
            // encrypt
            Console.WriteLine("******TESTING ENCRYPTION AND DECRYPTION******");
            RunTest(new McElieceEncryptionTest());
            Console.WriteLine("");

            // serialization tests
            Console.WriteLine("******TESTING KEY SERIALIZATION******");
            RunTest(new McElieceKeyTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING PARAMETERS******");
            RunTest(new McElieceParamTest());
            Console.WriteLine("");

            // cca2 encryption
            Console.WriteLine("******TESTING SIGNING FUNCTIONS******");
            RunTest(new McElieceSignTest());
            Console.WriteLine("");


            // note: the full test suite used by the java tbuktu version is implemented 
            // on the NTRU Sharp git entry: https://github.com/Steppenwolfe65/NTRU-Sharp
            Console.WriteLine(">>> NTRU IMPLEMENTATION TESTS <<<");
            Console.WriteLine("");

            Console.WriteLine("******TESTING KEYPAIR IMPLEMENTATION******");
            RunTest(new NtruKeyPairTest());

            Console.WriteLine("******TESTING ENCRYPTION ENGINE******");
            RunTest(new NtruEncryptTest());

            Console.WriteLine("******TESTING KEY SERIALIZATION******");
            RunTest(new NtruKeyTest());

            Console.WriteLine("******TESTING PARAMETER SERIALIZATION******");
            RunTest(new NtruParametersTest());

            Console.WriteLine("******TESTING PASSPHRASE BASED RNG******");
            RunTest(new PBPRngTest());
            Console.WriteLine("");


            Console.WriteLine(">>> RAINBOW IMPLEMENTATION TESTS <<<");
            Console.WriteLine("");

            // serialization tests
            Console.WriteLine("******TESTING KEY SERIALIZATION******");
            RunTest(new RNBWKeyTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING PARAMETERS******");
            RunTest(new RNBWParamTest());
            Console.WriteLine("");

            // sign and verify
            Console.WriteLine("******TESTING SIGNING FUNCTIONS******");
            RunTest(new RNBWSignTest());
            Console.WriteLine("");


            Console.WriteLine(">>> GMSS IMPLEMENTATION TESTS <<<");
            Console.WriteLine("");

            // serialization tests
            Console.WriteLine("******TESTING KEY SERIALIZATION******");
            RunTest(new GMSSKeyTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING PARAMETERS******");
            RunTest(new GMSSParamTest());
            Console.WriteLine("");

            // sign and verify
            Console.WriteLine("******TESTING SIGNING FUNCTIONS******");
            RunTest(new GMSSSignTest());
            Console.WriteLine("");


            Console.WriteLine("Completed! Press any key to close..");
            Console.ReadKey();
        }

        private static void RunTest(ITest Test)
        {
            try
            {
                Test.Progress += new EventHandler<TestEventArgs>(OnTestProgress);
                Console.WriteLine(Test.Description);
                Console.WriteLine(Test.Run());
                Console.WriteLine();
            }
            catch (Exception Ex)
            {
                Console.WriteLine("An error has occured!");
                Console.WriteLine(Ex.Message);
                Console.WriteLine("");
                Console.WriteLine("Continue Testing? Press 'Y' to continue, all other keys abort..");
                ConsoleKeyInfo keyInfo = Console.ReadKey();

                if (!keyInfo.Key.Equals(ConsoleKey.Y))
                    Environment.Exit(0);
            }
            finally
            {
                Test.Progress -= OnTestProgress;
            }
        }

        private static void OnTestProgress(object sender, TestEventArgs e)
        {
            Console.WriteLine(e.Message);
        }

        // vector test generators
        private static void GetDrbgVectors()
        {
            DrbgOutputTest t = new DrbgOutputTest();
            Console.WriteLine("Get the test vector for the CTRDrbg implementation");
            Console.WriteLine("");

            string s = t.GetCTRVector();
            // k:32, r:14 -result: b621dbd634714c11d9e72953d580474b37780e36b74edbd5c4b3a506e5a41018
            Console.WriteLine("RHX: r14, k256: " + s);
            Console.WriteLine("Get the test vectors for the SP20Drbg implementation");
            s = t.GetSP20Vector(24);
            // k:16, r:20 -result: a29a83f8607860361e180eab1de0832f1529ea1c72fc501bd37df9d4e15cff1f
            Console.WriteLine("Salsa20: r20, k128: " + s);
            Console.WriteLine("");
            s = t.GetSP20Vector(40);
            // k:32, r:20 -result: d00b46e37495862e642c35be3a1149a8562ee50cdafe3a5f4b26a5c579a45c36
            Console.WriteLine("Salsa20: r20, k256: " + s);
            Console.WriteLine("");

            s = t.GetPBKDFVector(new VTDev.Libraries.CEXEngine.Crypto.Digest.SHA256());
            // SHA256, n:100 -result: a2ab21c1ffd7455f76924b8be3ebb43bc03c591e8d309fc87a8a2483bf4c52d3
            Console.WriteLine("SHA256: n100: " + s);
            Console.WriteLine("");

            s = t.GetPBKDFVector(new VTDev.Libraries.CEXEngine.Crypto.Digest.SHA512());
            // SHA512, n:100 -result: cc46b9de43b3e3eac0685e5f945458e5da835851645c520f9c8edc91a5da28ee
            Console.WriteLine("SHA512: n100: " + s);
            Console.WriteLine("");
        }

        private static void GetHXVectors()
        {
            HXCipherOutputTest t = new HXCipherOutputTest();
            Console.WriteLine("Get 100 round Monte Carlo Vectors for RHX, THX and SHX");
            Console.WriteLine("Uses the SHA512 HMAC with a 96 byte key");
            Console.WriteLine("");

            // RHX: r14, sha512 -2ac5dd436cb2a1c976b25a1edaf1f650
            string s = t.GetHXVector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Rijndael,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests.SHA512,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R14);
            Console.WriteLine("RHX: r14, sha512: " + s);
            // RHX: r22, sha512 -497bef5ccb4faee957b7946705c3dc10
            s = t.GetHXVector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Rijndael,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests.SHA512,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R22);
            Console.WriteLine("RHX: r22, sha512: " + s);

            // Get 512 bit key test vectors, standard mode
            // *V1.56* Note: breaking changes to Rijndael key schedule with 512 keys produces different results from previous versions

            // Rijndael: r22, k512, none -05e57d29a9f646d840c070ed3a17da53
            s = t.Get512Vector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Rijndael, 
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R22);
            Console.WriteLine("Rijndael: r22, k512, b16, none: " + s);
            // Rijndael: r22, k512, b32, none -46af483df6bbaf9e3a0aa8c182011752bb8bab6f2ebc4cd424407994f6ff6534
            s = t.Get512Vector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Rijndael,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R22, 32);
            Console.WriteLine("Rijndael: r22, k512, b32, none: " + s);

            // SHX: r32, sha512 -6f4309f375cad2e65fcfa28091ceed17
            s = t.GetHXVector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Serpent,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests.SHA512,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R32);
            Console.WriteLine("SHX: r32, sha512: " + s);
            // SHX: r40, sha512 -9dcd48706592211eb48d659b9df8824f
            s = t.GetHXVector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Serpent,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests.SHA512,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R40);
            Console.WriteLine("SHX: r40, sha512: " + s);
            // Serpent: r40, none -9c41b8c6fba7154b95afc7c8a5449687
            s = t.Get512Vector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Serpent, 
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R40);
            Console.WriteLine("Serpent: r40, none: " + s);
            // THX: r16, sha512 -0b97de0f11367d25ad45d3293072e2bb
            s = t.GetHXVector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Twofish,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests.SHA512,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R16);
            Console.WriteLine("THX: r16, sha512: " + s);
            // THX: r20, sha512 -e0ec1b5807ed879a88a18244237e8bad
            s = t.GetHXVector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Twofish,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests.SHA512,
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R20);
            Console.WriteLine("THX: r20, sha512: " + s);
            // Twofish: r20, none -32626075c43a30a56aa4cc5ddbf58179
            s = t.Get512Vector(VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers.Twofish, 
                VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts.R20);
            Console.WriteLine("Twofish: r20, none: " + s);
        }
    }
}
