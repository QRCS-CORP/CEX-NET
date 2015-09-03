#region Directives
using System;
using VTDev.Projects.CEX.Test.Tests;
using VTDev.Projects.CEX.Test.Tests.Asymmetric.McEliece;
using VTDev.Projects.CEX.Test.Tests.AsymmetricTest.NTRU.Encrypt;
using VTDev.Projects.CEX.Test.Tests.CipherTest;
using VTDev.Projects.CEX.Test.Tests.DigestTest;
using VTDev.Projects.CEX.Test.Tests.GeneratorTest;
using VTDev.Projects.CEX.Test.Tests.MacTest;
using VTDev.Projects.CEX.Test.Tests.PrngTest;
using VTDev.Projects.CEX.Test.Tests.Tools;
using VTDev.Libraries.CEXEngine.Utility;
using VTDev.Projects.CEX.Test;
using VTDev.Projects.CEX.Test.Tests.BigInt;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using Test.Tests;
using VTDev.Projects.CEX.Test.Tests.Asymmetric.RNBW;
using VTDev.Projects.CEX.Test.Tests.Asymmetric.GMSS;
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

            Console.WriteLine("**********************************************");
            Console.WriteLine("* CEX Version 1.4                            *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.4                            *");
            Console.WriteLine("* Date:      July 18, 2015                   *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");

            Console.WriteLine("******TESTING BLOCK CIPHERS******");
            RunTest(new AesAvsTest());
            RunTest(new AesFipsTest());
            RunTest(new RijndaelTest());
            RunTest(new SerpentTest());
            RunTest(new TwofishTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING STREAM CIPHERS******");
            RunTest(new ChaChaTest());
            RunTest(new SalsaTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING IO AND CIPHER MODES******");
            RunTest(new CipherModeTest());
            RunTest(new IOTest());
            RunTest(new ParallelModeTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING MESSAGE DIGESTS******");
            RunTest(new StreamDigestTest());
            RunTest(new BlakeTest());
            RunTest(new KeccakTest());
            RunTest(new Sha2Test());
            RunTest(new SkeinTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING MAC GENERATORS******");
            RunTest(new StreamMacTest());
            RunTest(new HMacTest());
            RunTest(new VmpcMacTest());
            RunTest(new CMacTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING DETERMINISTIC RANDOM BYTE GENERATORS******");
            RunTest(new HkdfTest());
            RunTest(new DgcDrbgTest());
            RunTest(new Pbkdf2Test());
            RunTest(new Pkcs5Test());
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
            //RunTest(new NtruKeyPairTest());

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
            Console.WriteLine("");/**/


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
            Console.WriteLine("");/**/


            Console.WriteLine("Completed! Press any key to close..");
            Console.ReadKey();/**/
        }

        private static void RunTest(ITest Test)
        {
            try
            {
                Test.Progress -= OnTestProgress;
                Test.Progress += new EventHandler<TestEventArgs>(OnTestProgress);
                Console.WriteLine(Test.Description);
                Console.WriteLine(Test.Test());
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
        }

        private static void OnTestProgress(object sender, TestEventArgs e)
        {
            Console.WriteLine(e.Message);
        }
    }
}
