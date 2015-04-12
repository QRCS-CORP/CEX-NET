#region Directives
using System;
using VTDev.Projects.CEX.Test.Tests;
using VTDev.Projects.CEX.Test.Tests.DigestTest;
using VTDev.Projects.CEX.Test.Tests.MacTest;
using VTDev.Projects.CEX.Test.Tests.PrngTest;
using VTDev.Projects.CEX.Test.Tests.CipherTest;
using VTDev.Projects.CEX.Test.Tests.GeneratorTest;
#endregion

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("**********************************************");
            Console.WriteLine("* CEX Version 1.4                            *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.4                            *");
            Console.WriteLine("* Date:      April 27, 2015                  *");
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
            Console.WriteLine("");/**/

            Console.WriteLine("******TESTING MESSAGE DIGESTS******");
            RunTest(new DigestStreamTest());
            RunTest(new BlakeTest());
            RunTest(new KeccakTest());
            RunTest(new Sha2Test());
            RunTest(new SkeinTest());
            Console.WriteLine("");

            Console.WriteLine("******TESTING MAC GENERATORS******");
            RunTest(new MacStreamTest());
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

            Console.WriteLine("Completed! Press any key to close..");
            Console.ReadKey();
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
