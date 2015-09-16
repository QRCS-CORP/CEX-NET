using System;
using DTMServerTest.Utilities;

namespace DTMServerTest
{
    class Program
    {
        private const string CON_TITLE = "DTM Server> ";

        static void Main(string[] args)
        {
            char[] x = new char[] { (char)0x03 };
            System.Diagnostics.Debug.Print(new string(x));
            ConsoleUtils.SizeConsole(80, 60);
            ConsoleUtils.CenterConsole();
            Console.Title = "Deferred Trust Model KEX Server";

            // header
            Console.WriteLine("**********************************************");
            Console.WriteLine("* Deferred Trust Model DTM-KEX Test          *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.0                            *");
            Console.WriteLine("* Date:      June 26, 2015                   *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");

            new DTMServerTest().TestExchange();
        }
    }
}
