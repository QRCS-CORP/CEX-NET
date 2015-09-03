using System;
using DTMServerTest.Utilities;

namespace DTMClientTest
{
    public static class Program
    {
        const string CON_TITLE = "DTM Client> ";

        static void Main(string[] args)
        {
            ConsoleUtils.SizeConsole(80, 60);
            ConsoleUtils.CenterConsole();
            Console.Title = "Deferred Trust Model KEX Client";

            // header
            Console.WriteLine("**********************************************");
            Console.WriteLine("* Deferred Trust Model DTM-KEX Client Test   *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.0                            *");
            Console.WriteLine("* Date:      June 26, 2015                   *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");

            new DtmClientTest().TestExchange();
        }
    }
}
