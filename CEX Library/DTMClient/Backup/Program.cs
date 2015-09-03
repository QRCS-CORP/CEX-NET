using System;

namespace SocketAsyncClient
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                String host = args[0];
                Int32 port = Convert.ToInt32(args[1]);
                Int16 iterations = 1;
                if (args.Length == 3)
                {
                    iterations = Convert.ToInt16(args[2]);
                }

                using (SocketClient sa = new SocketClient(host, port))
                {
                    sa.Connect();

                    for (Int32 i = 0; i < iterations; i++)
                    {
                        Console.WriteLine(sa.SendReceive("Message #" + i.ToString()));
                    }
                    sa.Disconnect();

                    Console.WriteLine("Press any key to terminate the client process...");
                    Console.Read();
                }
            }
            catch (IndexOutOfRangeException)
            {
                Console.WriteLine("Usage: SocketAsyncClient <host> <port> [iterations]");
            }
            catch (FormatException)
            {
                Console.WriteLine("Usage: SocketAsyncClient <host> <port> [iterations]." +
                    "\r\n\t<host> Name of the host to connect." +
                    "\r\n\t<port> Numeric value for the host listening TCP port." +
                    "\r\n\t[iterations] Number of iterations to the host.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: " + ex.Message);
            }
        }
    }
}
