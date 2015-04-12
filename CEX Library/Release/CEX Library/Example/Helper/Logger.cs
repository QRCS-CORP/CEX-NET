using System;
using System.IO;

namespace VTDev.Projects.CEX.Helper
{
    static class Logger
    {
        #region Enums
        internal enum LogTypes
        {
            Console,
            LogFile,
        }
        #endregion

        #region Constants
        private const string LOGFILE_NAME = "results.txt";
        #endregion

        #region Properties
        internal static LogTypes LogOutput { get; set; }
        internal static string LogPath { get; set; }
        internal static string LogName { get { return LOGFILE_NAME; } }
        #endregion

        #region Constructor
        static Logger()
        {
            LogPath = Path.Combine(Environment.CurrentDirectory, LOGFILE_NAME);
            LogOutput = LogTypes.Console;
        }
        #endregion

        #region Private
        private static void CreateLog()
        {
            const string HEADER = "########################## RDX ANALYSIS RESULTS ##########################";

            WriteFile(HEADER);
        }

        private static void WriteFile(string Message)
        {
            try
            {
                using (StreamWriter writer = File.AppendText(LogPath))
                    writer.WriteLine(Message);
            }
            catch
            {
                Console.WriteLine("The logger could not save an entry!");
            }
        }

        private static void WriteConsole(string Message)
        {
            Console.WriteLine(Message);
        }
        #endregion

        #region Public
        internal static void LogSession()
        {
            if (!File.Exists(LogPath))
                CreateLog();

            WriteFile("");
            WriteFile("Analysis at: " + DateTime.Now.ToLongTimeString() + " : " + DateTime.Now.ToLongDateString());
        }

        internal static void LogResult(string Name, string Description, string State)
        {
            string message = "Name: " + Name + "    Description: " + Description + "    State: " + State;

            if (LogOutput == LogTypes.Console)
                WriteConsole(message);
            else
                WriteFile(message);
        }

        internal static void LogError(string Method, string Description, Exception Ex)
        {
            string message = "Method Name: " + Method + " Description: " + Description;

            if (Ex.InnerException != null)
                message += " Detail: " + Ex.InnerException.ToString();

            if (LogOutput == LogTypes.Console)
                WriteConsole(message);
            else
                WriteFile(message);
        }
        #endregion
    }
}
