using System;
using System.Diagnostics;
using System.Security.Cryptography;
using VTDev.Projects.CEX.Crypto.Ciphers;
using VTDev.Projects.CEX.Crypto.Tests.Ciphers;
using VTDev.Projects.CEX.Crypto;

namespace VTDev.Projects.CEX.Tests
{
    public class SalsaSpeed : ISpeedTest
    {
        #region Enums
        public enum SalsaImplementations
        {
            Ver1, 
            Bouncy, 
        };
        #endregion

        #region Properties
        /// <summary>
        /// Version of Salsa20
        /// </summary>
        public SalsaImplementations Implementation { get; set; }
        /// <summary>
        /// Number of blocks to process in a round
        /// </summary>
        public int BlockCount { get; set; }
        /// <summary>
        /// Number of test iterations
        /// </summary>
        public int Iterations { get; set; }
        #endregion

        public SalsaSpeed(SalsaImplementations Algo, int Iterations, int BlockCount)
        {
            this.Implementation = Algo;
        }

        public string Test()
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[8];
            byte[] data = new byte[BlockCount * 64];
            string ft = @"m\:ss\.ff";
            Stopwatch runTimer = new Stopwatch();

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
                rng.GetBytes(data);
            }

            runTimer.Start();

            if (this.Implementation == SalsaImplementations.Ver1)
            {
                for (int i = 0; i < Iterations; i++)
                    Salsa1Test(key, iv, data);
            }
            else
            {
                for (int i = 0; i < Iterations; i++)
                    Salsa2Test(key, iv, data);
            }

            runTimer.Stop();
            TimeSpan t1 = TimeSpan.FromMilliseconds(runTimer.Elapsed.TotalMilliseconds);

            return t1.ToString(ft);
        }

        private byte[] Salsa1Test(byte[] Key, byte[] Vector, byte[] Data)
        {
            int len = Data.Length;
            int ct = 0;
            byte[] output = new byte[len];

            using (Salsa20 salsa = new Salsa20())
            {
                salsa.Init(new KeyParams(Key, Vector));

                while (ct < len)
                {
                    salsa.Transform(Data, ct, 64, output, ct);
                    ct += 64;
                }
            }

            return output;
        }

        private byte[] Salsa2Test(byte[] Key, byte[] Vector, byte[] Data)
        {
            int len = Data.Length;
            int ct = 0;
            byte[] output = new byte[len];
            Salsa20Engine salsa = new Salsa20Engine();
            salsa.Init(true, Key, Vector);

            while (ct < len)
            {
                salsa.ProcessBytes(Data, ct, 64, output, ct);
                ct += 64;
            }

            return output;
        }
    }
}
