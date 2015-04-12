using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Windows.Forms;
using VTDev.Projects.CEX.CryptoGraphic;
using VTDev.Projects.CEX.Tests.BouncyCastle;
using VTDev.Projects.CEX.CryptoGraphic.Helpers;

/// Uses the Bouncy Castle FastAesEngine for comparisons. 
/// Many thanks to the authors of that great project, 
/// and for their tremendous contributions to the open source community..
/// For more information on Bouncy Castle, visit their website: <a href="http://bouncycastle.org/"></a>
namespace VTDev.Projects.CEX.Tests
{
    /// <summary>
    /// Speed comparisons between AesFastEngine, and RDX.
    /// </summary>
    class SpeedTest2
    {
        #region Properties
        internal AesImplementations Implementation { get; set; }
        #endregion

        #region Constructor
        public SpeedTest2(AesImplementations Algo)
        {
            this.Implementation = Algo;
        }
        #endregion

        #region Public
        internal string Test(int Iterations, int BlockCount)
        {
            byte[] key = new byte[32];
            byte[] data = new byte[BlockCount * 16];
            string ft = @"m\:ss\.ff";
            Stopwatch runTimer = new Stopwatch();

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
                rng.GetBytes(data);
            }

            //EqualTest(key, data);

            runTimer.Start();

            for (int i = 0; i < Iterations; i++)
                PerformTest(key, data);

            runTimer.Stop();
            TimeSpan t1 = TimeSpan.FromMilliseconds(runTimer.Elapsed.TotalMilliseconds);
            
            return t1.ToString(ft);
        }
        #endregion

        #region Helpers
        private void PerformTest(byte[] Key, byte[] Data)
        {
            byte[] encrypted = new byte[Data.Length];
            byte[] decrypted = new byte[Data.Length];

            if (this.Implementation == AesImplementations.FastAes)
            {
                encrypted = EncryptAesFast(Key, Data);
                decrypted = DecryptAesFast(Key, encrypted);
            }
            else
            {
                encrypted = EncryptRX(Key, Data);
                decrypted = DecryptRX(Key, encrypted);
            }
        }

        private bool DecAreEqual(byte[] Key, byte[] Data)
        {
            byte[] tmp1 = DecryptAesFast(Key, Data);
            byte[] tmp2 = DecryptRX(Key, Data);

            return Compare.AreEqual(tmp1, tmp2);
        }

        private bool EncAreEqual(byte[] Key, byte[] Data)
        {
            byte[] tmp1 = EncryptAesFast(Key, Data);
            byte[] tmp2 = EncryptRX(Key, Data);

            return Compare.AreEqual(tmp1, tmp2);
        }

        private void EqualTest(byte[] Key, byte[] Data)
        {
            if (!EncAreEqual(Key, Data))
                MessageBox.Show("Encrypted output is not equal!");

            if (!DecAreEqual(Key, Data))
                MessageBox.Show("Encrypted output is not equal!");
        }
        #endregion

        #region RDX
        private byte[] DecryptRX(byte[] Key, byte[] Data)
        {
            int blocks = Data.Length / 16;
            byte[] outputData = new byte[Data.Length];

            RDX transform = new RDX();
            transform.Init(false, Key);

            for (int i = 0; i < blocks; i++)
                transform.DecryptBlock(Data, i * 16, outputData, i * 16);

            return outputData;
        }

        private byte[] EncryptRX(byte[] Key, byte[] Data)
        {
            int blocks = Data.Length / 16;
            byte[] outputData = new byte[Data.Length];

            RDX transform = new RDX();
            transform.Init(true, Key);

            for (int i = 0; i < blocks; i++)
                transform.EncryptBlock(Data, i * 16, outputData, i * 16);

            return outputData;
        }
        #endregion

        #region BouncyCastle AesFastEngine
        private byte[] DecryptAesFast(byte[] Key, byte[] Data)
        {
            int blocks = Data.Length / 16;
            byte[] outputData = new byte[Data.Length];

            AesFastEngine transform = new AesFastEngine();
            transform.Init(false, Key);

            for (int i = 0; i < blocks; i++)
                transform.ProcessBlock(Data, i * 16, outputData, i * 16);

            return outputData;
        }

        private byte[] EncryptAesFast(byte[] Key, byte[] Data)
        {
            int blocks = Data.Length / 16;
            byte[] outputData = new byte[Data.Length];

            AesFastEngine transform = new AesFastEngine();
            transform.Init(true, Key);

            for (int i = 0; i < blocks; i++)
                transform.ProcessBlock(Data, i * 16, outputData, i * 16);

            return outputData;
        }
        #endregion
    }
}
