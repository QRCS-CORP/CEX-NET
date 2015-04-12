using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using VTDev.Projects.CEX.Crypto.Ciphers;
using VTDev.Projects.CEX.Crypto.Modes;
using VTDev.Projects.CEX.Crypto;

namespace VTDev.Projects.CEX.Tests
{
    /// <summary>
    /// CBC mode speed comparisons between RijndaelManaged and RDX.
    /// </summary>
    public class AesSpeed : ISpeedTest
    {
        #region Enums
        public enum AesImplementations
        {
            Managed, // .Net
            RDX,     // rdx
        };
        #endregion

        #region Properties
        /// <summary>
        /// AES implemntation engine
        /// </summary>
        public AesImplementations Implementation { get; set; }
        /// <summary>
        /// Number of times to perform this test
        /// </summary>
        public int BlockCount { get; set; }
        /// <summary>
        /// Number of 16 byte blocks to encrypt
        /// </summary>
        public int Iterations { get; set; }
        #endregion

        #region Constructor
        public AesSpeed(AesImplementations Engine, int Blocks, int Count)
        {
            this.Implementation = Engine;
            this.BlockCount = Blocks;
            this.Iterations = Count;
        }
        #endregion

        #region Public
        /// <summary>
        /// CBC mode speed comparisons between RijndaelManaged and RDX
        /// </summary>
        /// <param name="Iterations">Number of times to perform this test</param>
        /// <param name="BlockCount">Number of 16 byte blocks to encrypt</param>
        /// <returns>Elapsed milliseconds [string]</returns>
        public string Test()
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            byte[] data = new byte[this.BlockCount * 16];
            string ft = @"m\:ss\.ff";
            Stopwatch runTimer = new Stopwatch();

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv); 
                rng.GetBytes(data);
            }

            runTimer.Start();

            for (int i = 0; i < this.Iterations; i++)
                PerformTest(key, iv, data);

            runTimer.Stop();
            TimeSpan t1 = TimeSpan.FromMilliseconds(runTimer.Elapsed.TotalMilliseconds);

            return t1.ToString(ft);
        }
        #endregion

        #region Test
        private void PerformTest(byte[] Key, byte[] Vector, byte[] Data)
        {
            if (this.Implementation == AesImplementations.Managed)
            {
                byte[] encrypted = EncryptManaged(Key, Vector, Data);
                byte[] decrypted = DecryptManaged(Key, Vector, encrypted);
            }
            else if (this.Implementation == AesImplementations.RDX)
            {
                byte[] encrypted = EncryptRDX(Key, Vector, Data);
                byte[] decrypted = DecryptRDX(Key, Vector, encrypted);
            }
        }
        #endregion

        #region AesManaged
        private byte[] EncryptManaged(byte[] Key, byte[] Vector, byte[] Data)
        {
            byte[] encryptedBytes;

            using (MemoryStream stream = new MemoryStream())
            {
                using (AesManaged cipher = new AesManaged())
                {
                    cipher.Mode = CipherMode.CBC;
                    cipher.KeySize = Key.Length * 8;
                    cipher.BlockSize = Vector.Length * 8;
                    cipher.IV = Vector;
                    cipher.Padding = PaddingMode.None;

                    using (ICryptoTransform encryptor = cipher.CreateEncryptor(Key, Vector))
                    {
                        using (CryptoStream writer = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
                        {
                            writer.Write(Data, 0, Data.Length);
                            writer.FlushFinalBlock();
                            encryptedBytes = stream.ToArray();
                        }
                    }
                    cipher.Clear();
                }
            }
            return encryptedBytes;
        }

        private byte[] DecryptManaged(byte[] Key, byte[] Vector, byte[] Data)
        {
            byte[] decryptedBytes;
            int count = 0;

            using (MemoryStream stream = new MemoryStream(Data))
            {
                using (AesManaged cipher = new AesManaged())
                {
                    cipher.Mode = CipherMode.CBC;
                    cipher.Padding = PaddingMode.None;

                    using (ICryptoTransform decryptor = cipher.CreateDecryptor(Key, Vector))
                    {
                        using (CryptoStream reader = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                        {
                            decryptedBytes = new byte[stream.Length];
                            count = reader.Read(decryptedBytes, 0, decryptedBytes.Length);
                        }
                    }
                    cipher.Clear();
                }
            }
            return decryptedBytes;
        }
        #endregion

        #region RDX
        private byte[] DecryptRDX(byte[] Key, byte[] Vector, byte[] Data)
        {
            int blocks = Data.Length / 16;
            byte[] outputData = new byte[Data.Length];

            RDX transform = new RDX();
            ICipherMode cipher = new CBC(transform);
            cipher.Init(false, new KeyParams(Key, Vector));

            for (int i = 0; i < blocks; i++)
                cipher.Transform(Data, i * 16, outputData, i * 16);

            return outputData;
        }

        private byte[] EncryptRDX(byte[] Key, byte[] Vector, byte[] Data)
        {
            int blocks = Data.Length / 16;
            byte[] outputData = new byte[Data.Length];

            RDX transform = new RDX();
            ICipherMode cipher = new CBC(transform);
            cipher.Init(true, new KeyParams(Key, Vector));

            for (int i = 0; i < blocks; i++)
                cipher.Transform(Data, i * 16, outputData, i * 16);

            return outputData;
        }
        #endregion
    }
}
