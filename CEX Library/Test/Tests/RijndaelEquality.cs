using System;
using System.IO;
using System.Security.Cryptography;
using VTDev.Projects.CEX.Crypto.Ciphers;
using VTDev.Projects.CEX.Crypto.Helpers;
using VTDev.Projects.CEX.Crypto.Modes;
using VTDev.Projects.CEX.Crypto.Padding;
using VTDev.Projects.CEX.Helpers;

namespace VTDev.Projects.CEX.Tests
{
    /// <summary>
    /// Compare 16 and 32 byte block outputs against a verified implementation.
    /// Compare RDX vs the RijndaelManaged implementation using random input vectors.
    /// </summary>
    public class RijndaelEquality : IVectorTest
    {
        /// <summary>
        /// Compare output of 16 and 32 byte blocks with RijndaelManaged
        /// </summary>
        /// <returns>Success [bool]</returns>
        public bool Test()
        {
            try
            {
                CompareBlocks(16);
                CompareBlocks(32);
                return true;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                Logger.LogError("BlockEquality", message, Ex);
                return false;
            }
        }

        private void CompareBlocks(int BlockSize)
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[32];
                byte[] iv = new byte[BlockSize];
                byte[] data = new byte[1600];

                rng.GetBytes(key);
                rng.GetBytes(iv);
                rng.GetBytes(data);

                byte[] enc1 = EncryptRDX(key, iv, data);
                byte[] enc2 = EncryptManaged(key, iv, data);

                if (Compare.AreEqual(enc1, enc2) == false)
                    throw new Exception("Encrypted output is not equal!");

                byte[] dec1 = DecryptRDX(key, iv, data);
                byte[] dec2 = DecryptManaged(key, iv, data);

                if (Compare.AreEqual(dec2, dec1) == false)
                    throw new Exception("Decrypted output is not equal to input data!");
            }
        }

        #region RDX
        private byte[] DecryptRDX(byte[] Key, byte[] Vector, byte[] Data, PaddingModes Padding = PaddingModes.Zeros)
        {
            int blockSize = Vector.Length;
            int dataLen = Data.Length;
            int blocks = Data.Length / blockSize;
            int lastBlock = dataLen - blockSize == 0 ? blockSize : dataLen - blockSize;
            byte[] outputData = new byte[Data.Length];
            IPadding pad;

            if (Padding == PaddingModes.PKCS7)
                pad = new PKCS7();
            else if (Padding == PaddingModes.X923)
                pad = new X923();
            else
                pad = new ZeroPad();

            using (ICipherMode mode = new CBC(new RDX()))
            {
                mode.Cipher.BlockSize = blockSize;
                mode.Init(false, Key, Vector);

                for (int i = 0; i < dataLen; i += blockSize)
                    mode.Transform(Data, i, outputData, i);

                int size = pad.GetPaddingLength(outputData);

                if (size > 0)
                    Array.Resize<byte>(ref outputData, dataLen - (size - 1));
            }

            return outputData;
        }

        private byte[] EncryptRDX(byte[] Key, byte[] Vector, byte[] Data, PaddingModes Padding = PaddingModes.Zeros)
        {
            int blockSize = Vector.Length;
            int dataLen = Data.Length;
            int remainder = dataLen % blockSize;
            int blocks = Data.Length / blockSize;
            int alignedSize = blocks * blockSize;
            int lastBlock = alignedSize - blockSize == 0 ? blockSize : alignedSize - blockSize;
            int outSize = remainder > 0 ? alignedSize + blockSize : alignedSize;
            byte[] outputData = new byte[outSize];
            IPadding pad;

            if (Padding == PaddingModes.PKCS7)
                pad = new PKCS7();
            else if (Padding == PaddingModes.X923)
                pad = new X923();
            else
                pad = new ZeroPad();

            using (ICipherMode mode = new CBC(new RDX()))
            {
                mode.Cipher.BlockSize = blockSize;
                mode.Init(true, Key, Vector);

                for (int i = 0; i < alignedSize; i += blockSize)
                    mode.Transform(Data, i, outputData, i);

                if (remainder > 0)
                {
                    byte[] temp = new byte[blockSize];
                    Buffer.BlockCopy(Data, alignedSize, temp, 0, remainder);
                    pad.AddPadding(temp, (int)remainder);
                    mode.Transform(temp, 0, outputData, blockSize);
                }
            }

            return outputData;
        }
        #endregion

        #region RijndaelManaged
        private byte[] EncryptManaged(byte[] Key, byte[] Vector, byte[] Data, PaddingMode Padding = PaddingMode.Zeros)
        {
            byte[] encryptedBytes;

            using (MemoryStream stream = new MemoryStream())
            {
                using (RijndaelManaged cipher = new RijndaelManaged())
                {
                    cipher.Mode = CipherMode.CBC;
                    cipher.KeySize = Key.Length * 8;
                    cipher.BlockSize = Vector.Length * 8;
                    cipher.IV = Vector;
                    cipher.Padding = Padding;

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

        private byte[] DecryptManaged(byte[] Key, byte[] Vector, byte[] Data, PaddingMode Padding = PaddingMode.Zeros)
        {
            byte[] decryptedBytes;
            int count = 0;

            using (MemoryStream stream = new MemoryStream(Data))
            {
                using (RijndaelManaged cipher = new RijndaelManaged())
                {
                    cipher.Mode = CipherMode.CBC;
                    cipher.Padding = Padding;
                    cipher.KeySize = Key.Length * 8;
                    cipher.BlockSize = Vector.Length * 8;

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
    }
}
