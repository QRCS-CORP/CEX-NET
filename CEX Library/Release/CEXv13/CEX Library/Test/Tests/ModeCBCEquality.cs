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
    /// Compares encrypt/decrypt output padding in CBC mode against RijndaelManaged
    /// </summary>
    public class ModeCBCEquality : IVectorTest
    {
        /// <summary>
        /// Compares encrypt/decrypt output padding in CBC mode against RijndaelManaged
        /// </summary>
        /// <returns>Success [bool]</returns>
        public bool Test()
        {
            try
            {
                TestBlocks();
                TestModes();
                return true;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                Logger.LogError("BlockEquality", message, Ex);
                return false;
            }
        }

        #region Tests
        private void TestBlocks()
        {
            byte[][] key = new byte[16][];
            byte[][] iv = new byte[16][];
            byte[][] data = new byte[16][];
            int ct = key.Length;

            CreateDataSet(key, iv, data);

            for (int i = 1; i < ct; i++)
                CompareBlock(key[i], iv[i], data[i]);
        }

        private void TestModes()
        {
            byte[][] key = new byte[16][];
            byte[][] iv = new byte[16][];
            byte[][] data = new byte[16][];
            int ct = key.Length;

            CreateDataSet(key, iv, data);

            for (int i = 1; i < ct; i++)
                CompareMode(key[i], iv[i], data[i], PaddingModes.PKCS7);

            for (int i = 1; i < ct; i++)
                CompareMode(key[i], iv[i], data[i], PaddingModes.X923);
        }

        private void CompareBlock(byte[] key, byte[] iv, byte[] data)
        {
            byte[] enc1 = EncryptRDX(key, iv, data);
            byte[] enc2 = EncryptManaged(key, iv, data);

            if (Compare.AreEqual(enc1, enc2) == false)
                throw new Exception("Encrypted output is not equal!");

            byte[] dec1 = DecryptRDX(key, iv, data);
            byte[] dec2 = DecryptManaged(key, iv, data);

            if (Compare.AreEqual(dec2, dec1) == false)
                throw new Exception("Decrypted output is not equal to input data!");
        }

        private void CompareMode(byte[] key, byte[] iv, byte[] data, PaddingModes Padding)
        {
            PaddingMode mngPad = PaddingMode.Zeros;
            if (Padding == PaddingModes.PKCS7)
                mngPad = PaddingMode.PKCS7;
            else if (Padding == PaddingModes.X923)
                mngPad = PaddingMode.ANSIX923;

            byte[] enc1 = EncryptRDX(key, iv, data, Padding);
            byte[] enc2 = EncryptManaged(key, iv, data, mngPad);

            // bizarre .Net bug: (sometimes) it will add a *full block* of padding for no reason!
            // even if input ends on a block boundary, will add a full block in PKCS7!!
            if (enc1.Length == enc2.Length)
            {
                if (Compare.AreEqual(enc1, enc2) == false)
                    throw new Exception("Encrypted output is not equal!");

                byte[] dec1 = DecryptRDX(key, iv, data, Padding);
                byte[] dec2 = DecryptManaged(key, iv, data, mngPad);

                if (Compare.AreEqual(dec1, dec2) == false)
                    throw new Exception("Decrypted output is not equal to input data!");
            }
        }
        #endregion

        #region Helpers
        private void CreateDataSet(byte[][] Key, byte[][] Iv, byte[][] Data)
        {
            int ct = Key.Length;

            for (int i = 1; i < ct; i++)
            {
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    Key[i] = new byte[32];
                    Iv[i] = new byte[16];
                    uint size = NextUInt16(1200, 16);
                    Data[i] = new byte[ct * size];
                    // to recreate .Net bug, use this, pad is invalid about every 1 in 20
                    //Data[i] = new byte[ct * (i + 1)];

                    rng.GetBytes(Key[i]);
                    rng.GetBytes(Iv[i]);
                    rng.GetBytes(Data[i]);
                }
            }
        }

        private static UInt16 NextUInt16(Int16 Maximum, Int16 Minimum)
        {
            UInt16 num = 0;
            while ((num = NextUInt16()) > Maximum || num < Minimum) { }

            return num;
        }

        private static ushort NextUInt16()
        {
            byte[] data = new byte[2];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                rng.GetBytes(data);

            return BitConverter.ToUInt16(data, 0);
        }
        #endregion

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
        private byte[] EncryptManaged(byte[] Key, byte[] Vector, byte[] Data, PaddingMode Padding = PaddingMode.None)
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

        private byte[] DecryptManaged(byte[] Key, byte[] Vector, byte[] Data, PaddingMode Padding = PaddingMode.None)
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
