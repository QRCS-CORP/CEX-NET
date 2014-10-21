using System;
using System.IO;
using System.Runtime.InteropServices;

namespace VTDev.Projects.CEX.CryptoGraphic.Helpers
{
    #region KeyHeaderStruct
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    internal struct KeyHeaderStruct
    {
        internal Int32 Algorithm;
        internal Int32 KeySize;
        internal Int32 IvSize;
        internal Int32 CipherMode;
        internal Int32 PaddingMode;
        internal Int32 BlockSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] KeyID;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] ExtRandom;

        internal KeyHeaderStruct(Algorithms engine, KeySizes keySize, IVSizes ivSize, CipherModes cipher, PaddingModes padding, BlockSizes block)
        {
            this.Algorithm = (Int32)engine;
            this.KeySize = (Int32)keySize;
            this.IvSize = (Int32)ivSize;
            this.CipherMode = (Int32)cipher;
            this.PaddingMode = (Int32)padding;
            this.BlockSize = (Int32)block;
            this.KeyID = Guid.NewGuid().ToByteArray();
            this.ExtRandom = KeyGenerator.GenerateIV(IVSizes.V128);
        }
    }
    #endregion

    internal static class KeyHeader
    {
        #region Constants
        private const int SEEKTO_ENGINE = 0;
        private const int SEEKTO_KEYSIZE = 4;
        private const int SEEKTO_IVSIZE = 8;
        private const int SEEKTO_CIPHER = 12;
        private const int SEEKTO_PADDING = 16;
        private const int SEEKTO_BLOCK = 20;
        private const int SEEKTO_ID = 24;
        private const int SEEKTO_RAND = 40;
        private const int SIZE_ENGINE = 4;
        private const int SIZE_KEYSIZE = 4;
        private const int SIZE_IVSIZE = 4;
        private const int SIZE_CIPHER = 4;
        private const int SIZE_PADDING = 4;
        private const int SIZE_BLOCK = 4;
        private const int SIZE_ID = 16;
        private const int SIZE_RAND = 16;
        private const int SIZE_KEYHEADER = 56;
        #endregion

        #region Properties
        internal static int GetHeaderSize { get { return SIZE_KEYHEADER; } }
        #endregion

        #region Serialize
        internal static KeyHeaderStruct DeSerializeHeader(string KeyFile)
        {
            KeyHeaderStruct keyStruct = new KeyHeaderStruct();
            if (!File.Exists(KeyFile)) return keyStruct;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                keyStruct.Algorithm = reader.ReadInt32();
                keyStruct.KeySize = reader.ReadInt32();
                keyStruct.IvSize = reader.ReadInt32();
                keyStruct.CipherMode = reader.ReadInt32();
                keyStruct.PaddingMode = reader.ReadInt32();
                keyStruct.BlockSize = reader.ReadInt32();
                keyStruct.KeyID = reader.ReadBytes(SIZE_ID);
                keyStruct.ExtRandom = reader.ReadBytes(SIZE_RAND);
            }

            return keyStruct;
        }

        internal static KeyHeaderStruct DeSerializeHeader(Stream DataStream)
        {
            KeyHeaderStruct keyStruct = new KeyHeaderStruct();

            using (BinaryReader reader = new BinaryReader(DataStream))
            {
                keyStruct.Algorithm = reader.ReadInt32();
                keyStruct.KeySize = reader.ReadInt32();
                keyStruct.IvSize = reader.ReadInt32();
                keyStruct.CipherMode = reader.ReadInt32();
                keyStruct.PaddingMode = reader.ReadInt32();
                keyStruct.BlockSize = reader.ReadInt32();
                keyStruct.KeyID = reader.ReadBytes(SIZE_ID);
                keyStruct.ExtRandom = reader.ReadBytes(SIZE_RAND);
            }

            return keyStruct;
        }

        internal static Stream SerializeHeader(KeyHeaderStruct Header)
        {
            MemoryStream stream = new MemoryStream(SIZE_KEYHEADER);

            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(Header.Algorithm);
            writer.Write(Header.KeySize);
            writer.Write(Header.IvSize);
            writer.Write(Header.CipherMode);
            writer.Write(Header.PaddingMode);
            writer.Write(Header.BlockSize);
            writer.Write(Header.KeyID);
            writer.Write(Header.ExtRandom);

            return stream;
        }
        #endregion

        #region Getters
        internal static Algorithms GetEngine(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return 0;
            int flag = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_ENGINE, SeekOrigin.Begin);
                flag = reader.ReadInt32();
            }

            return (Algorithms)flag;
        }

        internal static KeySizes GetKeySize(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return 0;
            int flag = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_KEYSIZE, SeekOrigin.Begin);
                flag = reader.ReadInt32();
            }

            return (KeySizes)flag;
        }

        internal static IVSizes GetIvSize(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return 0;
            int flag = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_IVSIZE, SeekOrigin.Begin);
                flag = reader.ReadInt32();
            }

            return (IVSizes)flag;
        }

        internal static CipherModes GetCipherMode(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return 0;
            int flag = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_CIPHER, SeekOrigin.Begin);
                flag = reader.ReadInt32();
            }

            return (CipherModes)flag;
        }

        internal static PaddingModes GetPaddingMode(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return 0;
            int flag = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_PADDING, SeekOrigin.Begin);
                flag = reader.ReadInt32();
            }

            return (PaddingModes)flag;
        }

        internal static BlockSizes GetBlockSize(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return 0;
            int flag = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_BLOCK, SeekOrigin.Begin);
                flag = reader.ReadInt32();
            }

            return (BlockSizes)flag;
        }

        internal static Guid GetKeyId(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return new Guid();
            byte[] flag = new byte[16];

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_ID, SeekOrigin.Begin);
                flag = reader.ReadBytes(SIZE_ID);
            }

            return new Guid(flag);
        }

        internal static byte[] GetExtRandom(string KeyFile)
        {
            byte[] flag = new byte[16];
            if (!File.Exists(KeyFile)) return flag;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_RAND, SeekOrigin.Begin);
                flag = reader.ReadBytes(SIZE_RAND);
            }

            return flag;
        }

        internal static bool IsValid(string KeyFile)
        {
            return ((int)GetEngine(KeyFile) < 4);
        }
        #endregion

        #region Setters
        internal static void SetEngine(string KeyFile, Algorithms Engine)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_ENGINE, SeekOrigin.Begin);
                writer.Write((int)Engine);
            }
        }

        internal static void SetKeySize(string KeyFile, KeySizes KeySize)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_KEYSIZE, SeekOrigin.Begin);
                writer.Write((int)KeySize);
            }
        }

        internal static void SetIvSize(string KeyFile, IVSizes IvSize)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_IVSIZE, SeekOrigin.Begin);
                writer.Write((int)IvSize);
            }
        }

        internal static void SetCipherMode(string KeyFile, CipherModes CipherMode)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_CIPHER, SeekOrigin.Begin);
                writer.Write((int)CipherMode);
            }
        }

        internal static void SetPaddingMode(string KeyFile, PaddingModes PaddingMode)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_PADDING, SeekOrigin.Begin);
                writer.Write((int)PaddingMode);
            }
        }

        internal static void SetBlockSize(string KeyFile, BlockSizes BlockSize)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_BLOCK, SeekOrigin.Begin);
                writer.Write((int)BlockSize);
            }
        }

        internal static void SetKeyId(string KeyFile, Guid KeyId)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_ID, SeekOrigin.Begin);
                writer.Write(KeyId.ToByteArray());
            }
        }
        #endregion
    }
}
