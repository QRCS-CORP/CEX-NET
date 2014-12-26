using System;
using System.IO;
using System.Runtime.InteropServices;

namespace VTDev.Libraries.CEXEngine.Crypto.Helpers
{
    #region KeyHeaderStruct
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct KeyHeaderStruct
    {
        internal Int32 Engine;
        internal Int32 KeySize;
        internal Int32 IvSize;
        internal Int32 CipherMode;
        internal Int32 PaddingMode;
        internal Int32 BlockSize;
        internal Int32 RoundCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] KeyID;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] ExtRandom;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        internal byte[] MessageKey;

        public KeyHeaderStruct(Engines engine, KeySizes keySize, IVSizes ivSize, CipherModes cipher, PaddingModes padding, BlockSizes block, RoundCounts round)
        {
            this.Engine = (Int32)engine;
            this.KeySize = (Int32)keySize;
            this.IvSize = (Int32)ivSize;
            this.CipherMode = (Int32)cipher;
            this.PaddingMode = (Int32)padding;
            this.BlockSize = (Int32)block;
            this.RoundCount = (Int32)round;
            this.KeyID = Guid.NewGuid().ToByteArray();
            this.ExtRandom = KeyGenerator.GetSeed16();
            this.MessageKey = KeyGenerator.GetSeed64();
        }
    }
    #endregion

    public static class KeyHeader
    {
        #region Constants
        private const int SEEKTO_ENGINE = 0;
        private const int SEEKTO_KEYSIZE = 4;
        private const int SEEKTO_IVSIZE = 8;
        private const int SEEKTO_CIPHER = 12;
        private const int SEEKTO_PADDING = 16;
        private const int SEEKTO_BLOCK = 20;
        private const int SEEKTO_ROUND = 24;
        private const int SEEKTO_ID = 28;
        private const int SEEKTO_RAND = 44;
        private const int SEEKTO_MKEY = 60;
        private const int SIZE_ENGINE = 4;
        private const int SIZE_KEYSIZE = 4;
        private const int SIZE_IVSIZE = 4;
        private const int SIZE_CIPHER = 4;
        private const int SIZE_PADDING = 4;
        private const int SIZE_BLOCK = 4;
        private const int SIZE_ROUND = 4;
        private const int SIZE_ID = 16;
        private const int SIZE_RAND = 16;
        private const int SIZE_MKEY = 64; // rfc 2104
        private const int SIZE_KEYHEADER = 124;
        #endregion

        #region Properties
        public static int GetHeaderSize { get { return SIZE_KEYHEADER; } }
        #endregion

        #region Serialize
        public static KeyHeaderStruct DeSerializeHeader(string KeyFile)
        {
            KeyHeaderStruct keyStruct = new KeyHeaderStruct();
            if (!File.Exists(KeyFile)) return keyStruct;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                keyStruct.Engine = reader.ReadInt32();
                keyStruct.KeySize = reader.ReadInt32();
                keyStruct.IvSize = reader.ReadInt32();
                keyStruct.CipherMode = reader.ReadInt32();
                keyStruct.PaddingMode = reader.ReadInt32();
                keyStruct.BlockSize = reader.ReadInt32();
                keyStruct.RoundCount = reader.ReadInt32();
                keyStruct.KeyID = reader.ReadBytes(SIZE_ID);
                keyStruct.ExtRandom = reader.ReadBytes(SIZE_RAND);
                keyStruct.MessageKey = reader.ReadBytes(SIZE_MKEY);
            }

            return keyStruct;
        }

        public static KeyHeaderStruct DeSerializeHeader(Stream DataStream)
        {
            KeyHeaderStruct keyStruct = new KeyHeaderStruct();

            using (BinaryReader reader = new BinaryReader(DataStream))
            {
                keyStruct.Engine = reader.ReadInt32();
                keyStruct.KeySize = reader.ReadInt32();
                keyStruct.IvSize = reader.ReadInt32();
                keyStruct.CipherMode = reader.ReadInt32();
                keyStruct.PaddingMode = reader.ReadInt32();
                keyStruct.BlockSize = reader.ReadInt32();
                keyStruct.RoundCount = reader.ReadInt32();
                keyStruct.KeyID = reader.ReadBytes(SIZE_ID);
                keyStruct.ExtRandom = reader.ReadBytes(SIZE_RAND);
                keyStruct.MessageKey = reader.ReadBytes(SIZE_MKEY);
            }

            return keyStruct;
        }

        public static Stream SerializeHeader(KeyHeaderStruct Header)
        {
            MemoryStream stream = new MemoryStream(SIZE_KEYHEADER);

            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(Header.Engine);
            writer.Write(Header.KeySize);
            writer.Write(Header.IvSize);
            writer.Write(Header.CipherMode);
            writer.Write(Header.PaddingMode);
            writer.Write(Header.BlockSize);
            writer.Write(Header.RoundCount);
            writer.Write(Header.KeyID);
            writer.Write(Header.ExtRandom);
            writer.Write(Header.MessageKey);

            return stream;
        }
        #endregion

        #region Getters
        public static Engines GetEngine(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return 0;
            int flag = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_ENGINE, SeekOrigin.Begin);
                flag = reader.ReadInt32();
            }

            return (Engines)flag;
        }

        public static KeySizes GetKeySize(string KeyFile)
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

        public static IVSizes GetIvSize(string KeyFile)
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

        public static CipherModes GetCipherMode(string KeyFile)
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

        public static PaddingModes GetPaddingMode(string KeyFile)
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

        public static BlockSizes GetBlockSize(string KeyFile)
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

        public static RoundCounts GetRoundCount(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return 0;
            int flag = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_ROUND, SeekOrigin.Begin);
                flag = reader.ReadInt32();
            }

            return (RoundCounts)flag;
        }

        public static Guid GetKeyId(string KeyFile)
        {
            if (!File.Exists(KeyFile)) return new Guid();
            byte[] flag = new byte[SIZE_ID];

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_ID, SeekOrigin.Begin);
                flag = reader.ReadBytes(SIZE_ID);
            }

            return new Guid(flag);
        }

        public static byte[] GetExtRandom(string KeyFile)
        {
            byte[] flag = new byte[SIZE_RAND];
            if (!File.Exists(KeyFile)) return flag;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_RAND, SeekOrigin.Begin);
                flag = reader.ReadBytes(SIZE_RAND);
            }

            return flag;
        }

        public static byte[] GetMessageKey(string KeyFile)
        {
            byte[] flag = new byte[SIZE_MKEY];
            if (!File.Exists(KeyFile)) return flag;

            using (BinaryReader reader = new BinaryReader(new FileStream(KeyFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_MKEY, SeekOrigin.Begin);
                flag = reader.ReadBytes(SIZE_MKEY);
            }

            return flag;
        }

        public static bool IsValid(string KeyFile)
        {
            return ((int)GetEngine(KeyFile) < 4);
        }
        #endregion

        #region Setters
        public static void SetEngine(string KeyFile, Engines Engine)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_ENGINE, SeekOrigin.Begin);
                writer.Write((int)Engine);
            }
        }

        public static void SetKeySize(string KeyFile, KeySizes KeySize)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_KEYSIZE, SeekOrigin.Begin);
                writer.Write((int)KeySize);
            }
        }

        public static void SetIvSize(string KeyFile, IVSizes IvSize)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_IVSIZE, SeekOrigin.Begin);
                writer.Write((int)IvSize);
            }
        }

        public static void SetCipherMode(string KeyFile, CipherModes CipherMode)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_CIPHER, SeekOrigin.Begin);
                writer.Write((int)CipherMode);
            }
        }

        public static void SetPaddingMode(string KeyFile, PaddingModes PaddingMode)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_PADDING, SeekOrigin.Begin);
                writer.Write((int)PaddingMode);
            }
        }

        public static void SetBlockSize(string KeyFile, BlockSizes BlockSize)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_BLOCK, SeekOrigin.Begin);
                writer.Write((int)BlockSize);
            }
        }

        public static void SetRoundCount(string KeyFile, RoundCounts RoundCount)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(KeyFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_ROUND, SeekOrigin.Begin);
                writer.Write((int)RoundCount);
            }
        }

        public static void SetKeyId(string KeyFile, Guid KeyId)
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
