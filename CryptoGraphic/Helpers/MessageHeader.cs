using System;
using System.IO;
using System.Runtime.InteropServices;

namespace VTDev.Projects.CEX.Cryptographic.Helpers
{
    #region MessageHeaderStruct
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    internal struct MessageHeaderStruct
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] MessageID;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Extension;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        internal byte[] MessageHash;

        internal MessageHeaderStruct(byte[] messageID, byte[] messageHash, byte[] extension)
        {
            this.MessageID = messageID;
            this.Extension = new byte[16];
            extension.CopyTo(Extension, 0);
            this.MessageHash = messageHash;
        }
    }
    #endregion

    internal static class MessageHeader
    {
        #region Constants
        private const int SEEKTO_ID = 0;
        private const int SEEKTO_EXT = 16;
        private const int SEEKTO_HASH = 32;
        private const int SIZE_ID = 16;
        private const int SIZE_EXT = 16;
        private const int SIZE_HASH = 32;
        private const int SIZE_MESSAGEHEADER = 64;
        #endregion

        #region Properties
        internal static int GetHeaderSize { get { return SIZE_MESSAGEHEADER; } }
        #endregion

        #region Create
        public static byte[] Create(string KeyFile, string Extension, byte[] Hash)
        {
            // get the header data
            byte[] keyId = KeyHeader.GetKeyId(KeyFile).ToByteArray();
            // encrypt the extension
            byte[] extension = EncryptExtension(Extension, KeyHeader.GetExtRandom(KeyFile));

            // return serialized header
            return MessageHeader.SerializeHeader(new MessageHeaderStruct(keyId, Hash, extension)).ToArray();
        }
        #endregion

        #region Serialize
        internal static MessageHeaderStruct DeSerializeHeader(string MessageFile)
        {
            MessageHeaderStruct messageStruct = new MessageHeaderStruct();
            if (!File.Exists(MessageFile)) return messageStruct;

            using (BinaryReader reader = new BinaryReader(new FileStream(MessageFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                messageStruct.MessageID = reader.ReadBytes(SIZE_ID);
                messageStruct.Extension = reader.ReadBytes(SIZE_EXT);
                messageStruct.MessageHash = reader.ReadBytes(SIZE_HASH);
            }

            return messageStruct;
        }

        internal static MessageHeaderStruct DeSerializeHeader(Stream DataStream)
        {
            MessageHeaderStruct messageStruct = new MessageHeaderStruct();

            using (BinaryReader reader = new BinaryReader(DataStream))
            {
                messageStruct.MessageID = reader.ReadBytes(SIZE_ID);
                messageStruct.Extension = reader.ReadBytes(SIZE_EXT);
                messageStruct.MessageHash = reader.ReadBytes(SIZE_HASH);
            }

            return messageStruct;
        }

        internal static MemoryStream SerializeHeader(MessageHeaderStruct Header)
        {
            MemoryStream stream = new MemoryStream(SIZE_MESSAGEHEADER);

            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(Header.MessageID);
            writer.Write(Header.Extension);
            writer.Write(Header.MessageHash);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Test for valid header in file
        /// </summary>
        /// <param name="FilePath">Full path to message file</param>
        /// <returns>Valid [bool]</returns>
        public static bool HasHeader(string FilePath)
        {
            if (!File.Exists(FilePath)) return false;

            return FileGetSize(FilePath) > GetHeaderSize;
        }

        internal static Guid GetMessageId(string MessageFile)
        {
            Guid flag = Guid.Empty;
            if (!File.Exists(MessageFile)) return flag;

            using (BinaryReader reader = new BinaryReader(new FileStream(MessageFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_ID, SeekOrigin.Begin);
                flag = new Guid(reader.ReadBytes(SIZE_ID));
            }

            return flag;
        }

        /// <summary>
        /// Get original file extension
        /// </summary>
        /// <param name="MessagePath">Full path to message file</param>
        /// <returns>Valid [bool]</returns>
        public static string GetExtension(string MessagePath, byte[] Random)
        {
            if (!File.Exists(MessagePath)) return "";

            byte[] data = new byte[16];
            char[] letters = new char[8];

            using (BinaryReader reader = new BinaryReader(new FileStream(MessagePath, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                reader.BaseStream.Seek(SEEKTO_EXT, SeekOrigin.Begin);
                data = reader.ReadBytes(SIZE_EXT);
            }

            // xor the buffer and hash
            for (int i = 0; i < data.Length; i++)
                data[i] ^= Random[i];

            Buffer.BlockCopy(data, 0, letters, 0, 16);

            return new string(letters).Replace("\0", String.Empty);
        }

        /// <summary>
        /// Encrypt the file extension
        /// </summary>
        /// <param name="MessagePath">File extension</param>
        /// <returns>Encrypted [byte[]]</returns>
        public static byte[] EncryptExtension(string Extension, byte[] Random)
        {
            byte[] data = new byte[16];
            char[] letters = Extension.ToCharArray();
            int len = letters.Length * 2;

            Buffer.BlockCopy(letters, 0, data, 0, len);

            // xor the buffer and hash
            for (int i = 0; i < data.Length; i++)
                data[i] ^= Random[i];

            return data;
        }

        internal static byte[] GetMessageHash(string MessageFile)
        {
            byte[] flag = new byte[32];
            if (!File.Exists(MessageFile)) return flag;

            using (BinaryReader reader = new BinaryReader(new FileStream(MessageFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_HASH, SeekOrigin.Begin);
                flag = reader.ReadBytes(SIZE_HASH);
            }

            return flag;
        }
        #endregion

        #region Setters
        internal static void SetMessageHash(string MessageFile, byte[] Data)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(MessageFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_HASH, SeekOrigin.Begin);
                writer.Write(Data);
            }
        }

        internal static void SetMessageId(string MessageFile, byte[] Data)
        {
            using (BinaryWriter writer = new BinaryWriter(new FileStream(MessageFile, FileMode.Open, FileAccess.Write, FileShare.None)))
            {
                writer.Seek(SEEKTO_ID, SeekOrigin.Begin);
                writer.Write(Data);
            }
        }
        #endregion

        #region Helpers
        private static long FileGetSize(string FilePath)
        {
            try
            {
                return File.Exists(FilePath) ? new FileInfo(FilePath).Length : 0;
            }
            catch { }
            return -1;
        }
        #endregion
    }
}
