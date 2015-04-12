#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    #region MessageHeaderStruct
    /// <summary>
    /// An encrypted file header structure. 
    /// <para>KeyID and Extension values must each be 16 bytes in length.</para>
    /// </summary>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct MessageHeaderStruct
    {
        /// <summary>
        /// The 16 byte key identifier
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] KeyID;
        /// <summary>
        /// The encrypted message file extension
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Extension;
        /// <summary>
        /// The HMAC hash value of the encrypted file
        /// </summary>
        public byte[] MessageMac;

        /// <summary>
        /// MessageHeaderStruct constructor
        /// </summary>
        /// 
        /// <param name="KeyID">A unique 16 byte key ID</param>
        /// <param name="Extension">A 16 byte encrypted file extension</param>
        /// <param name="MessageHash">A message hash value, can be null</param>
        public MessageHeaderStruct(byte[] KeyID, byte[] Extension, byte[] MessageHash = null)
        {
            this.KeyID = KeyID;
            this.Extension = new byte[16];
            Extension.CopyTo(this.Extension, 0);
            this.MessageMac = MessageHash;
        }

        /// <summary>
        /// Clear all struct members
        /// </summary>
        public void Reset()
        {
            this.KeyID = null;
            this.Extension = null;
            this.MessageMac = null;
        }
    }
    #endregion

    /// <summary>
    /// <h3>A helper class that manages a message header structure.</h3>
    /// 
    /// <list type="bullet">
    /// <item><description>KeyID and Extension values must always be 16 bytes in length; if they are not specified they are auto-generated.</description></item>
    /// <item><description>GetHeaderSize returns size of base header; the size of the optional Message Authentication code is contained in the <see cref="KeyHeaderStruct"/>.</description></item>
    /// <item><description>MessageMac is the MAC value of the encrypted message file.</description></item>
    /// <item><description>HMAC key is contained in the Key file.</description></item>
    /// </list>
    /// </summary>
    public static class MessageHeader
    {
        #region Constants
        private const int SEEKTO_ID = 0;
        private const int SEEKTO_EXT = 16;
        private const int SEEKTO_HASH = 32;
        private const int SIZE_ID = 16;
        private const int SIZE_EXT = 16;
        private const int SIZE_BASEHEADER = 32;
        #endregion

        #region Properties
        /// <summary>
        /// Get the size of a MessageHeaderStruct
        /// </summary>
        public static int GetHeaderSize { get { return SIZE_BASEHEADER; } }
        #endregion

        #region Create
        /// <summary>
        /// Create a serialized message header
        /// </summary>
        /// 
        /// <param name="KeyStream">A Stream containing a <see cref="KeyHeaderStruct"/></param>
        /// <param name="Extension">The file extension</param>
        /// <param name="Hash">The message files hash value, can be null</param>
        /// 
        /// <returns>Serialized MessageHeaderStruct</returns>
        public static byte[] Create(Stream KeyStream, string Extension, byte[] Hash = null)
        {
            // get the header data
            byte[] keyId = KeyHeader.GetKeyId(KeyStream).ToByteArray();
            // encrypt the extension
            byte[] extension = EncryptExtension(Extension, KeyHeader.GetExtensionKey(KeyStream));

            // return serialized header
            return MessageHeader.SerializeHeader(new MessageHeaderStruct(keyId, extension, Hash)).ToArray();
        }
        #endregion

        #region Serialize
        /// <summary>
        /// Serialize a <see cref="MessageHeaderStruct"/>
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// <param name="MacLength">Length in bytes of the Message Authentication Code; must align to MacLength property in <see cref="KeyHeaderStruct"/></param>
        /// 
        /// <returns>A populated MessageHeaderStruct</returns>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid MessageStream is used</exception>
        public static MessageHeaderStruct DeSerializeHeader(Stream MessageStream, int MacLength = 0)
        {
            if (MessageStream.Length < SIZE_BASEHEADER)
                throw new ArgumentOutOfRangeException("Message Header stream is too small!");

            BinaryReader reader = new BinaryReader(MessageStream);
            MessageStream.Seek(SEEKTO_ID, SeekOrigin.Begin);

            MessageHeaderStruct msgStruct = new MessageHeaderStruct() 
            { 
                KeyID = reader.ReadBytes(SIZE_ID),
                Extension = reader.ReadBytes(SIZE_EXT)
            };

            if (MacLength > 0)
                msgStruct.MessageMac = reader.ReadBytes(MacLength);

            return msgStruct;
        }

        /// <summary>
        /// Serialize a <see cref="MessageHeaderStruct"/>
        /// </summary>
        /// 
        /// <param name="MessageHeader">An populated MessageHeaderStruct</param>
        /// 
        /// <returns>A serialized MessageHeaderStruct MemoryStream</returns>
        public static MemoryStream SerializeHeader(MessageHeaderStruct MessageHeader)
        {
            MemoryStream stream = new MemoryStream(SIZE_BASEHEADER);

            stream.Write(MessageHeader.KeyID, 0, SIZE_ID);
            stream.Write(MessageHeader.Extension, 0, SIZE_EXT);

            if (MessageHeader.MessageMac != null)
                stream.Write(MessageHeader.MessageMac, 0, MessageHeader.MessageMac.Length);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Encrypt the file extension
        /// </summary>
        /// 
        /// <param name="Extension">The message file extension</param>
        /// <param name="Random">Random byte array used to encrypt the extension</param>
        /// 
        /// <returns>Encrypted file extension</returns>
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

        /// <summary>
        /// Get decrypted file extension
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// <param name="Random">Random byte array used to encrypt the extension</param>
        /// 
        /// <returns>File extension</returns>
        public static string GetExtension(Stream MessageStream, byte[] Random)
        {
            byte[] data = new byte[16];
            char[] letters = new char[8];

            BinaryReader reader = new BinaryReader(MessageStream);

            MessageStream.Seek(SEEKTO_EXT, SeekOrigin.Begin);
            data = reader.ReadBytes(SIZE_EXT);

            // xor the buffer and hash
            for (int i = 0; i < data.Length; i++)
                data[i] ^= Random[i];

            Buffer.BlockCopy(data, 0, letters, 0, 16);

            return new string(letters).Replace("\0", String.Empty);
        }

        /// <summary>
        /// Get the messages unique key identifier
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// 
        /// <returns>The unique 16 byte ID of the key used to encrypt this message</returns>
        public static Guid GetKeyId(Stream MessageStream)
        {
            MessageStream.Seek(SEEKTO_ID, SeekOrigin.Begin);
            return new Guid(new BinaryReader(MessageStream).ReadBytes(SIZE_ID));
        }

        /// <summary>
        /// Get the MAC value for this file
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// <param name="MacSize">Size of the Message Authentication Code</param>
        /// 
        /// <returns>64 byte Hash value</returns>
        public static byte[] GetMessageMac(Stream MessageStream, int MacSize)
        {
            MessageStream.Seek(SEEKTO_HASH, SeekOrigin.Begin);
            return new BinaryReader(MessageStream).ReadBytes(MacSize);
        }

        /// <summary>
        /// Test for valid header in file
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// 
        /// <returns>Valid</returns>
        public static bool HasHeader(Stream MessageStream)
        {
            // not a guarantee of valid header
            return MessageStream.Length >= GetHeaderSize;
        }
        #endregion

        #region Setters
        /// <summary>
        /// Set the messages 16 byte Key ID value
        /// </summary>
        /// 
        /// <param name="MessageStream">The message stream</param>
        /// <param name="Extension">The message file extension</param>
        public static void SetExtension(Stream MessageStream, byte[] Extension)
        {
            MessageStream.Seek(SEEKTO_EXT, SeekOrigin.Begin);
            MessageStream.Write(Extension, 0, SIZE_EXT);
        }

        /// <summary>
        /// Set the messages 16 byte Key ID value
        /// </summary>
        /// 
        /// <param name="MessageStream">The message stream</param>
        /// <param name="KeyID">The unique 16 byte ID of the key used to encrypt this message</param>
        public static void SetKeyId(Stream MessageStream, byte[] KeyID)
        {
            MessageStream.Seek(SEEKTO_ID, SeekOrigin.Begin);
            MessageStream.Write(KeyID, 0, SIZE_ID);
        }

        /// <summary>
        /// Set the messages MAC value
        /// </summary>
        /// 
        /// <param name="MessageStream">The message stream</param>
        /// <param name="Mac">The Message Authentication Code</param>
        public static void SetMessageMac(Stream MessageStream, byte[] Mac)
        {
            MessageStream.Seek(SEEKTO_HASH, SeekOrigin.Begin);
            MessageStream.Write(Mac, 0, Mac.Length);
        }
        #endregion
    }
}
