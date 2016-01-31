#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Structure
{
    /// <summary>
    /// An encrypted message file header structure. 
    /// <para>Used in conjunction with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/> class.
    /// KeyID and Extension values must each be 16 bytes in length. Message MAC code is optional.</para>
    /// </summary>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/03/12" version="1.3.2.0">Initial release</revision>
    /// <revision date="2015/07/02" version="1.4.0.0">Changes to documentation and method structure</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream">VTDev.Libraries.CEXEngine.Crypto.Processing CipherStream class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory.PackageFactory">VTDev.Libraries.CEXEngine.Crypto PackageFactory class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures PackageKey structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.KeyAuthority">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures KeyAuthority structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherDescription structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies">VTDev.Libraries.CEXEngine.Crypto.Enumeration KeyPolicies Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates">VTDev.Libraries.CEXEngine.Crypto KeyStates Enumeration</seealso>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct MessageHeader
    {
        #region Constants
        private const int KEYID_SIZE = 16;
        private const int EXTKEY_SIZE = 16;
        private const int SIZE_BASEHEADER = 32;
        private const int SEEKTO_ID = 0;
        private const int SEEKTO_EXT = 16;
        private const int SEEKTO_HASH = 32;
        #endregion

        #region Public Fields
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
        #endregion

        #region Constructor
        /// <summary>
        /// MessageHeader constructor
        /// </summary>
        /// 
        /// <param name="KeyId">A unique 16 byte key ID</param>
        /// <param name="Extension">A 16 byte encrypted file extension</param>
        /// <param name="MessageHash">A message hash value, can be null</param>
        public MessageHeader(byte[] KeyId, byte[] Extension, byte[] MessageHash = null)
        {
            this.KeyID = KeyId;
            this.Extension = new byte[16];
            Extension.CopyTo(this.Extension, 0);
            this.MessageMac = MessageHash;
        }

        /// <summary>
        /// Initialize the MessageHeader structure using a Stream
        /// </summary>
        /// 
        /// <param name="HeaderStream">The Stream containing the MessageHeader</param>
        /// <param name="MacLength">Length in bytes of the Message Authentication Code; must align to MacLength property in <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/></param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the DataStream is too small</exception>
        public MessageHeader(Stream HeaderStream, int MacLength = 0)
        {
            if (HeaderStream.Length < SIZE_BASEHEADER)
                throw new CryptoProcessingException("MessageHeader:CTor", "MessageHeader stream is too small!", new ArgumentOutOfRangeException());

            BinaryReader reader = new BinaryReader(HeaderStream);

            KeyID = reader.ReadBytes(KEYID_SIZE);
            Extension = reader.ReadBytes(EXTKEY_SIZE);
            MessageMac = reader.ReadBytes(MacLength);
        }

        /// <summary>
        /// Initialize the MessageHeader structure using a byte array
        /// </summary>
        /// 
        /// <param name="HeaderArray">The byte array containing the MessageHeader</param>
        public MessageHeader(byte[] HeaderArray)
        {
            MemoryStream ms = new MemoryStream(HeaderArray);
            BinaryReader reader =  new BinaryReader(ms);
            KeyID = reader.ReadBytes(KEYID_SIZE);
            Extension = reader.ReadBytes(EXTKEY_SIZE);
            long len = ms.Length - ms.Position;
            MessageMac = reader.ReadBytes((int)len);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Clear all struct members
        /// </summary>
        public void Reset()
        {
            if (KeyID != null)
            {
                Array.Clear(KeyID, 0, KeyID.Length);
                KeyID = null;
            }
            if (Extension != null)
            {
                Array.Clear(Extension, 0, Extension.Length);
                Extension = null;
            }
            if (MessageMac != null)
            {
                Array.Clear(MessageMac, 0, MessageMac.Length);
                MessageMac = null;
            }
        }

        /// <summary>
        /// Convert the MessageHeader structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the MessageHeader</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the MessageHeader structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the MessageHeader</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            stream.Write(KeyID, 0, KEYID_SIZE);
            stream.Write(Extension, 0, EXTKEY_SIZE);

            if (MessageMac != null)
                stream.Write(MessageMac, 0, MessageMac.Length);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Get decrypted file extension
        /// </summary>
        /// 
        /// <param name="Extension">The encrypted file extension</param>
        /// <param name="Key">Random byte array used to encrypt the extension</param>
        /// 
        /// <returns>File extension</returns>
        public static string DecryptExtension(byte[] Extension, byte[] Key)
        {
            byte[] data = new byte[16];
            char[] letters = new char[8];

            Buffer.BlockCopy(Extension, 0, data, 0, Extension.Length);

            // xor the buffer and hash
            for (int i = 0; i < data.Length; i++)
                data[i] ^= Key[i];

            Buffer.BlockCopy(data, 0, letters, 0, 16);

            return new string(letters).Replace("\0", String.Empty);
        }

        /// <summary>
        /// Encrypt the file extension
        /// </summary>
        /// 
        /// <param name="Extension">The message file extension</param>
        /// <param name="Key">Random byte array used to encrypt the extension</param>
        /// 
        /// <returns>Encrypted file extension</returns>
        public static byte[] EncryptExtension(string Extension, byte[] Key)
        {
            byte[] data = new byte[16];
            char[] letters = Extension.ToCharArray();
            int len = letters.Length * 2;

            Buffer.BlockCopy(letters, 0, data, 0, len);

            // xor the buffer and hash
            for (int i = 0; i < data.Length; i++)
                data[i] ^= Key[i];

            return data;
        }

        /// <summary>
        /// Get the file extension key
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// 
        /// <returns>The 16 byte extension field</returns>
        public static byte[] GetExtension(Stream MessageStream)
        {
            MessageStream.Seek(SEEKTO_EXT, SeekOrigin.Begin);
            return new BinaryReader(MessageStream).ReadBytes(EXTKEY_SIZE);
        }

        /// <summary>
        /// Get the size of a MessageHeader
        /// </summary>
        public static int GetHeaderSize { get { return SIZE_BASEHEADER; } }

        /// <summary>
        /// Get the messages unique key identifier
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a message header</param>
        /// 
        /// <returns>The unique 16 byte ID of the key used to encrypt this message</returns>
        public static byte[] GetKeyId(Stream MessageStream)
        {
            MessageStream.Seek(SEEKTO_ID, SeekOrigin.Begin);
            return new BinaryReader(MessageStream).ReadBytes(KEYID_SIZE);
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
            MessageStream.Write(Extension, 0, EXTKEY_SIZE);
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
            MessageStream.Write(KeyID, 0, KEYID_SIZE);
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

        #region Overrides
        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int result = 1;
            for (int i = 0; i < KeyID.Length; i++)
                result += 31 * KeyID[i];
            for (int i = 0; i < Extension.Length; i++)
                result += 31 * Extension[i];

            if (MessageMac != null)
            {
                for (int i = 0; i < MessageMac.Length; i++)
                    result += 31 * MessageMac[i];
            }

            return result;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (!(Obj is MessageHeader))
                return false;

            MessageHeader other = (MessageHeader)Obj;

            if (!Compare.IsEqual(KeyID, other.KeyID))
                return false;
            if (!Compare.IsEqual(Extension, other.Extension))
                return false;

            if (MessageMac != null)
            {
                if (!Compare.IsEqual(MessageMac, other.MessageMac))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare this object instance is equal to another
        /// </summary>
        /// 
        /// <param name="X">The first object</param>
        /// <param name="Y">The second object</param>
        /// 
        /// <returns>Equal</returns>
        public static bool operator ==(MessageHeader X, MessageHeader Y)
        {
            return X.Equals(Y);
        }

        /// <summary>
        /// Compare this object instance is not equal to another
        /// </summary>
        /// 
        /// <param name="X">The first object</param>
        /// <param name="Y">The second object</param>
        /// 
        /// <returns>Not equal</returns>
        public static bool operator !=(MessageHeader X, MessageHeader Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
}
