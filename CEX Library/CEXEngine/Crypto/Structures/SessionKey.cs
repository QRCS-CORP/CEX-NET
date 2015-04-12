#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Structures
{
    #region SessionKey
    /// <summary>
    /// Session Key structure; contains a minimal description of the cipher.
    /// <para>Used to create a key file that contains the description and a Key and Vector set, implemented with minimal overhead. 
    /// For use primarily when transporting a symmetric key over an asymmetric stream with a limited maximum message size.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of creating a <c>SessionKey</c> structure:</description>
    /// <code>
    ///  // initialize with CipherDescription structure containing all of the settings used by the cipher instance
    ///  SessionKey session = new SessionKey(cipherDesc);
    /// </code>
    /// <description>Example of writing a KeyParams class to a <c>SessionKey</c> structure:</description>
    /// <code>
    ///  // write key material to the stream
    ///  SessionKey.SetKey(keyStream, keyParams);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/03/12" version="1.3.2.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Helper.KeyFactory">VTDev.Libraries.CEXEngine.Crypto.Helper KeyFactory class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Structures.SessionKey">VTDev.Libraries.CEXEngine.Crypto.Structures SessionKey structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Structures.KeyAuthority">VTDev.Libraries.CEXEngine.Crypto.Structures KeyAuthority structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Structures.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Structures CipherDescription structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.KeyPolicies">VTDev.Libraries.CEXEngine.Crypto KeyPolicies Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.KeyStates">VTDev.Libraries.CEXEngine.Crypto KeyStates Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Process.CipherStream">VTDev.Libraries.CEXEngine.Crypto.Process CipherStream class</seealso>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct SessionKey
    {
        #region Constants
        private const int ENGTPE_SIZE = 1;
        private const int KEYSZE_SIZE = 2;
        private const int IVSIZE_SIZE = 1;
        private const int CPRTPE_SIZE = 1;
        private const int PADTPE_SIZE = 1;
        private const int BLKSZE_SIZE = 1;
        private const int RNDCNT_SIZE = 1;
        private const int KDFENG_SIZE = 1;
        private const int HDR_SIZE = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE;

        private const long ENGTPE_SEEK = 0;
        private const long KEYSZE_SEEK = ENGTPE_SIZE;
        private const long IVSIZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE;
        private const long CPRTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE;
        private const long PADTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE;
        private const long BLKSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE;
        private const long RNDCNT_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE;
        private const long KDFENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE;
        private const long MACSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The Cryptographic <see cref="Engines">Engine</see> type
        /// </summary>
        public byte EngineType;
        /// <summary>
        /// The cipher <see cref="KeySizes">Key Size</see>
        /// </summary>
        public short KeySize;
        /// <summary>
        /// Size of the cipher <see cref="IVSizes">Initialization Vector</see>
        /// </summary>
        public byte IvSize;
        /// <summary>
        /// The type of <see cref="CipherModes">Cipher Mode</see>
        /// </summary>
        public byte CipherType;
        /// <summary>
        /// The type of cipher <see cref="PaddingModes">Padding Mode</see>
        /// </summary>
        public byte PaddingType;
        /// <summary>
        /// The cipher <see cref="BlockSizes">Block Size</see>
        /// </summary>
        public byte BlockSize;
        /// <summary>
        /// The number of diffusion <see cref="RoundCounts">Rounds</see>
        /// </summary>
        public byte RoundCount;
        /// <summary>
        /// The <see cref="Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers
        /// </summary>
        public byte KdfEngine;
        #endregion

        #region Constructor
        /// <summary>
        /// CipherDescription constructor
        /// </summary>
        /// 
        /// <param name="EngineType">The Cryptographic <see cref="Engines">Engine</see> type</param>
        /// <param name="KeySize">The cipher Key Size in bytes</param>
        /// <param name="IvSize">Size of the cipher <see cref="IVSizes">Initialization Vector</see></param>
        /// <param name="CipherType">The type of <see cref="CipherModes">Cipher Mode</see></param>
        /// <param name="PaddingType">The type of cipher <see cref="PaddingModes">Padding Mode</see></param>
        /// <param name="BlockSize">The cipher <see cref="BlockSizes">Block Size</see></param>
        /// <param name="RoundCount">The number of diffusion <see cref="RoundCounts">Rounds</see></param>
        /// <param name="KdfEngine">The <see cref="Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid KeyId, MessageKey, or ExtensionKey is used</exception>
        public SessionKey(Engines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType,
            BlockSizes BlockSize, RoundCounts RoundCount, Digests KdfEngine = Digests.SHA512)
        {
            this.EngineType = (byte)EngineType;
            this.KeySize = (short)KeySize;
            this.IvSize = (byte)IvSize;
            this.CipherType = (byte)CipherType;
            this.PaddingType = (byte)PaddingType;
            this.BlockSize = (byte)BlockSize;
            this.RoundCount = (byte)RoundCount;
            this.KdfEngine = (byte)KdfEngine;
        }
        #endregion

        #region Serialize
        /// <summary>
        /// Deserialize a <see cref="SessionKey"/>
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing a serialized SessionKey</param>
        /// 
        /// <returns>A populated SessionKey</returns>
        public static SessionKey DeSerialize(Stream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            SessionKey session = new SessionKey()
            {
                EngineType = reader.ReadByte(),
                KeySize = reader.ReadInt16(),
                IvSize = reader.ReadByte(),
                CipherType = reader.ReadByte(),
                PaddingType = reader.ReadByte(),
                BlockSize = reader.ReadByte(),
                RoundCount = reader.ReadByte(),
                KdfEngine = reader.ReadByte(),
            };

            return session;
        }

        /// <summary>
        /// Serialize a <see cref="SessionKey"/>
        /// </summary>
        /// 
        /// <param name="Session">A SessionKey</param>
        /// 
        /// <returns>A stream containing the SessionKey data</returns>
        public static Stream Serialize(SessionKey Session)
        {
            MemoryStream stream = new MemoryStream(GetHeaderSize());
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(Session.EngineType);
            writer.Write(Session.KeySize);
            writer.Write(Session.IvSize);
            writer.Write(Session.CipherType);
            writer.Write(Session.PaddingType);
            writer.Write(Session.BlockSize);
            writer.Write(Session.RoundCount);
            writer.Write(Session.KdfEngine);

            return stream;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert a string to a SessionKey structure
        /// </summary>
        /// 
        /// <param name="Session">The string containing the SessionKey</param>
        /// 
        /// <returns>A SessionKey structuree</returns>
        public static SessionKey FromString(string Session)
        {
            return DeSerialize(new MemoryStream(Encoding.ASCII.GetBytes(Session)));
        }

        /// <summary>
        /// Convert a SessionKey to a string representation
        /// </summary>
        /// 
        /// <param name="Session">The SessionKey</param>
        /// 
        /// <returns>An ASCII representation of the structure</returns>
        public static string ToString(SessionKey Session)
        {
            return Encoding.ASCII.GetString(((MemoryStream)Serialize(Session)).ToArray());
        }

        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <returns>Header size</returns>
        public static int GetHeaderSize()
        {
            return HDR_SIZE;
        }

        /// <summary>
        /// Get this is a valid header file
        /// </summary>
        /// 
        /// <param name="Session">The stream containing a key header</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValid(SessionKey Session)
        {
            // not guaranteed, but should be ok
            return (Session.EngineType < Enum.GetValues(typeof(Engines)).Length);
        }

        /// <summary>
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            EngineType = 0;
            KeySize = 0;
            IvSize = 0;
            CipherType = 0;
            PaddingType = 0;
            BlockSize = 0;
            RoundCount = 0;
            KdfEngine = 0;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Get the key data from the key stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a session key</param>
        /// 
        /// <returns>KeyParams structure</returns>
        public static KeyParams GetKey(Stream KeyStream)
        {
            SessionKey session = DeSerialize(KeyStream);
            byte[] key = new byte[session.KeySize];
            byte[] iv = new byte[session.IvSize];

            KeyStream.Seek(HDR_SIZE, SeekOrigin.Begin);
            KeyStream.Read(key, 0, key.Length);
            KeyStream.Read(iv, 0, iv.Length);

            return new KeyParams(key, iv);
        }
        #endregion

        #region Setters
        /// <summary>
        /// Write the key data from the key stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a session key</param>
        /// <param name="KeyData">KeyParams class containing the keying material</param>
        public static void SetKey(Stream KeyStream, KeyParams KeyData)
        {
            byte[] key = KeyData.Key;
            byte[] iv = KeyData.IV;

            KeyStream.Seek(HDR_SIZE, SeekOrigin.Begin);
            KeyStream.Write(key, 0, key.Length);
            KeyStream.Write(iv, 0, iv.Length);
        }

        /// <summary>
        /// Write the key data from the key stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a session key</param>
        /// <param name="Data">A byte array containing the keying material</param>
        public static void SetKey(Stream KeyStream, byte[] Data)
        {
            KeyStream.Seek(HDR_SIZE, SeekOrigin.Begin);
            KeyStream.Write(Data, 0, Data.Length);
        }
        #endregion
    }
    #endregion
}
