#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    #region KeyHeaderStruct
    /// <summary>
    /// Key header structure.
    /// <para>KeyID and ExtRandom values must each be 16 bytes in length.
    /// If they are not specified they will be populated automatically.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of populating a <c>KeyHeaderStruct</c> structure:</description>
    /// <code>
    ///    KeyHeaderStruct khs = new KeyHeaderStruct(
    ///        Engines.RHX,        // cipher engine
    ///        192,                // key size in bytes
    ///        IVSizes.V128,       // cipher iv size enum
    ///        CipherModes.CTR,    // cipher mode enum
    ///        PaddingModes.X923,  // cipher padding mode enum
    ///        BlockSizes.B128,    // block size enum
    ///        RoundCounts.R18,    // diffusion rounds enum
    ///        Digests.Skein512,   // cipher kdf engine
    ///        64,                 // mac size
    ///        Digests.Keccak);    // mac digest
    /// </code>
    /// </example>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct KeyHeaderStruct
    {
        /// <summary>
        /// The Cryptographic <see cref="Engines">Engine</see> type
        /// </summary>
        public Int32 EngineType;
        /// <summary>
        /// The cipher <see cref="KeySizes">Key Size</see>
        /// </summary>
        public Int32 KeySize;
        /// <summary>
        /// Size of the cipher <see cref="IVSizes">Initialization Vector</see>
        /// </summary>
        public Int32 IvSize;
        /// <summary>
        /// The type of <see cref="CipherModes">Cipher Mode</see>
        /// </summary>
        public Int32 CipherType;
        /// <summary>
        /// The type of cipher <see cref="PaddingModes">Padding Mode</see>
        /// </summary>
        public Int32 PaddingType;
        /// <summary>
        /// The cipher <see cref="BlockSizes">Block Size</see>
        /// </summary>
        public Int32 BlockSize;
        /// <summary>
        /// The number of diffusion <see cref="RoundCounts">Rounds</see>
        /// </summary>
        public Int32 RoundCount;
        /// <summary>
        /// The <see cref="Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers
        /// </summary>
        public Int32 KdfEngine;
        /// <summary>
        /// The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key
        /// </summary>
        public Int32 MacSize;
        /// <summary>
        /// The HMAC <see cref="Digests">Digest</see> engine used to authenticate a message file encrypted with this key
        /// </summary>
        public Int32 MacEngine;
        /// <summary>
        /// The unique 16 byte ID field used to identify this key. A null value auto generates this field.
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] KeyID;
        /// <summary>
        /// An array of random bytes used to encrypt a message file extension. A null value auto generates this field.
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ExtensionKey;

        /// <summary>
        /// Key header constructor used with Stream Ciphers. 
        /// <para>Optional fields passing a null value will auto-generate their values.
        /// The KeyId and ExtensionKey fields require a 16 byte value if added manually.</para>
        /// </summary>
        /// 
        /// <param name="EngineType">The Cryptographic <see cref="Engines">Engine</see> type</param>
        /// <param name="KeySize">The cipher Key Size in bytes</param>
        /// <param name="IvSize">Size of the cipher <see cref="IVSizes">Initialization Vector</see></param>
        /// <param name="BlockSize">The cipher <see cref="BlockSizes">Block Size</see></param>
        /// <param name="RoundCount">The number of diffusion <see cref="RoundCounts">Rounds</see></param>
        /// <param name="KdfEngine">The <see cref="Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
        /// <param name="MacEngine">The HMAC <see cref="Digests">Digest</see> engine used to authenticate a message file encrypted with this key</param>
        /// <param name="MacSize">The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key</param>
        /// <param name="KeyId">The unique 16 byte ID field used to identify this key. A null value auto generates this field.</param>
        /// <param name="ExtensionKey">An array of random bytes used to encrypt a message file extension. A null value auto generates this field.</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid KeyId, MessageKey, or ExtensionKey is used</exception>
        public KeyHeaderStruct(Engines EngineType, int KeySize, IVSizes IvSize, BlockSizes BlockSize, RoundCounts RoundCount, 
            Digests KdfEngine = Digests.SHA512, int MacSize = 64, Digests MacEngine = Digests.SHA512, byte[] KeyId = null, byte[] ExtensionKey = null)
        {
            this.EngineType = (Int32)EngineType;
            this.KeySize = KeySize;
            this.IvSize = (Int32)IvSize;
            this.BlockSize = (Int32)BlockSize;
            this.RoundCount = (Int32)RoundCount;
            this.KdfEngine = (Int32)KdfEngine;
            this.MacSize = MacSize;
            this.MacEngine = (Int32)MacEngine;
            this.CipherType = (Int32)CipherModes.CTR;
            this.PaddingType = (Int32)PaddingModes.X923;

            if (KeyId != null)
            {
                if (KeyId.Length != 16)
                    throw new ArgumentOutOfRangeException("Key ID must be exactly 16 bytes in length!");

                this.KeyID = KeyId;
            }
            else
            {
                this.KeyID = Guid.NewGuid().ToByteArray();
            }

            if (ExtensionKey != null)
            {
                if (ExtensionKey.Length != 16)
                    throw new ArgumentOutOfRangeException("Extension key must be exactly 16 bytes in length!");

                this.ExtensionKey = ExtensionKey;
            }
            else
            {
                using (CSPRng rand = new CSPRng())
                    this.ExtensionKey = rand.GetBytes(16);
            }
        }

        /// <summary>
        /// Key header constructor. 
        /// <para>Optional fields passing a null value will auto-generate their values.
        /// The KeyId and ExtensionKey fields require a 16 byte value if added manually.</para>
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
        /// <param name="MacEngine">The HMAC <see cref="Digests">Digest</see> engine used to authenticate a message file encrypted with this key</param>
        /// <param name="MacSize">The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key</param>
        /// <param name="KeyId">The unique 16 byte ID field used to identify this key. A null value auto generates this field.</param>
        /// <param name="ExtensionKey">An array of random bytes used to encrypt a message file extension. A null value auto generates this field.</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid KeyId, MessageKey, or ExtensionKey is used</exception>
        public KeyHeaderStruct(Engines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType,
            BlockSizes BlockSize, RoundCounts RoundCount, Digests KdfEngine = Digests.SHA512, int MacSize = 64, Digests MacEngine = Digests.SHA512, byte[] KeyId = null, byte[] ExtensionKey = null)
        {
            this.EngineType = (Int32)EngineType;
            this.KeySize = KeySize;
            this.CipherType = (Int32)CipherType;
            this.PaddingType = (Int32)PaddingType;
            this.BlockSize = (Int32)BlockSize;
            this.RoundCount = (Int32)RoundCount;
            this.KdfEngine = (Int32)KdfEngine;
            this.MacSize = MacSize;
            this.MacEngine = (Int32)MacEngine;

            if (EngineType == Engines.DCS || CipherType == CipherModes.ECB)
                this.IvSize = 0;
            else
                this.IvSize = (Int32)IvSize;

            if (KeyId != null)
            {
                if (KeyId.Length != 16)
                    throw new ArgumentOutOfRangeException("Key ID must be exactly 16 bytes in length!");

                this.KeyID = KeyId;
            }
            else
            {
                this.KeyID = Guid.NewGuid().ToByteArray();
            }

            if (ExtensionKey != null)
            {
                if (ExtensionKey.Length != 16)
                    throw new ArgumentOutOfRangeException("Extension key must be exactly 16 bytes in length!");

                this.ExtensionKey = ExtensionKey;
            }
            else
            {
                using (CSPRng rand = new CSPRng())
                    this.ExtensionKey = rand.GetBytes(16);
            }
        }

        /// <summary>
        /// Clear all struct members
        /// </summary>
        public void Reset()
        {
            this.EngineType = 0;
            this.KeySize = 0;
            this.IvSize = 0;
            this.CipherType = 0;
            this.PaddingType = 0;
            this.BlockSize = 0;
            this.RoundCount = 0;
            this.KdfEngine = 0;
            this.MacSize = 0;
            this.MacEngine = 0;
            this.KeyID = null;
            this.ExtensionKey = null;
        }
    }
    #endregion

    /// <summary>
    /// <h3>A helper class that manages an encryption key header structure.</h3>
    /// 
    /// <list type="bullet">
    /// <item><description>Keys are contracted MAC enabled by default; set the MacSize member of the KeyHeaderStruct to 0, to disable message authentication.</description></item>
    /// <item><description>The key description and a KeyParams structure containing key material can easily be obtained using the <see cref="KeyFactory"/> class Extract() method</description></item>
    /// <item><description>The KeyID member is a unique Guid that identifies this key in a message file.</description></item>
    /// <item><description>The ExtRandom member is an array of random bytes used to encrypt the messages file extension.</description></item>
    /// <item><description>KeyID and ExtRandom values must always be 16 bytes in length if specified manually.</description></item>
    /// <item><description>KeySize, IvSize, and MacSize determine size values and corresponding offsets of additional Keying material.</description></item>
    /// </list>
    /// </summary>
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
        private const int SEEKTO_KDFENG = 28;
        private const int SEEKTO_MACSIZE = 32;
        private const int SEEKTO_MACENG = 36;
        private const int SEEKTO_ID = 40;
        private const int SEEKTO_EKEY = 56;
        private const int SIZE_ENGINE = 4;
        private const int SIZE_KEYSIZE = 4;
        private const int SIZE_IVSIZE = 4;
        private const int SIZE_CIPHER = 4;
        private const int SIZE_PADDING = 4;
        private const int SIZE_BLOCK = 4;
        private const int SIZE_ROUND = 4;
        private const int SIZE_KDFENG = 4;
        private const int SIZE_MACENG = 4;
        private const int SIZE_MAC = 4;
        private const int SIZE_ID = 16;
        private const int SIZE_EKEY = 16;
        private const int SIZE_KEYHEADER = 72;
        #endregion

        #region Properties
        /// <summary>
        /// Get the size of the KeyHeaderStruct
        /// </summary>
        public static int GetHeaderSize { get { return SIZE_KEYHEADER; } }
        #endregion

        #region Serialize
        /// <summary>
        /// Deserialize a <see cref="KeyHeaderStruct"/>
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing a serialized KeyHeaderStruct</param>
        /// 
        /// <returns>A populated KeyHeaderStruct</returns>
        public static KeyHeaderStruct DeSerializeHeader(Stream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            KeyHeaderStruct keyStruct = new KeyHeaderStruct()
            {
                EngineType = reader.ReadInt32(),
                KeySize = reader.ReadInt32(),
                IvSize = reader.ReadInt32(),
                CipherType = reader.ReadInt32(),
                PaddingType = reader.ReadInt32(),
                BlockSize = reader.ReadInt32(),
                RoundCount = reader.ReadInt32(),
                KdfEngine = reader.ReadInt32(),
                MacSize = reader.ReadInt32(),
                MacEngine = reader.ReadInt32(),
                KeyID = reader.ReadBytes(SIZE_ID),
                ExtensionKey = reader.ReadBytes(SIZE_EKEY),
            };

            return keyStruct;
        }

        /// <summary>
        /// Serialize a <see cref="KeyHeaderStruct"/>
        /// </summary>
        /// 
        /// <param name="KeyHeader">A KeyHeaderStruct</param>
        /// 
        /// <returns>A stream containing the KeyHeaderStruct data</returns>
        public static Stream SerializeHeader(KeyHeaderStruct KeyHeader)
        {
            MemoryStream stream = new MemoryStream(SIZE_KEYHEADER);

            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(KeyHeader.EngineType);
            writer.Write(KeyHeader.KeySize);
            writer.Write(KeyHeader.IvSize);
            writer.Write(KeyHeader.CipherType);
            writer.Write(KeyHeader.PaddingType);
            writer.Write(KeyHeader.BlockSize);
            writer.Write(KeyHeader.RoundCount);
            writer.Write(KeyHeader.KdfEngine);
            writer.Write(KeyHeader.MacSize);
            writer.Write(KeyHeader.MacEngine);
            writer.Write(KeyHeader.KeyID);
            writer.Write(KeyHeader.ExtensionKey);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Get the cipher <see cref="BlockSizes">Block Size</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Cipher Block Size</returns>
        public static BlockSizes GetBlockSize(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_BLOCK, SeekOrigin.Begin);
            return (BlockSizes)new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the cipher processing <see cref="CipherModes">Mode type</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Cipher processing Mode</returns>
        public static CipherModes GetCipherType(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_CIPHER, SeekOrigin.Begin);
            return (CipherModes)new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the cryptographic <see cref="Engines">Engine type</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Cipher Engine type</returns>
        public static Engines GetEngineType(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_ENGINE, SeekOrigin.Begin);
            return (Engines)new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the random field used to encrypt a file extension
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Random array</returns>
        public static byte[] GetExtensionKey(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_EKEY, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadBytes(SIZE_EKEY);
        }

        /// <summary>
        /// Get the Cipher keys Unique ID
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Key ID</returns>
        public static Guid GetKeyId(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_ID, SeekOrigin.Begin);
            return new Guid(new BinaryReader(KeyStream).ReadBytes(SIZE_ID));
        }

        /// <summary>
        /// Get the cipher Key Size in bytes
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Cipher Key size</returns>
        public static int GetKeySize(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_KEYSIZE, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the cipher Key Derivation Function <see cref="Digests">Engine</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Cipher KDF Engine</returns>
        public static Digests GetKdfEngine(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_KDFENG, SeekOrigin.Begin);
            return (Digests)new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the cipher <see cref="IVSizes">IV Size</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Cipher IV Size</returns>
        public static IVSizes GetIvSize(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_IVSIZE, SeekOrigin.Begin);
            return (IVSizes)new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the <see cref="Digests">HMAC engine</see> used to generate the message authentication code
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Digest engine</returns>
        public static Digests GetMacEngine(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_MACENG, SeekOrigin.Begin);
            return (Digests)new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the size of the message authentication code in bytes
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>HMAC hash value size in bytes</returns>
        public static int GetMacSize(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_MACSIZE, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the cipher <see cref="PaddingModes">Padding Mode type</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Cipher Padding Mode</returns>
        public static PaddingModes GetPaddingType(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_PADDING, SeekOrigin.Begin);
            return (PaddingModes)new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the Cipher diffusion <see cref="RoundCounts">Rounds Count</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Cipher Rounds Count</returns>
        public static RoundCounts GetRoundCount(Stream KeyStream)
        {
            KeyStream.Seek(SEEKTO_ROUND, SeekOrigin.Begin);
            return (RoundCounts)new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get this is a valid header file
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValid(Stream KeyStream)
        {
            // not a guarantee, but odds are invalid header will produce a large integer
            return ((int)GetEngineType(KeyStream) < Enum.GetValues(typeof(Engines)).Length);
        }

        /// <summary>
        /// Get this is a valid header file
        /// </summary>
        /// 
        /// <param name="Header">The stream containing a key header</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValid(KeyHeaderStruct Header)
        {
            // not guaranteed
            return (Header.EngineType < Enum.GetValues(typeof(Engines)).Length);
        }
        #endregion

        #region Setters
        /// <summary>
        /// Set the cipher <see cref="BlockSizes">Block Size</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="BlockSize">The cipher block size</param>
        public static void SetBlockSize(Stream KeyStream, BlockSizes BlockSize)
        {
            KeyStream.Seek(SEEKTO_BLOCK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write((int)BlockSize);
        }

        /// <summary>
        /// Set the cipher <see cref="CipherModes">Processing Mode</see> type
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="CipherType">Cipher mode</param>
        public static void SetCipherType(Stream KeyStream, CipherModes CipherType)
        {
            KeyStream.Seek(SEEKTO_CIPHER, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write((int)CipherType);
        }

        /// <summary>
        /// Set the Cipher <see cref="Engines">Engine</see> type
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="EngineType">Engine type</param>
        public static void SetEngineType(Stream KeyStream, Engines EngineType)
        {
            KeyStream.Seek(SEEKTO_ENGINE, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write((int)EngineType);
        }

        /// <summary>
        /// Set the Cipher Key Derivation <see cref="Digests">Engine</see> type
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="EngineType">KDF Engine type</param>
        public static void SetKdfEngine(Stream KeyStream, Digests EngineType)
        {
            KeyStream.Seek(SEEKTO_KDFENG, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write((int)EngineType);
        }

        /// <summary>
        /// Set the unique 16 byte Key ID
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="KeyId">Guid Key id</param>
        public static void SetKeyId(Stream KeyStream, Guid KeyId)
        {
            KeyStream.Seek(SEEKTO_ID, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(KeyId.ToByteArray());
        }

        /// <summary>
        /// Set the cipher Key Size in bytes
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="KeySize">Key size</param>
        public static void SetKeySize(Stream KeyStream, KeySizes KeySize)
        {
            KeyStream.Seek(SEEKTO_KEYSIZE, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write((int)KeySize);
        }

        /// <summary>
        /// Set the cipher <see cref="IVSizes">IV Size</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="IvSize">IV size</param>
        public static void SetIvSize(Stream KeyStream, IVSizes IvSize)
        {
            KeyStream.Seek(SEEKTO_IVSIZE, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write((int)IvSize);
        }

        /// <summary>
        /// Set the HMAC <see cref="Digests">Digest engine</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="Digest">Digest engine type</param>
        public static void SetMacEngine(Stream KeyStream, Digests Digest)
        {
            KeyStream.Seek(SEEKTO_MACENG, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write((int)Digest);
        }

        /// <summary>
        /// Set the HMAC message code size
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="Size">Size of the MAC engine digest</param>
        public static void SetMacSize(Stream KeyStream, int Size)
        {
            KeyStream.Seek(SEEKTO_MACSIZE, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(Size);
        }

        /// <summary>
        /// Set the cipher <see cref="PaddingModes">Padding Mode</see> type
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="PaddingType">Padding mode</param>
        public static void SetPaddingType(Stream KeyStream, PaddingModes PaddingType)
        {
            KeyStream.Seek(SEEKTO_PADDING, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write((int)PaddingType);
        }

        /// <summary>
        /// Set the cipher diffusion <see cref="RoundCounts">Rounds Count</see>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key header</param>
        /// <param name="RoundCount">Rounds count</param>
        public static void SetRoundCount(Stream KeyStream, RoundCounts RoundCount)
        {
            KeyStream.Seek(SEEKTO_ROUND, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write((int)RoundCount);
        }
        #endregion
    }
}
