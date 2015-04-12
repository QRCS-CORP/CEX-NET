#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Structures
{
    #region CipherDescription
    /// <summary>
    /// The CipherDescription structure.
    /// <para>Contains all the necessary settings required to recreate a cipher instance.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of populating a <c>CipherDescription</c> structure:</description>
    /// <code>
    ///    CipherDescription cdsc = new CipherDescription(
    ///        Engines.RHX,             // cipher engine
    ///        192,                     // key size in bytes
    ///        IVSizes.V128,            // cipher iv size enum
    ///        CipherModes.CTR,         // cipher mode enum
    ///        PaddingModes.X923,       // cipher padding mode enum
    ///        BlockSizes.B128,         // block size enum
    ///        RoundCounts.R18,         // diffusion rounds enum
    ///        Digests.Skein512,        // cipher kdf engine
    ///        64,                      // mac size
    ///        Digests.Keccak);         // mac digest
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Process.CipherStream">VTDev.Libraries.CEXEngine.Crypto.Process CipherStream class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Structures.KeyPackage">VTDev.Libraries.CEXEngine.Crypto.Structures KeyPackage Structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Structures.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Structures CipherDescription Structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.KeyPolicies">VTDev.Libraries.CEXEngine.Crypto KeyPolicies Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.KeyStates">VTDev.Libraries.CEXEngine.Crypto KeyStates Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prngs">VTDev.Libraries.CEXEngine.Crypto.Prngs Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digests">VTDev.Libraries.CEXEngine.Crypto.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Helper.KeyGenerator">VTDev.Libraries.CEXEngine.Crypto.Helper.KeyGenerator class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.KeyParams">VTDev.Libraries.CEXEngine.Crypto.KeyParams class</seealso>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/09/23" version="1.3.2.0">Rebuilt to accomodate KeyPackage structures</revision>
    /// </revisionHistory>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct CipherDescription
    {
        #region Constants
        private const int ENGTPE_SIZE = 4;
        private const int KEYSZE_SIZE = 4;
        private const int IVSIZE_SIZE = 4;
        private const int CPRTPE_SIZE = 4;
        private const int PADTPE_SIZE = 4;
        private const int BLKSZE_SIZE = 4;
        private const int RNDCNT_SIZE = 4;
        private const int KDFENG_SIZE = 4;
        private const int MACSZE_SIZE = 4;
        private const int MACENG_SIZE = 4;
        private const int HDR_SIZE = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE + MACSZE_SIZE + MACENG_SIZE;

        private const long ENGTPE_SEEK = 0;
        private const long KEYSZE_SEEK = ENGTPE_SIZE;
        private const long IVSIZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE;
        private const long CPRTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE;
        private const long PADTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE;
        private const long BLKSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE;
        private const long RNDCNT_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE;
        private const long KDFENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE;
        private const long MACSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE;
        private const long MACENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE + MACSZE_SIZE;
        #endregion

        #region Public Fields
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
        /// <param name="MacSize">The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key</param>
        /// <param name="MacEngine">The HMAC <see cref="Digests">Digest</see> engine used to authenticate a message file encrypted with this key</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid KeyId, MessageKey, or ExtensionKey is used</exception>
        public CipherDescription(Engines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType,
            BlockSizes BlockSize, RoundCounts RoundCount, Digests KdfEngine = Digests.SHA512, int MacSize = 64, Digests MacEngine = Digests.SHA512)
        {
            this.EngineType = (Int32)EngineType;
            this.KeySize = KeySize;
            this.IvSize = (Int32)IvSize;
            this.CipherType = (Int32)CipherType;
            this.PaddingType = (Int32)PaddingType;
            this.BlockSize = (Int32)BlockSize;
            this.RoundCount = (Int32)RoundCount;
            this.KdfEngine = (Int32)KdfEngine;
            this.MacSize = MacSize;
            this.MacEngine = (Int32)MacEngine; 
        }
        #endregion

        #region Serialize
        /// <summary>
        /// Deserialize a <see cref="CipherDescription"/>
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing a serialized CipherDescription</param>
        /// 
        /// <returns>A populated CipherDescription</returns>
        public static CipherDescription DeSerialize(Stream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            CipherDescription cipherDesc = new CipherDescription()
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
            };

            return cipherDesc;
        }

        /// <summary>
        /// Serialize a <see cref="CipherDescription"/>
        /// </summary>
        /// 
        /// <param name="Description">A CipherDescription</param>
        /// 
        /// <returns>A stream containing the CipherDescription data</returns>
        public static Stream Serialize(CipherDescription Description)
        {
            MemoryStream stream = new MemoryStream(GetHeaderSize());
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(Description.EngineType);
            writer.Write(Description.KeySize);
            writer.Write(Description.IvSize);
            writer.Write(Description.CipherType);
            writer.Write(Description.PaddingType);
            writer.Write(Description.BlockSize);
            writer.Write(Description.RoundCount);
            writer.Write(Description.KdfEngine);
            writer.Write(Description.MacSize);
            writer.Write(Description.MacEngine);

            return stream;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert a string to a CipherDescription structure
        /// </summary>
        /// 
        /// <param name="Package">The string containing the CipherDescription</param>
        /// 
        /// <returns>A CipherDescription structuree</returns>
        public static CipherDescription FromString(string Package)
        {
            return DeSerialize(new MemoryStream(Encoding.ASCII.GetBytes(Package)));
        }

        /// <summary>
        /// Convert a CipherDescription to a string representation
        /// </summary>
        /// 
        /// <param name="Description">The CipherDescription</param>
        /// 
        /// <returns>An ASCII representation of the structure</returns>
        public static string ToString(CipherDescription Description)
        {
            return Encoding.ASCII.GetString(((MemoryStream)Serialize(Description)).ToArray());
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
        /// <param name="Description">The stream containing a key header</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValid(CipherDescription Description)
        {
            // not guaranteed, but should be ok
            return (Description.EngineType < Enum.GetValues(typeof(Engines)).Length);
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
            MacSize = 0;
            MacEngine = 0;
        }
        #endregion
    }
    #endregion
}
