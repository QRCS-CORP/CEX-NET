#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Common
{
    #region CipherDescription
    /// <summary>
    /// The CipherDescription structure.
    /// <para>Used in conjunction with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/>, <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CompressionCipher"/>, 
    /// <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.PacketCipher"/>, and <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher"/> classes.
    /// Contains all the necessary settings required to recreate a cipher instance.</para>
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
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream">VTDev.Libraries.CEXEngine.Crypto.Processing CipherStream class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher">VTDev.Libraries.CEXEngine.Crypto.Processing VolumeCipher class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures PackageKey Structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies">VTDev.Libraries.CEXEngine.Crypto.Enumeration KeyPolicies Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates">VTDev.Libraries.CEXEngine.Crypto KeyStates Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyGenerator">VTDev.Libraries.CEXEngine.Crypto.KeyGenerator class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams">VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams class</seealso>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/09/23" version="1.3.2.0">Rebuilt to accomodate PackageKey structures</revision>
    /// <revision date="2015/09/23" version="1.3.6.0">Shortened field sizes on serialized header</revision>
    /// </revisionHistory>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct CipherDescription
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
        private const int MACSZE_SIZE = 1;
        private const int MACENG_SIZE = 1;
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
        /// The Cryptographic <see cref="SymmetricEngines">Engine</see> type
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
        /// <param name="EngineType">The Cryptographic <see cref="SymmetricEngines">Engine</see> type</param>
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
        public CipherDescription(SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType,
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

        /// <summary>
        /// Initialize the CipherDescription structure using a Stream
        /// </summary>
        /// 
        /// <param name="DescriptionStream">The Stream containing the CipherDescription</param>
        public CipherDescription(Stream DescriptionStream)
        {
            BinaryReader reader = new BinaryReader(DescriptionStream);

            EngineType = reader.ReadByte();
            KeySize = reader.ReadInt16();
            IvSize = reader.ReadByte();
            CipherType = reader.ReadByte();
            PaddingType = reader.ReadByte();
            BlockSize = reader.ReadByte();
            RoundCount = reader.ReadByte();
            KdfEngine = reader.ReadByte();
            MacSize = reader.ReadByte();
            MacEngine = reader.ReadByte();
        }

        /// <summary>
        /// Initialize the CipherDescription structure using a byte array
        /// </summary>
        /// 
        /// <param name="DescriptionArray">The byte array containing the CipherDescription</param>
        public CipherDescription(byte[] DescriptionArray) :
            this (new MemoryStream(DescriptionArray))
        {
        }
        #endregion

        #region Public Methods
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
            return (Description.EngineType < Enum.GetValues(typeof(SymmetricEngines)).Length << 2);
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

        /// <summary>
        /// Convert the CipherDescription structure as a byte array
        /// </summary>
        /// 
        /// <returns>The byte array containing the CipherDescription</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Convert the CipherDescription structure to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the CipherDescription</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream(GetHeaderSize());
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write((byte)EngineType);
            writer.Write((short)KeySize);
            writer.Write((byte)IvSize);
            writer.Write((byte)CipherType);
            writer.Write((byte)PaddingType);
            writer.Write((byte)BlockSize);
            writer.Write((byte)RoundCount);
            writer.Write((byte)KdfEngine);
            writer.Write((byte)MacSize);
            writer.Write((byte)MacEngine);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
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

            result += 31 * EngineType;
            result += 31 * KeySize;
            result += 31 * IvSize;
            result += 31 * CipherType;
            result += 31 * PaddingType;
            result += 31 * BlockSize;
            result += 31 * RoundCount;
            result += 31 * KdfEngine;
            result += 31 * MacSize;
            result += 31 * MacEngine;

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
            if (!(Obj is CipherDescription))
                return false;

            CipherDescription other = (CipherDescription)Obj;

            if (EngineType != other.EngineType)
                return false;
            if (KeySize != other.KeySize)
                return false;
            if (IvSize != other.IvSize)
                return false;
            if (CipherType != other.CipherType)
                return false;
            if (PaddingType != other.PaddingType)
                return false;
            if (BlockSize != other.BlockSize)
                return false;
            if (RoundCount != other.RoundCount)
                return false;
            if (KdfEngine != other.KdfEngine)
                return false;
            if (MacSize != other.MacSize)
                return false;
            if (MacEngine != other.MacEngine)
                return false;

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
        public static bool operator ==(CipherDescription X, CipherDescription Y)
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
        public static bool operator !=(CipherDescription X, CipherDescription Y)
        {
            return !(X.Equals(Y));
        }
        #endregion
    }
    #endregion
}
