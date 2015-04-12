#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Structures
{
    #region KeyPackage
    /// <summary>
    /// The KeyPackage structure. 
    /// <para>Contains the KeyAuthority structure with identity and origin, attached policies, a description of the sub-key sets, 
    /// and the CipherDescription structure containing the description of the cipher.</para>
    /// <para>Used to create a key file that contains a series of Key, and optional Vector and Ikm sets. A key set; the keying material assigned to a subkey, is valid for
    /// only one cycle of encryption, guaranteeing that unique key material is used for every encryption cycle, but allowing for a key that can perform many
    /// encryptions while still exerting the maximum amount of security.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of populating a <c>KeyPackage</c> structure:</description>
    /// <code>
    ///    KeyPackage package = new KeyPackage(
    ///        keypol,      // a KeyAuthority structure containing originating identity, the master policy flag, and authentication info
    ///        cpdesc       // CipherDescription structure containing all of the settings used by the cipher instance
    ///        10);         // number of key sets contained in this package
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/03/12" version="1.3.2.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Helper.KeyFactory">VTDev.Libraries.CEXEngine.Crypto.Helper KeyFactory class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Structures.KeyPackage">VTDev.Libraries.CEXEngine.Crypto.Structures KeyPackage structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Structures.KeyAuthority">VTDev.Libraries.CEXEngine.Crypto.Structures KeyAuthority structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Structures.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Structures CipherDescription structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.KeyPolicies">VTDev.Libraries.CEXEngine.Crypto KeyPolicies Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.KeyStates">VTDev.Libraries.CEXEngine.Crypto KeyStates Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Process.CipherStream">VTDev.Libraries.CEXEngine.Crypto.Process CipherStream class</seealso>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct KeyPackage
    {
        #region Constants
        // adjust these constants to match container sizes
        private const int POLICY_SIZE = 8;
        private const int CREATE_SIZE = 8;
        private const int KEYAUT_SIZE = 144;
        private const int CIPHER_SIZE = 40;
        private const int EXTKEY_SIZE = 16;
        private const int KEYCNT_SIZE = 4;
        private const int KEYPOL_SIZE = 8;
        private const int KEYID_SIZE = 16;

        private const long POLICY_SEEK = 0;
        private const long CREATE_SEEK = POLICY_SIZE;
        private const long KEYAUT_SEEK = POLICY_SIZE + CREATE_SIZE;
        private const long CIPHER_SEEK = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE;
        private const long EXTKEY_SEEK = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + CIPHER_SIZE;
        private const long KEYCNT_SEEK = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + CIPHER_SIZE + EXTKEY_SIZE;
        private const long KEYPOL_SEEK = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + CIPHER_SIZE + EXTKEY_SIZE + KEYCNT_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The master key policy flags, used to determine encryption state
        /// </summary>
        public Int64 KeyPolicy;
        /// <summary>
        /// The creation date/time of this key in milliseconds
        /// </summary>
        public Int64 CreatedOn;
        /// <summary>
        /// The <see cref="KeyAuthority">KeyAuthority</see> structure containing the key authorization schema.
        /// </summary>
        [MarshalAs(UnmanagedType.Struct, SizeConst = KEYAUT_SIZE)]
        public KeyAuthority Authority;
        /// <summary>
        /// The <see cref="CipherDescription">CipherDescription</see> structure containing a complete description of the cipher instance.
        /// </summary>
        [MarshalAs(UnmanagedType.Struct, SizeConst = CIPHER_SIZE)]
        public CipherDescription Description;
        /// <summary>
        /// An array of random bytes used to encrypt a message file extension. A null value auto generates this field.
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = EXTKEY_SIZE)]
        public byte[] ExtensionKey;
        /// <summary>
        /// The number of Key Sets contained in this key package file.
        /// </summary>
        public Int32 SubKeyCount;
        /// <summary>
        /// A <see cref="SubKeyPolicy">KeyPolicy</see> array that contains the policy flags for each sub key set
        /// </summary>
        public Int64[] SubKeyPolicy;
        /// <summary>
        /// An array of unique 16 byte fields that identify each sub key set
        /// </summary>
        public byte[][] SubKeyID;
        #endregion

        #region Constructor
        /// <summary>
        /// A KeyPackage header structure. 
        /// </summary>
        /// 
        /// <param name="Authority">The <see cref="KeyAuthority">KeyAuthority</see> structure containing the key authorization schema.</param>
        /// <param name="Cipher">The <see cref="CipherDescription">CipherDescription</see> structure containing a complete description of the cipher instance.</param>
        /// <param name="SubKeyCount">The number of Key Sets contained in this key package file.</param>
        /// <param name="ExtensionKey">An array of random bytes used to encrypt a message file extension. A null value auto generates this field.</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid ExtensionKey is used</exception>
        public KeyPackage(KeyAuthority Authority, CipherDescription Cipher, int SubKeyCount, byte[] ExtensionKey = null)
        {
            this.KeyPolicy = Authority.KeyPolicy;
            this.Authority = Authority;
            this.Description = Cipher;
            this.SubKeyCount = SubKeyCount;
            SubKeyPolicy = new long[SubKeyCount];
            SubKeyID = new byte[SubKeyCount][];

            // generate the subkey ids and set master policy
            for (int i = 0; i < SubKeyCount; i++)
            {
                SubKeyPolicy[i] = (long)Authority.KeyPolicy;
                SubKeyID[i] = Guid.NewGuid().ToByteArray();
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

            CreatedOn = DateTime.Now.Ticks;
        }

        /// <summary>
        /// Reset all members of the KeyPackage structure, 
        /// including the CipherDescription and KeyAuthority structures
        /// </summary>
        public void Reset()
        {
            this.KeyPolicy = 0;
            this.CreatedOn = 0;
            this.Authority.Reset();
            this.Description.Reset();

            if (this.ExtensionKey != null)
            {
                Array.Clear(this.ExtensionKey, 0, this.ExtensionKey.Length);
                this.ExtensionKey = null;
            }

            this.SubKeyCount = 0;

            if (this.SubKeyPolicy != null)
            {
                Array.Clear(this.SubKeyPolicy, 0, this.SubKeyPolicy.Length);
                this.SubKeyPolicy = null;
            }

            if (this.SubKeyID != null)
            {
                for (int i = 0; i < this.SubKeyID.Length; i++)
                {
                    if (this.SubKeyID[i] != null)
                    {
                        Array.Clear(this.SubKeyID[i], 0, this.SubKeyID[i].Length);
                        this.SubKeyID[i] = null;
                    }
                }
                this.SubKeyID = null;
            }
        }

        /// <summary>
        /// Convert a string to a KeyPackage structure
        /// </summary>
        /// 
        /// <param name="Package">The string containing the KeyPackage</param>
        /// 
        /// <returns>A KeyPackage structuree</returns>
        public static KeyPackage FromString(string Package)
        {
            return DeSerialize(new MemoryStream(Encoding.ASCII.GetBytes(Package)));
        }

        /// <summary>
        /// Convert a KeyPackage to a string representation
        /// </summary>
        /// 
        /// <param name="Package">The KeyPackage</param>
        /// 
        /// <returns>An ASCII representation of the structure</returns>
        public static string ToString(KeyPackage Package)
        {
            return Encoding.ASCII.GetString(((MemoryStream)Serialize(Package)).ToArray());
        }
        #endregion

        #region Serialize
        /// <summary>
        /// Deserialize a <see cref="KeyPackage"/>
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing a serialized KeyPackage</param>
        /// 
        /// <returns>A populated KeyPackage</returns>
        public static KeyPackage DeSerialize(Stream KeyStream)
        {
            KeyStream.Seek(POLICY_SEEK, SeekOrigin.Begin);
            BinaryReader reader = new BinaryReader(KeyStream);
            KeyPackage kpg = new KeyPackage();

            kpg.KeyPolicy = reader.ReadInt64();
            kpg.CreatedOn = reader.ReadInt64();
            kpg.Authority = KeyAuthority.DeSerialize(new MemoryStream(reader.ReadBytes(KeyAuthority.GetHeaderSize())));
            kpg.Description = CipherDescription.DeSerialize(new MemoryStream(reader.ReadBytes(CipherDescription.GetHeaderSize())));
            kpg.ExtensionKey = reader.ReadBytes(EXTKEY_SIZE);
            kpg.SubKeyCount = reader.ReadInt32();
            kpg.SubKeyPolicy = new long[kpg.SubKeyCount];

            byte[] buffer = reader.ReadBytes(kpg.SubKeyCount * KEYPOL_SIZE);
            Buffer.BlockCopy(buffer, 0, kpg.SubKeyPolicy, 0, buffer.Length);

            buffer = reader.ReadBytes(kpg.SubKeyCount * KEYID_SIZE);
            kpg.SubKeyID = new byte[kpg.SubKeyCount][];

            for (int i = 0; i < kpg.SubKeyCount; i++)
            {
                kpg.SubKeyID[i] = new byte[KEYID_SIZE];
                Buffer.BlockCopy(buffer, i * KEYID_SIZE, kpg.SubKeyID[i], 0, KEYID_SIZE);
            }

            return kpg;
        }

        /// <summary>
        /// Serialize a <see cref="KeyPackage"/>
        /// </summary>
        /// 
        /// <param name="Package">A KeyPackage</param>
        /// 
        /// <returns>A stream containing the KeyPackage data</returns>
        public static Stream Serialize(KeyPackage Package)
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(Package.KeyPolicy);
            writer.Write(Package.CreatedOn);
            writer.Write(((MemoryStream)KeyAuthority.Serialize(Package.Authority)).ToArray());
            writer.Write(((MemoryStream)CipherDescription.Serialize(Package.Description)).ToArray());
            writer.Write(Package.ExtensionKey);
            writer.Write(Package.SubKeyCount);

            byte[] buffer = new byte[Package.SubKeyCount * KEYPOL_SIZE];
            Buffer.BlockCopy(Package.SubKeyPolicy, 0, buffer, 0, buffer.Length);
            writer.Write(buffer);

            buffer = new byte[Package.SubKeyCount * KEYID_SIZE];

            for (int i = 0; i < Package.SubKeyCount; i++)
                Buffer.BlockCopy(Package.SubKeyID[i], 0, buffer, i * KEYID_SIZE, KEYID_SIZE);

            writer.Write(buffer);

            return stream;
        }
        #endregion

        #region Getters
        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <param name="Package">The key package structure</param>
        /// 
        /// <returns>Header size</returns>
        public static int GetHeaderSize(KeyPackage Package)
        {
            return POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + CIPHER_SIZE + EXTKEY_SIZE + KEYCNT_SIZE + (Package.SubKeyCount * (KEYPOL_SIZE + KEYID_SIZE));
        }

        /// <summary>
        /// Get policy flag offset
        /// </summary>
        /// 
        /// <returns>offset size</returns>
        public static int GetPolicyOffset()
        {
            return POLICY_SIZE;
        }

        /// <summary>
        /// Get the key master policy flags
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Key policy flags</returns>
        public static long GetKeyPolicy(Stream KeyStream)
        {
            KeyStream.Seek(POLICY_SEEK, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadInt64();
        }

        /// <summary>
        /// Get the creation date/time timestamp (in milliseconds)
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Created on timestamp</returns>
        public static long GetCreatedOn(Stream KeyStream)
        {
            KeyStream.Seek(CREATE_SEEK, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadInt64();
        }

        /// <summary>
        /// Get the KeyAuthority structure
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a KeyAuthority structure</param>
        /// 
        /// <returns>KeyAuthority structure</returns>
        public static KeyAuthority GetKeyAuthority(Stream KeyStream)
        {
            KeyStream.Seek(KEYAUT_SEEK, SeekOrigin.Begin);
            return KeyAuthority.DeSerialize(new MemoryStream(new BinaryReader(KeyStream).ReadBytes(KeyAuthority.GetHeaderSize())));
        }

        /// <summary>
        /// Get the cipher description header
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>CipherDescription structure</returns>
        public static CipherDescription GetCipherDescription(Stream KeyStream)
        {
            KeyStream.Seek(CIPHER_SEEK, SeekOrigin.Begin);
            return CipherDescription.DeSerialize(new MemoryStream(new BinaryReader(KeyStream).ReadBytes(CipherDescription.GetHeaderSize())));
        }

        /// <summary>
        /// Get the extension key (16 bytes)
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>The file extension key</returns>
        public static byte[] GetExtensionKey(Stream KeyStream)
        {
            KeyStream.Seek(EXTKEY_SEEK, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadBytes(EXTKEY_SIZE);
        }

        /// <summary>
        /// Get the number of subkey sets contained in the key package
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Number of subkey sets</returns>
        public static int GetSubKeyCount(Stream KeyStream)
        {
            KeyStream.Seek(KEYCNT_SEEK, SeekOrigin.Begin);
            return new BinaryReader(KeyStream).ReadInt32();
        }

        /// <summary>
        /// Get the subkey policy flags contained in the key package
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Policy flag array</returns>
        public static long[] GetSubKeyPolicies(Stream KeyStream)
        {
            int count = GetSubKeyCount(KeyStream);
            KeyStream.Seek(KEYPOL_SEEK, SeekOrigin.Begin);
            byte[] buffer = new BinaryReader(KeyStream).ReadBytes(count * KEYPOL_SIZE);
            long[] policies = new long[count];
            Buffer.BlockCopy(buffer, 0, policies, 0, buffer.Length);

            return policies;
        }

        /// <summary>
        /// Get the subkey identity arrays
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Subkey id arrays</returns>
        public static byte[][] GetSubKeyIds(Stream KeyStream)
        {
            int skcnt = GetSubKeyCount(KeyStream);
            long idpos = KEYPOL_SEEK + (skcnt * KEYPOL_SIZE);
            KeyStream.Seek(idpos, SeekOrigin.Begin);

            byte[] buffer = new BinaryReader(KeyStream).ReadBytes(skcnt * KEYID_SIZE);
            byte[][] ids = new byte[skcnt][];

            for (int i = 0; i < skcnt; i++)
            {
                ids[i] = new byte[KEYID_SIZE];
                Buffer.BlockCopy(buffer, i * KEYID_SIZE, ids[i], 0, KEYID_SIZE);
            }
            return ids;
        }
        #endregion

        #region Setters
        /// <summary>
        /// Set the Key master policy flag
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Flags">Key policy flags</param>
        public static void SetKeyPolicy(Stream KeyStream, long Flags)
        {
            KeyStream.Seek(POLICY_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(Flags);
        }

        /// <summary>
        /// Set the Key package creation time
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="TimeStamp">Creation Date/Time in milliseconds</param>
        public static void SetCreatedOn(Stream KeyStream, long TimeStamp)
        {
            KeyStream.Seek(CREATE_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(TimeStamp);
        }

        /// <summary>
        /// Set the KeyAuthority structure
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Authority">The CipherDescription structure</param>
        public static void SetKeyAuthority(Stream KeyStream, KeyAuthority Authority)
        {
            KeyStream.Seek(KEYAUT_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(((MemoryStream)KeyAuthority.Serialize(Authority)).ToArray());
        }

        /// <summary>
        /// Set the CipherDescription structure
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Description">The CipherDescription structure</param>
        public static void SetCipherDescription(Stream KeyStream, CipherDescription Description)
        {
            KeyStream.Seek(CIPHER_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(((MemoryStream)CipherDescription.Serialize(Description)).ToArray());
        }

        /// <summary>
        /// Set the ExtensionKey
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="ExtensionKey">Array of 16 bytes containing the ExtensionKey</param>
        public static void SetExtensionKey(Stream KeyStream, byte[] ExtensionKey)
        {
            byte[] key = new byte[EXTKEY_SIZE];
            Array.Copy(ExtensionKey, 0, key, 0, ExtensionKey.Length < EXTKEY_SIZE ? ExtensionKey.Length : EXTKEY_SIZE);
            KeyStream.Seek(EXTKEY_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(key);
        }

        /// <summary>
        /// Set the Key package SubKey Count
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Count">Number of SubKeys in the package</param>
        public static void SetSubKeyCount(Stream KeyStream, int Count)
        {
            KeyStream.Seek(KEYCNT_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(Count);
        }

        /// <summary>
        /// Set the Key package SubKey Policy flags
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Policies">Array of SubKey policy flags</param>
        public static void SetSubKeyPolicies(Stream KeyStream, long[] Policies)
        {
            byte[] buffer = new byte[Policies.Length * KEYPOL_SIZE];
            Buffer.BlockCopy(Policies, 0, buffer, 0, buffer.Length);
            KeyStream.Seek(KEYPOL_SEEK, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(buffer);
        }

        /// <summary>
        /// Set the SubKeyId arrays
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="KeyIds">Array of SubKey Id arrays</param>
        public static void SetSubKeyIds(Stream KeyStream, byte[][] KeyIds)
        {
            int skcnt = GetSubKeyCount(KeyStream);
            byte[] buffer = new byte[skcnt * KEYID_SIZE];

            for (int i = 0; i < skcnt; i++)
                Buffer.BlockCopy(KeyIds[i], 0, buffer, i * KEYID_SIZE, KEYID_SIZE);

            long pos = KEYPOL_SEEK + (skcnt * KEYPOL_SIZE);
            KeyStream.Seek(pos, SeekOrigin.Begin);
            new BinaryWriter(KeyStream).Write(buffer);
        }
        #endregion

        #region Key Methods
        /// <summary>
        /// Clear all policy flags from the KeyPolicy at the specified Index
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package, changes are written to this stream</param>
        /// <param name="Index">Index of KeyPolicy within the KeyPolicies array</param>
        public static void SubKeyClearPolicies(Stream KeyStream, int Index)
        {
            long[] expol = GetSubKeyPolicies(KeyStream);

            if (Index > expol.Length - 1)
                throw new ArgumentOutOfRangeException("The specified index does not exist!");

            expol[Index] = 0;

            SetSubKeyPolicies(KeyStream, expol);
        }

        /// <summary>
        /// Clear the KeyPolicy flag from the KeyPolicy at the specified Index
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a KeyPackage, changes are written to this stream</param>
        /// <param name="Index">Index of KeyPolicy within the KeyPolicies array</param>
        /// <param name="KeyPolicy">KeyPolicy flag to clear</param>
        public static void SubKeyClearPolicy(Stream KeyStream, int Index, long KeyPolicy)
        {
            long[] expol = GetSubKeyPolicies(KeyStream);

            if (Index > expol.Length - 1)
                throw new ArgumentOutOfRangeException("The specified index does not exist!");

            if (KeyHasPolicy(expol[Index], KeyPolicy))
                expol[Index] &= ~KeyPolicy;

            SetSubKeyPolicies(KeyStream, expol);
        }

        /// <summary>
        /// Find a subkey index position within the stream
        /// </summary>
        /// <param name="KeyStream">The stream containing a KeyPackage structure</param>
        /// <param name="KeyId">The unique identifies of the sub key</param>
        /// 
        /// <returns>The index or -1 if the subkey was not found</returns>
        public static int SubKeyFind(Stream KeyStream, byte[] KeyId)
        {
            int index = -1;
            byte[][] keyIds = GetSubKeyIds(KeyStream);

            for (int i = 0; i < keyIds.Length; i++)
            {
                if (Compare.AreEqual(keyIds[i], KeyId))
                    return i;
            }

            return index;
        }

        /// <summary>
        /// Test if a specific KeyPolicy is within a policy group
        /// </summary>
        /// 
        /// <param name="PolicyGroup">Policies group as an integer</param>
        /// <param name="KeyPolicy">Policy to test for existence</param>
        /// 
        /// <returns>True if it contains the KeyPolicy</returns>
        public static bool KeyHasPolicy(long PolicyGroup, long KeyPolicy)
        {
            return ((PolicyGroup & (long)KeyPolicy) == (long)KeyPolicy);
        }

        /// <summary>
        /// Test if a specific KeyPolicy is within a policy group
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Index">Index of KeyPolicy within the KeyPolicies array</param>
        /// <param name="KeyPolicy">Policy to test for existence</param>
        /// 
        /// <returns>True if it contains the KeyPolicy</returns>
        public static bool SubKeyHasPolicy(Stream KeyStream, int Index, long KeyPolicy)
        {
            long[] expol = GetSubKeyPolicies(KeyStream);

            if (Index > expol.Length - 1)
                throw new ArgumentOutOfRangeException("The specified index does not exist!");

            return ((expol[Index] & (long)KeyPolicy) == (long)KeyPolicy);
        }

        /// <summary>
        /// Gets the next subkey available for encryption
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// 
        /// <returns>Index of subkey, or -1 for empty</returns>
        public static int SubKeyNextValid(Stream KeyStream)
        {
            int index = -1;
            long[] policies = GetSubKeyPolicies(KeyStream);

            for (int i = 0; i < policies.Length; i++)
            {
                if (!KeyHasPolicy(policies[i], (long)KeyStates.Expired))
                    return i;
            }

            return index;
        }

        /// <summary>
        /// Gdet the starting position of the key material (key/iv/mac key) of a specific subkey within the key package file
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="KeyId">The unique identifies of the sub key</param>
        /// 
        /// <returns>The starting position index of the key material</returns>
        public static long SubKeyOffset(Stream KeyStream, byte[] KeyId)
        {
            long keyPos = -1;
            int index = SubKeyFind(KeyStream, KeyId);

            if (index == -1)
                return keyPos;

            int keyCount = GetSubKeyCount(KeyStream);
            CipherDescription cipher = GetCipherDescription(KeyStream);
            int keySize = cipher.KeySize + cipher.IvSize + cipher.MacSize;
            int hdrSize = POLICY_SIZE + CREATE_SIZE + KEYAUT_SIZE + CIPHER_SIZE + EXTKEY_SIZE + KEYCNT_SIZE + (keyCount * (KEYPOL_SIZE + KEYID_SIZE));
            keyPos = hdrSize + (keySize * index);

            return keyPos;
        }

        /// <summary>
        /// Set a policy flag on a member of the KeyPolicies array
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing a key package</param>
        /// <param name="Index">Index of KeyPolicy within the KeyPolicies array</param>
        /// <param name="KeyPolicy">Policy flag to add to the KeyPolicy</param>
        public static void SubKeySetPolicy(Stream KeyStream, int Index, long KeyPolicy)
        {
            long[] expol = GetSubKeyPolicies(KeyStream);

            if (Index > expol.Length - 1)
                throw new ArgumentOutOfRangeException("The specified index does not exist!");

            if (!KeyHasPolicy(expol[Index], KeyPolicy))
            {
                expol[Index] |= KeyPolicy;
                SetSubKeyPolicies(KeyStream, expol);
            }
        }
        #endregion
    }
    #endregion
}
