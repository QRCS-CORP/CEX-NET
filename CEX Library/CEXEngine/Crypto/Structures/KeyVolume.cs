#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Structures
{
    /// <summary>
    /// The KeyVolume structure. 
    /// <para>This structure is used for the encryption of a series of sequential files with a single key, like a directory or onlne volume.
    /// Using CTR or CBC cippher modes, the IV can be recorded into an array at its last state after a file encryption.
    /// This IV can then be added to the Vectors array, used as the starting Vector for the next file encryption.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of populating a <c>KeyVolume</c> structure:</description>
    /// <code>
    /// private KeyVolume _keyVol = new KeyVolume(tag, key, 16);
    /// ...
    /// using (CTR cipher = new CTR(new RDX()))
    /// {
    ///     keyVol.Initialize(true, new KeyParams (Key, iv));
    ///
    ///     // encrypt the file
    ///     ...
    ///     // add the iv in it's last state as start vector for the next file
    ///     _keyVol.Add(cipher.IV);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/03/12" version="1.3.5.0">Initial release</revision>
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
    public struct KeyVolume
    {
        #region Constants
        private const int TAG_SIZE = 32;
        private const int TAG_SEEK = 0;
        #endregion

        #region Public Fields
        /// <summary>
        /// The volume tag; a 32 byte field identifying this volume
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = TAG_SIZE)]
        public byte[] Tag;
        /// <summary>
        /// The number of vectors in this container
        /// </summary>
        public Int32 KeySize;
        /// <summary>
        /// The length of a single vector in bytes
        /// </summary>
        public Int32 VectorSize;
        /// <summary>
        /// The number of vectors in this container
        /// </summary>
        public Int32 Count;
        /// <summary>
        /// The encryption key
        /// </summary>
        public byte[] Key;
        /// <summary>
        /// A concurrently aligned series of vectors
        /// </summary>
        public byte[] Vectors;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize an empty KeyVolume structure
        /// </summary>
        /// 
        /// <param name="Tag">The volume tag; a 32 byte field identifying this volume</param>
        /// <param name="Key">The encryption key</param>
        /// <param name="VectorSize">The length of a single vector in bytes</param>
        public KeyVolume(byte[] Tag, byte[] Key, int VectorSize)
        {
            this.Tag = new byte[TAG_SIZE];
            Array.Copy(Tag, this.Tag, Math.Min(Tag.Length, TAG_SIZE));
            this.KeySize = Key.Length;
            this.VectorSize = VectorSize;
            this.Count = 0;
            this.Key = Key;
            this.Vectors = new byte[0];
        }

        /// <summary>
        /// Initialize the KeyVolume structure with vectors
        /// </summary>
        /// 
        /// <param name="Tag">The volume tag; a 32 byte field identifying this volume</param>
        /// <param name="Key">The encryption key</param>
        /// <param name="VectorSize">The length of a single vector in bytes</param>
        /// <param name="Vectors">A concurrently aligned series of vectors</param>
        public KeyVolume(byte[] Tag, byte[] Key, int VectorSize, byte[] Vectors)
        {
            this.Tag = new byte[TAG_SIZE];
            Array.Copy(Tag, this.Tag, Math.Min(Tag.Length, TAG_SIZE));
            this.KeySize = Key.Length;
            this.VectorSize = VectorSize;
            this.Count = Vectors.Length / VectorSize;
            this.Key = Key;
            this.Vectors = Vectors;
        }
        #endregion

        #region Serialize
        /// <summary>
        /// Deserialize a <see cref="KeyVolume"/>
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing a serialized KeyVolume</param>
        /// 
        /// <returns>A populated KeyVolume</returns>
        public static KeyVolume DeSerialize(Stream KeyStream)
        {
            KeyStream.Seek(0, SeekOrigin.Begin);
            BinaryReader reader = new BinaryReader(KeyStream);
            KeyVolume kvl = new KeyVolume();

            kvl.Tag = reader.ReadBytes(TAG_SIZE);
            kvl.KeySize = reader.ReadInt32();
            kvl.VectorSize = reader.ReadInt32();
            kvl.Count = reader.ReadInt32();
            kvl.Key = reader.ReadBytes(kvl.KeySize);
            kvl.Vectors = reader.ReadBytes(kvl.VectorSize * kvl.Count);

            return kvl;
        }

        /// <summary>
        /// Serialize a <see cref="KeyVolume"/>
        /// </summary>
        /// 
        /// <param name="Volume">A KeyVolume</param>
        /// 
        /// <returns>A stream containing the KeyVolume data</returns>
        public static Stream Serialize(KeyVolume Volume)
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(Volume.Tag);
            writer.Write(Volume.KeySize);
            writer.Write(Volume.VectorSize);
            writer.Write(Volume.Count);
            writer.Write(Volume.Key);
            writer.Write(Volume.Vectors);

            return stream;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Add a vector
        /// </summary>
        /// 
        /// <param name="Vector">The vector to add</param>
        public void Add(byte[] Vector)
        {
            int len = Vectors.Length;
            Array.Resize<byte>(ref Vectors, len + VectorSize);
            Buffer.BlockCopy(Vector, 0, Vectors, len, VectorSize);
        }

        /// <summary>
        /// Get the vector at a given index
        /// </summary>
        /// 
        /// <param name="Index">The index value</param>
        /// 
        /// <returns>The vector</returns>
        public byte[] AtIndex(int Index)
        {
            int offset = Index * VectorSize;
            byte[] ret = new byte[VectorSize];
            Buffer.BlockCopy(Vectors, offset, ret, 0, VectorSize);

            return ret;
        }
        #endregion
    }
}
