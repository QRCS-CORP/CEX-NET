#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures
{
    #region DtmClient
    /// <summary>
    /// The DtmClient structure.
    /// <para>The DtmClient structure is used to store data that uniquely identifies the host.</para>
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM DtmParameters class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmIdentity">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmIdentity structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmPacket">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmPacket structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmSession">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmSession structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmKex">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM DtmKex class</seealso>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/05/23" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <para>The PublicId field is a byte array used as a unique id, presented to other operators as a host identifier 
    /// during the <c>Auth-Stage</c> of the key exchange.
    /// The SecretId is a byte array that can be a serialized object like a key, or code, and is used to identify 
    /// the host during the <c>Primary-Stage</c> of the key exchange.</para>
    /// </remarks>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct DtmClient
    {
        #region Public Fields
        /// <summary>
        /// The <c>Auth-Stage</c> Public Identity field
        /// </summary>
        public byte[] PublicId;
        /// <summary>
        /// The <c>Primary-Stage</c> Secret Identity field
        /// </summary>
        public byte[] SecretId;
        /// <summary>
        /// The options flag; can be used as additional information about the client structure
        /// </summary>
        public long OptionsFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// The DtmClient primary constructor
        /// </summary>
        /// 
        /// <param name="PublicId">The <c>Auth-Stage</c> Public Identity</param>
        /// <param name="SecretId">The <c>Primary-Stage</c> Secret Identity</param>
        /// <param name="OptionsFlag">A flag used for additional information</param>
        public DtmClient(byte[] PublicId, byte[] SecretId, long OptionsFlag = 0)
        {
            this.PublicId = new byte[PublicId.Length];
            Array.Copy(PublicId, this.PublicId, PublicId.Length);
            this.SecretId = new byte[SecretId.Length];
            Array.Copy(SecretId, this.SecretId, SecretId.Length);
            this.OptionsFlag = OptionsFlag;
        }
        
        /// <summary>
        /// Extracts a DtmClient from a byte array
        /// </summary>
        /// 
        /// <param name="ClientArray">The byte array containing the DtmClient structure</param>
        public DtmClient(byte[] ClientArray) :
            this(new MemoryStream(ClientArray))
        {
        }

        /// <summary>
        /// Constructs a DtmClient from a stream
        /// </summary>
        /// 
        /// <param name="ClientStream">Stream containing a serialized DtmClient</param>
        /// 
        /// <returns>A populated DtmClient</returns>
        public DtmClient(Stream ClientStream)
        {
            BinaryReader reader = new BinaryReader(ClientStream);
            int len = reader.ReadInt32();
            PublicId = reader.ReadBytes(len);
            len = reader.ReadInt32();
            SecretId = reader.ReadBytes(len);
            OptionsFlag = reader.ReadInt64();
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Deserialize an DtmClient
        /// </summary>
        /// 
        /// <param name="ClientStream">Stream containing a serialized DtmClient</param>
        /// 
        /// <returns>A populated DtmClient</returns>
        public static DtmClient DeSerialize(Stream ClientStream)
        {
            return new DtmClient(ClientStream);
        }

        /// <summary>
        /// Serialize an DtmClient structure
        /// </summary>
        /// 
        /// <param name="Client">A DtmClient structure</param>
        /// 
        /// <returns>A stream containing the DtmClient data</returns>
        public static Stream Serialize(DtmClient Client)
        {
            return Client.ToStream();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the header Size in bytes
        /// </summary>
        /// 
        /// <returns>Header size</returns>
        public int GetHeaderSize()
        {
            return (int)Serialize(this).Length;
        }
        /// <summary>
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            OptionsFlag = 0;
            Array.Clear(PublicId, 0, PublicId.Length);
            Array.Clear(SecretId, 0, SecretId.Length);
        }

        /// <summary>
        /// Returns the DtmClient as an encoded byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmClient</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmClient as an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmClient</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write((int)PublicId.Length);
            writer.Write(PublicId);
            writer.Write((int)SecretId.Length);
            writer.Write(SecretId);
            writer.Write((long)OptionsFlag);

            return stream;
        }
        #endregion
    }
    #endregion
}
