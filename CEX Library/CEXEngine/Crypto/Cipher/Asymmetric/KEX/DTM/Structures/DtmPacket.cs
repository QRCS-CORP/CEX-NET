#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures
{
    #region DtmPacket
    /// <summary>
    /// The DTM Packet structure.
    /// The primary packet header used in a DTM key exchange; used to classify and describe the message content.
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmClient">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmClient structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmIdentity">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmIdentity structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmSession">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmSession structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM DtmParameters class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmKex">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM DtmKex class</seealso>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/06/14" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct DtmPacket
    {
        #region Constants
        private const int MSGTPE_SIZE = 1;
        private const int PAYLEN_SIZE = 8;
        private const int SEQNUM_SIZE = 8;
        private const int PKTFLG_SIZE = 1;
        private const int OPTFLG_SIZE = 8;
        private const int HDR_SIZE = MSGTPE_SIZE + PAYLEN_SIZE + SEQNUM_SIZE + PKTFLG_SIZE + OPTFLG_SIZE;
        #endregion

        #region Public Fields
        /// <summary>
        /// The <see cref="DtmPacketTypes"/> message type; describes the packet classification
        /// </summary>
        public DtmPacketTypes PacketType;
        /// <summary>
        /// The length of the payload contained in the packet
        /// </summary>
        public long PayloadLength;
        /// <summary>
        /// The packet sequence number
        /// </summary>
        public long Sequence;
        /// <summary>
        /// The <see cref="DtmServiceFlags"/> exchange state; indicates the exchange state position
        /// </summary>
        public short PacketFlag;
        /// <summary>
        /// The packet header option flag
        /// </summary>
        public long OptionFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// CTKEPacket primary constructor
        /// </summary>
        /// 
        /// <param name="PacketType">The <see cref="DtmPacketTypes"/> message type; describes the packet classification</param>
        /// <param name="PayloadLength">The length of the payload contained in the packet</param>
        /// <param name="Sequence">The packet sequence number</param>
        /// <param name="Sequence">The <see cref="DtmServiceFlags"/> exchange state; indicates the exchange state position</param>
        /// <param name="OptionFlag">The packet header option flag</param>
        public DtmPacket(DtmPacketTypes PacketType, long PayloadLength, long Sequence, short PacketFlag, long OptionFlag = 0)
        {
            this.PacketType = PacketType;
            this.PayloadLength = PayloadLength;
            this.Sequence = Sequence;
            this.PacketFlag = PacketFlag;
            this.OptionFlag = OptionFlag;
        }

        /// <summary>
        /// Extracts a DtmPacket from a byte array
        /// </summary>
        /// 
        /// <param name="PacketArray">The byte array containing the DtmPacket structure</param>
        public DtmPacket(byte[] PacketArray) :
            this(new MemoryStream(PacketArray))
        {
        }

        /// <summary>
        /// Extracts a DtmPacket from a Stream
        /// </summary>
        /// 
        /// <param name="PacketStream">The Stream containing the DtmPacket structure</param>
        public DtmPacket(Stream PacketStream)
        {
            BinaryReader reader = new BinaryReader(PacketStream);
            PacketType = (DtmPacketTypes)reader.ReadByte();
            PayloadLength = reader.ReadInt64();
            Sequence = reader.ReadInt64();
            PacketFlag = (short)reader.ReadByte();
            OptionFlag = reader.ReadInt64();
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Returns the DtmPacket as a byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmPacket</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmPacket as a MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmPacket</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write((byte)PacketType);
            writer.Write((long)PayloadLength);
            writer.Write((long)Sequence);
            writer.Write((byte)PacketFlag);
            writer.Write((long)OptionFlag);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }

        /// <summary>
        /// Deserialize a <see cref="DtmPacket"/>
        /// </summary>
        /// 
        /// <param name="PacketStream">Stream containing a serialized CTKEPacket</param>
        /// 
        /// <returns>A populated CTKEPacket</returns>
        public static DtmPacket DeSerialize(Stream PacketStream)
        {
            return new DtmPacket(PacketStream);
        }

        /// <summary>
        /// Serialize a <see cref="DtmPacket"/> structure
        /// </summary>
        /// 
        /// <param name="Packet">A CTKEPacket structure</param>
        /// 
        /// <returns>A stream containing the CTKEPacket data</returns>
        public static Stream Serialize(DtmPacket Packet)
        {
            return Packet.ToStream();
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
        /// Reset all struct members
        /// </summary>
        public void Reset()
        {
            PacketType = 0;
            PayloadLength = 0;
            Sequence = 0;
            PacketFlag = 0;
            OptionFlag = 0;
        }
        #endregion
    }
    #endregion
}
