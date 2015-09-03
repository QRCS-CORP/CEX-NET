#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures
{
    #region DtmMessage
    /// <summary>
    /// The DtmMessage structure.
    /// <para>The DtmMessage structure is a header that encapsulates encrypted messages; it contains describe the payload and padding.</para>
    /// </summary>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM DtmParameters class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmClient">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmClient structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmIdentity">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmIdentity structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmPacket">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmPacket structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmSession">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmSession structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmKex">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM DtmKex class</seealso>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/05/23" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    public struct DtmMessage
    {
        #region Public Fields
        /// <summary>
        /// The maximum number of pseudo-random bytes to append to a message before encryption
        /// </summary>
        public int MessageAppend;
        /// <summary>
        /// The maximum number of pseudo-random bytes to prepend to a message before encryption
        /// </summary>
        public int MessagePrePend;
        /// <summary>
        /// Flag used to identify the type of payload and options
        /// </summary>
        public long OptionsFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// The DtmMessage primary constructor
        /// </summary>
        /// 
        /// <param name="MessageAppend">The number of pseudo-random bytes to append to a message before encryption</param>
        /// <param name="MessagePrePend">The number of pseudo-random bytes to prepend to a message before encryption</param>
        /// <param name="OptionsFlag">Flag used to identify the type of payload and options</param>
        public DtmMessage(int MessageAppend = 0, int MessagePrePend = 0, long OptionsFlag = 0)
        {
            this.MessageAppend = MessageAppend;
            this.MessagePrePend = MessagePrePend;
            this.OptionsFlag = OptionsFlag;
        }

        /// <summary>
        /// Constructs a DtmMessage from a byte array
        /// </summary>
        /// 
        /// <param name="MessageArray">The byte array containing the DtmMessage structure</param>
        public DtmMessage(byte[] MessageArray) :
            this(new MemoryStream(MessageArray))
        {
        }

        /// <summary>
        /// Constructs a DtmIdentity from a stream
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a serialized DtmMessage</param>
        /// 
        /// <returns>A populated DtmMessage</returns>
        public DtmMessage(Stream MessageStream)
        {
            BinaryReader reader = new BinaryReader(MessageStream);
            MessageAppend = reader.ReadInt32();
            MessagePrePend = reader.ReadInt32();
            OptionsFlag = reader.ReadInt64();
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Deserialize an DtmMessage
        /// </summary>
        /// 
        /// <param name="MessageStream">Stream containing a serialized DtmMessage</param>
        /// 
        /// <returns>A populated DtmMessage</returns>
        public static DtmMessage DeSerialize(Stream MessageStream)
        {
            return new DtmMessage(MessageStream);
        }

        /// <summary>
        /// Serialize an DtmMessage structure
        /// </summary>
        /// 
        /// <param name="Message">A DtmMessage structure</param>
        /// 
        /// <returns>A stream containing the DtmMessage data</returns>
        public static Stream Serialize(DtmMessage Message)
        {
            return Message.ToStream();
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
            MessageAppend = 0;
            MessagePrePend = 0;
            OptionsFlag = 0;
        }
        /// <summary>
        /// Returns the DtmMessage as an encoded byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmMessage</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmMessage as an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmMessage</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write((int)MessageAppend);
            writer.Write((int)MessagePrePend);
            writer.Write((long)OptionsFlag);

            return stream;
        }
        #endregion
    }
    #endregion
}
