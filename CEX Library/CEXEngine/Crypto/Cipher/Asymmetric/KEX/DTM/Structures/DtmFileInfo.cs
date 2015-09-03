#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures
{
    #region DtmFileInfo
    /// <summary>
    /// The DtmFileInfo structure.
    /// <para>The DtmFileInfo structure is a header that preceedes a file.</para>
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
    public struct DtmFileInfo
    {
        #region Public Fields
        /// <summary>
        /// The file name
        /// </summary>
        public string FileName;
        /// <summary>
        /// The total number of file bytes in the file
        /// </summary>
        public long FileSize;
        /// <summary>
        /// Flag used to identify the type of payload and options
        /// </summary>
        public long OptionsFlag;
        #endregion

        #region Constructor
        /// <summary>
        /// The DtmFileInfo primary constructor
        /// </summary>
        /// 
        /// <param name="FileName">The file name</param>
        /// <param name="FileSize">The total number of file bytes in the file</param>
        /// <param name="OptionsFlag">The total length of the stream</param>
        public DtmFileInfo(string FileName = "", long FileSize = 0, long OptionsFlag = 0)
        {
            this.FileName = FileName;
            this.FileSize = FileSize;
            this.OptionsFlag = OptionsFlag;
        }

        /// <summary>
        /// Constructs a DtmFileInfo from a byte array
        /// </summary>
        /// 
        /// <param name="FragmentArray">The byte array containing the DtmFileInfo structure</param>
        public DtmFileInfo(byte[] FragmentArray) :
            this(new MemoryStream(FragmentArray))
        {
        }

        /// <summary>
        /// Constructs a DtmIdentity from a stream
        /// </summary>
        /// 
        /// <param name="InfoStream">Stream containing a serialized DtmFileInfo</param>
        /// 
        /// <returns>A populated DtmFileInfo</returns>
        public DtmFileInfo(Stream InfoStream)
        {
            BinaryReader reader = new BinaryReader(InfoStream);
            int len = reader.ReadInt32();
            if (len > 0)
            {
                byte[] name = reader.ReadBytes(len);
                FileName = System.Text.Encoding.Unicode.GetString(name);
            }
            else
            {
                FileName = "";
            }
            FileSize = reader.ReadInt64();
            OptionsFlag = reader.ReadInt64();
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Deserialize an DtmFileInfo
        /// </summary>
        /// 
        /// <param name="InfoStream">Stream containing a serialized DtmFileInfo</param>
        /// 
        /// <returns>A populated DtmFileInfo</returns>
        public static DtmFileInfo DeSerialize(Stream InfoStream)
        {
            return new DtmFileInfo(InfoStream);
        }

        /// <summary>
        /// Serialize an DtmFileInfo structure
        /// </summary>
        /// 
        /// <param name="FileInfo">A DtmFileInfo structure</param>
        /// 
        /// <returns>A stream containing the DtmFileInfo data</returns>
        public static Stream Serialize(DtmFileInfo FileInfo)
        {
            return FileInfo.ToStream();
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
            FileName = "";
            FileSize = 0;
            OptionsFlag = 0;
        }
        /// <summary>
        /// Returns the DtmFileInfo as an encoded byte array
        /// </summary>
        /// 
        /// <returns>The serialized DtmFileInfo</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Returns the DtmFileInfo as an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The serialized DtmFileInfo</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            byte[] name = System.Text.Encoding.Unicode.GetBytes(FileName);
            writer.Write((int)name.Length);
            writer.Write(name);
            writer.Write((long)FileSize);
            writer.Write((long)OptionsFlag);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion
    }
    #endregion
}
