#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages
{
    /// <summary>
    /// The <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmPacket"/> primary message types.
    /// </summary>
    public enum DtmPacketTypes : int
    {
        /// <summary>
        /// The packet contains a service instruction
        /// </summary>
        Service = 1,
        /// <summary>
        /// The packet contains message data
        /// </summary>
        Message = 2,
        /// <summary>
        /// The packet contains file transfer information
        /// </summary>
        Transfer = 3,
        /// <summary>
        /// The packet is part of a key exchange
        /// </summary>
        Exchange = 4
    }
}
