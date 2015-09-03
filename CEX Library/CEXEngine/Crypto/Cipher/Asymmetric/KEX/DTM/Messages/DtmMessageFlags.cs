namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages
{
    /// <summary>
    /// The flag indicating the state of a transfer operation
    /// </summary>
    public enum DtmMessageFlags : short
    {
        /// <summary>
        /// The payload is a post-exchange encrypted datagram
        /// </summary>
        Transmission = 61,
    }
}
