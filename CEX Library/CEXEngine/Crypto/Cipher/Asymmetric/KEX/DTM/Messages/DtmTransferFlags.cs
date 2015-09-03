namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages
{
    /// <summary>
    /// The flag indicating the state of a transfer operation
    /// </summary>
    public enum DtmTransferFlags : short
    {
        /// <summary>
        /// Packet contains a transfer request
        /// </summary>
        Request = 41,
        /// <summary>
        /// The transfer request was refused
        /// </summary>
        Refused = 42,
        /// <summary>
        /// Packet contains transmission data
        /// </summary>
        DataChunk = 43,
        /// <summary>
        /// The transfer receive operation has completed
        /// </summary>
        Received = 44,
        /// <summary>
        /// The transfer send operation has completed
        /// </summary>
        Sent = 45
    }
}
