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
        Request = 71,
        /// <summary>
        /// The transfer request was refused
        /// </summary>
        Refused = 72,
        /// <summary>
        /// Packet contains transmission data
        /// </summary>
        DataChunk = 73,
        /// <summary>
        /// The transfer receive operation has completed
        /// </summary>
        Received = 74,
        /// <summary>
        /// The transfer send operation has completed
        /// </summary>
        Sent = 75
    }
}
