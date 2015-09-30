namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages
{
    /// <summary>
    /// The flag indicating the type of service request
    /// </summary>
    public enum DtmServiceFlags : short
    {
        /// <summary>
        /// An internal error has occured
        /// </summary>
        Internal = 61,
        /// <summary>
        /// The host refused the connection
        /// </summary>
        Refusal = 62,
        /// <summary>
        /// The host was disconnected from the session
        /// </summary>
        Disconnected = 63,
        /// <summary>
        /// The host requires a re-transmission of the data
        /// </summary>
        Resend = 64,
        /// <summary>
        /// The host received data that was out of sequence
        /// </summary>
        OutOfSequence = 65,
        /// <summary>
        /// The data can not be recovered, attempt a resync
        /// </summary>
        DataLost = 66,
        /// <summary>
        /// Tear down the connection
        /// </summary>
        Terminate = 67,
        /// <summary>
        /// Response to a data lost messagem attempt to resync crypto stream
        /// </summary>
        Resync = 68,
        /// <summary>
        /// The response is an echo
        /// </summary>
        Echo = 69,
        /// <summary>
        /// The message is a keep alive
        /// </summary>
        KeepAlive = 80
    }
}
