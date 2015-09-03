namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages
{
    /// <summary>
    /// The flag indicating the type of service request
    /// </summary>
    public enum DtmErrorFlags : short
    {
        /// <summary>
        /// The host had an unexpected error
        /// </summary>
        InternalError = 81,
        /// <summary>
        /// The client refused the connection
        /// </summary>
        ConnectionRefused = 82, 
        /// <summary>
        /// Connection was dropped
        /// </summary>
        ConnectionDropped = 83,
        /// <summary>
        /// The connection timed out
        /// </summary>
        ConnectionTimedOut = 84,
        /// <summary>
        /// Session encountered unrecoverable data loss
        /// </summary>
        UnrecoverableDataLoss = 85,
        /// <summary>
        /// The maximum number of retransmission attempts for the session was exceeded
        /// </summary>
        MaxResendExceeded = 86,
        /// <summary>
        /// Unspecified network error
        /// </summary>
        NetworkError = 87,
        /// <summary>
        /// Transmission could not be sent in a timely manner
        /// </summary>
        SendTimeoutExceeded = 88,
        /// <summary>
        /// The session received bad data and can not recover
        /// </summary>
        ReceivedBadData = 89
    }
}
