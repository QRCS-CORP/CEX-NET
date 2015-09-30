namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages
{
    /// <summary>
    /// The flag indicating the type of service request
    /// </summary>
    public enum DtmErrorFlags : short
    {
        /// <summary>
        /// Connection was dropped
        /// </summary>
        ConnectionDropped = 1,
        /// <summary>
        /// The client refused the connection
        /// </summary>
        ConnectionRefused = 2, 
        /// <summary>
        /// The connection terminated normally
        /// </summary>
        ConnectionTerminated = 3,
        /// <summary>
        /// The connection timed out
        /// </summary>
        ConnectionTimedOut = 4,
        /// <summary>
        /// The host had an unexpected error
        /// </summary>
        InternalError = 4,
        /// <summary>
        /// The maximum number of retransmission attempts for the session was exceeded
        /// </summary>
        MaxResendExceeded = 6,
        /// <summary>
        /// Unspecified network error
        /// </summary>
        NetworkError = 7,
        /// <summary>
        /// The session received bad data and can not recover
        /// </summary>
        ReceivedBadData = 8,
        /// <summary>
        /// Transmission could not be sent in a timely manner
        /// </summary>
        SendTimeoutExceeded = 9,
        /// <summary>
        /// Session encountered unrecoverable data loss
        /// </summary>
        UnrecoverableDataLoss = 10,
    }
}
