namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages
{
    /// <summary>
    /// The flag indicating the severity of an error condition
    /// </summary>
    public enum DtmErrorSeverity : short
    {
        /// <summary>
        /// An information message
        /// </summary>
        Information = 1,
        /// <summary>
        /// An error has been handled
        /// </summary>
        Warning = 2,
        /// <summary>
        /// The network connection has experienced an error
        /// </summary>
        Connection = 3,
        /// <summary>
        /// Data has been lost, but might be recovered
        /// </summary>
        DataLoss = 4,
        /// <summary>
        /// A critical error has occured, haltin operations
        /// </summary>
        Critical = 5
    }
}
