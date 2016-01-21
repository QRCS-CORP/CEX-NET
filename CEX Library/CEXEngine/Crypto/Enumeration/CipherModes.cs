namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Cipher Modes
    /// </summary>
    public enum CipherModes : int
    {
        /// <summary>
        /// Electronic CodeBook Mode (not secure, testing only)
        /// </summary>
        ECB = 0,
        /// <summary>
        /// Cipher Block Chaining Mode
        /// </summary>
        CBC = 1,
        /// <summary>
        /// Cipher FeedBack Mode
        /// </summary>
        CFB = 2,
        /// <summary>
        /// SIC Counter Mode
        /// </summary>
        CTR = 4,
        /// <summary>
        /// Output FeedBack Mode
        /// </summary>
        OFB = 8
    }
}
