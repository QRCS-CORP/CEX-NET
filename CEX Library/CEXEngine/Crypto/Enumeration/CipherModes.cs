namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Cipher Modes
    /// </summary>
    public enum CipherModes : int
    {
        /// <summary>
        /// Cipher Block Chaining Mode
        /// </summary>
        CBC = 0,
        /// <summary>
        /// Cipher FeedBack Mode
        /// </summary>
        CFB,
        /// <summary>
        /// SIC Counter Mode
        /// </summary>
        CTR,
        /*/// <summary> // test only
        /// Electronic CodeBook Mode
        /// </summary>
        ECB,*/
        /// <summary>
        /// Output FeedBack Mode
        /// </summary>
        OFB
    }
}
