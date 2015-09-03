namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Block Cipher Padding Modes
    /// </summary>
    public enum PaddingModes : int
    {
        /// <summary>
        /// ISO7816 Padding Mode
        /// </summary>
        ISO7816 = 0,
        /// <summary>
        /// PKCS7 Padding Mode
        /// </summary>
        PKCS7,
        /// <summary>
        /// Trailing Bit Complement Padding Mode
        /// </summary>
        TBC,
        /// <summary>
        /// X923 Padding Mode
        /// </summary>
        X923
    }
}
