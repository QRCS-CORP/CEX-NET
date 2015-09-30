namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages
{
    /// <summary>
    /// For future use in an Auth-Stage encryption scheme
    /// </summary>
    public enum DtmTrustStates : short
    {
        /// <summary>
        /// No trust relationship exists
        /// </summary>
        None = 81,
        /// <summary>
        /// A partial trust has been established
        /// </summary>
        Partial = 82,
        /// <summary>
        /// Full trust has been established
        /// </summary>
        Full = 83
    }
}
