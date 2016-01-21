namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Message Authentication Code Generators
    /// </summary>
    public enum Macs : int
    {
        /// <summary>
        /// A Cipher based Message Authentication Code wrapper (CMAC)
        /// </summary>
        CMAC = 1,
        /// <summary>
        /// A Hash based Message Authentication Code wrapper (HMAC)
        /// </summary>
        HMAC = 2,
        /// <summary>
        /// A Variably Modified Permutation Composition based Message Authentication Code (VMAC)
        /// </summary>
        VMAC = 4
    }
}
