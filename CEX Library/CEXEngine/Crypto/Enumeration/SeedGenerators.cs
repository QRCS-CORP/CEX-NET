namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Seed Generators
    /// </summary>
    public enum SeedGenerators : int
    {
        /// <summary>
        /// A Secure Seed Generator using the RNGCryptoServiceProvider api
        /// </summary>
        CSPRsg = 1,
        /// <summary>
        /// A Secure Seed Generator using the ISAAC generator
        /// </summary>
        ISCRsg = 2,
        /// <summary>
        /// A Seed Generator using the XorShift+ generator
        /// </summary>
        XSPRsg = 4
    }
}
