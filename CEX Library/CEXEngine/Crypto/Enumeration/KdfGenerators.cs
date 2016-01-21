namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Random Generator Digest KDFs
    /// </summary>
    public enum KdfGenerators : int
    {
        /// <summary>
        /// An implementation of a Digest Counter based DRBG
        /// </summary>
        DGCDRBG = 2,
        /// <summary>
        /// A Hash based Key Derivation Function HKDF
        /// </summary>
        HKDF = 4,
        /// <summary>
        /// An implementation of the Hash based KDF KDF2 DRBG
        /// </summary>
        KDF2 = 8,
        /// <summary>
        /// An implementation of PBKDF2 Version 2
        /// </summary>
        PBKDF2 = 16
    }
}
