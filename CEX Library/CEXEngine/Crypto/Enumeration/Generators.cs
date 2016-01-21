namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Random Generators
    /// </summary>
    public enum Generators : int
    {
        /// <summary>
        /// An implementation of a Encryption Counter based DRBG
        /// </summary>
        CTRDrbg = 1,
        /// <summary>
        /// An implementation of a Digest Counter based DRBG
        /// </summary>
        DGCDrbg = 2,
        /// <summary>
        /// A Hash based Key Derivation Function HKDF
        /// </summary>
        HKDF = 4,
        /// <summary>
        /// An implementation of a Hash based Key Derivation Function PBKDF2
        /// </summary>
        KDF2Drbg = 8,
        /// <summary>
        /// An implementation of a Hash based Key Derivation PKCS#5 Version 2
        /// </summary>
        PBKDF2 = 16,
        /// <summary>
        /// An implementation of a Salsa20 Counter based DRBG
        /// </summary>
        SP20Drbg = 32,
    }
}
