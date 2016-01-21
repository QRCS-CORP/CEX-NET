namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Pseudo Random Generators
    /// </summary>
    public enum Prngs : int
    {
        /// <summary>
        ///  A Secure PRNG using RNGCryptoServiceProvider
        /// </summary>
        CSPPrng = 0,
        /// <summary>
        /// A Blum-Blum-Shub random number generator
        /// </summary>
        BBSG = 1,
        /// <summary>
        /// A Cubic Congruential Generator II (CCG) random number generator
        /// </summary>
        CCG = 2,
        /// <summary>
        /// A Symmetric Cipher Counter mode random number generator
        /// </summary>
        CTRPrng = 4,
        /// <summary>
        /// A Digest Counter mode random number generator
        /// </summary>
        DGCPrng = 8,
        /// <summary>
        /// A Modular Exponentiation Generator (MODEXPG) random number generator
        /// </summary>
        MODEXPG = 16,
        /// <summary>
        /// An implementation of a passphrase based PKCS#5 random number generator
        /// </summary>
        PBPrng = 32,
        /// <summary>
        /// A Quadratic Congruential Generator I (QCG-I) random number generator
        /// </summary>
        QCG1 = 64,
        /// <summary>
        /// A Quadratic Congruential Generator II (QCG-II) random number generator
        /// </summary>
        QCG2 = 128,
        /// <summary>
        /// An implementation of a Salsa20 Counter based Prng
        /// </summary>
        SP20Prng = 256,
    }
}
