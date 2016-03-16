namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Message Digests
    /// </summary>
    public enum Digests : int
    {
        /// <summary>
        /// The Blake digest with a 256 bit return size
        /// </summary>
        Blake256 = 0,
        /// <summary>
        /// The Blake digest with a 512 bit return size
        /// </summary>
        Blake512 = 1,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 256 bit return size
        /// </summary>
        Keccak256 = 2,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 512 bit return size
        /// </summary>
        Keccak512 = 4,
        /// <summary>
        ///The SHA-2 digest with a 256 bit return size
        /// </summary>
        SHA256 = 8,
        /// <summary>
        /// The SHA-2 digest with a 512 bit return size
        /// </summary>
        SHA512 = 16,
        /// <summary>
        /// The Skein digest with a 256 bit return size
        /// </summary>
        Skein256 = 32,
        /// <summary>
        /// The Skein digest with a 512 bit return size
        /// </summary>
        Skein512 = 64,
        /// <summary>
        /// The Skein digest with a 1024 bit return size
        /// </summary>
        Skein1024 = 128
    }
}
