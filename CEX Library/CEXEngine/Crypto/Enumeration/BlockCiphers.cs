namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Block Ciphers
    /// </summary>
    public enum BlockCiphers : int
    {
        /// <summary>
        /// An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
        /// </summary>
        RHX = 1,
        /// <summary>
        /// The Serpent Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        SHX = 2,
        /// <summary>
        /// A Twofish Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        THX = 4,
    }
}
