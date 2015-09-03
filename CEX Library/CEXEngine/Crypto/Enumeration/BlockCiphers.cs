namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Block Ciphers
    /// </summary>
    public enum BlockCiphers : int
    {
        /// <summary>
        /// An extended implementation of the Rijndael Block Cipher
        /// </summary>
        RDX = 1,
        /// <summary>
        /// An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
        /// </summary>
        RHX = 2,
        /// <summary>
        /// An implementation based on the Rijndael and Serpent Merged Block Cipher
        /// </summary>
        RSM = 3,
        /// <summary>
        /// An extended implementation of the Serpent Block Cipher
        /// </summary>
        SPX = 4,
        /// <summary>
        /// The Serpent Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        SHX = 5,
        /// <summary>
        /// An extended implementation of the Twofish Block Cipher
        /// </summary>
        TFX = 6,
        /// <summary>
        /// A Twofish Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        THX = 7,
        /// <summary>
        /// An implementation based on the Twofish and Serpent Merged Block Ciphers, using an HKDF Key Schedule
        /// </summary>
        TSM = 8
    }
}
