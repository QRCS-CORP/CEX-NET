using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;

namespace VTDev.Libraries.CEXEngine.Crypto.Helper
{
    /// <summary>
    /// Get a Block Cipher instance from it's enumeration name
    /// </summary>
    public static class BlockCipherFromName
    {
        /// <summary>
        /// Get a block cipher instance with default initialization parameters
        /// </summary>
        /// 
        /// <param name="BlockCipherType">The block cipher enumeration name</param>
        /// 
        /// <returns>An initialized block cipher</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the enumeration name is not supported</exception>
        public static IBlockCipher GetInstance(BlockCiphers BlockCipherType)
        {
            switch (BlockCipherType)
            {
                case BlockCiphers.RHX:
                    return new RHX();
                case BlockCiphers.SHX:
                    return new SHX();
                case BlockCiphers.THX:
                    return new THX();
                default:
                    throw new CryptoProcessingException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
            }
        }

        /// <summary>
        /// Get a block cipher instance with specified initialization parameters
        /// </summary>
        /// 
        /// <param name="BlockCipherType">The block cipher enumeration name</param>
        /// <param name="BlockSize">The cipher block size</param>
        /// <param name="RoundCount">The number of cipher rounds</param>
        /// <param name="KdfEngineType">The ciphers key expansion engine (default is SHA256)</param>
        /// 
        /// <returns>An initialized block cipher</returns>
        public static IBlockCipher GetInstance(BlockCiphers BlockCipherType, int BlockSize, int RoundCount, Digests KdfEngineType = Digests.None)
        {
            switch (BlockCipherType)
            {
                case BlockCiphers.RHX:
                    return new RHX(BlockSize, RoundCount, KdfEngineType);
                case BlockCiphers.SHX:
                    return new SHX(RoundCount, KdfEngineType);
                case BlockCiphers.THX:
                    return new THX(RoundCount, KdfEngineType);
                default:
                    throw new CryptoProcessingException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
            }
        }
    }
}
