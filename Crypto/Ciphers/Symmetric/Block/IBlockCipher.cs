using System;

namespace VTDev.Libraries.CEXEngine.Crypto.Ciphers
{
    /// <summary>
    /// Block Cipher Interface
    /// </summary>
    public interface IBlockCipher : IDisposable
    {
        /// <summary>
        /// Unit block size of internal cipher.
        /// </summary>
        int BlockSize { get; set; }

        /// <summary>
        /// Used as encryptor, false for decryption. 
        /// Value set in the Init() call.
        /// </summary>
        bool IsEncryption { get; }

        /// <summary>
        /// Key has been expanded
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Cipher name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Decrypt a single block of bytes.
        /// Init must be called with the IsEncrypted flag set to false before this method can be used.
        /// Input and Output must be at least BlockSize in length.
        /// </summary>
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        void DecryptBlock(byte[] Input, byte[] Output);

        /// <summary>
        /// Decrypt a block of bytes within an array.
        /// Init must be called with the IsEncrypted flag set to false before this method can be used.
        /// Input and Output + Offsets must be at least BlockSize in length.
        /// </summary>
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset);

        /// <summary>
        /// Encrypt a block of bytes.
        /// Init must be called with the IsEncrypted flag set to true before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        void EncryptBlock(byte[] Input, byte[] Output);

        /// <summary>
        /// Encrypt a block of bytes within an array.
        /// Init must be called with the IsEncrypted flag set to true before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset);

        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// <param name="Encryption">Using Encryption or Decryption mode</param>
        /// <param name="KeyParam">Cipher key, valid sizes are: 128, 192, 256 and 512 bytes</param>
        void Init(bool Encryption, KeyParams KeyParam);

        /// <summary>
        /// Transform a block of bytes.
        /// Init must be called before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt/Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        void Transform(byte[] Input, byte[] Output);

        /// <summary>
        /// Transform a block of bytes.
        /// Init must be called before this method can be used.
        /// </summary>
        /// <param name="Input">Bytes to encrypt or decrypt</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Output bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset);

        /// <summary>
        /// Dispose of this class
        /// </summary>
        void Dispose();
    }
}
