#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Ciphers
{
    /// <summary>
    /// Block Cipher Interface
    /// </summary>
    public interface IBlockCipher : IDisposable
    {
        /// <summary>
        /// Get: Unit block size of internal cipher
        /// <para>Block size must be 16 or 32 bytes wide</para>
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Get: Used as encryptor, false for decryption
        /// </summary>
        bool IsEncryption { get; }

        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Cipher name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Decrypt a single block of bytes.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
        /// Input and Output must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="Output">Decrypted bytes</param>
        void DecryptBlock(byte[] Input, byte[] Output);

        /// <summary>
        /// Decrypt a block of bytes within an array.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
        /// Input and Output array lengths - Offset must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Encrypted bytes</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Output">Decrypted bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
        void DecryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset);

        /// <summary>
        /// Encrypt a block of bytes.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
        /// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        void EncryptBlock(byte[] Input, byte[] Output);

        /// <summary>
        /// Encrypt a block of bytes within an array.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
        /// Input and Output array lengths - Offset must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
        void EncryptBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset);

        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// 
        /// <param name="Encryption">Using Encryption or Decryption mode</param>
        /// <param name="KeyParam">Cipher key container. The <see cref="LegalKeySizes"/> property contains valid sizes.</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null key is used.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid key size is used.</exception>
        void Init(bool Encryption, KeyParams KeyParam);

        /// <summary>
        /// Transform a block of bytes.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.
        /// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt or Decrypt</param>
        /// <param name="Output">Encrypted or Decrypted bytes</param>
        void Transform(byte[] Input, byte[] Output);

        /// <summary>
        /// Transform a block of bytes within an array.
        /// <para><see cref="Init(bool, KeyParams)"/> must be called before this method can be used.
        /// Input and Output array lengths - Offset must be at least <see cref="BlockSize"/> in length.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
        void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset);

        /// <summary>
        /// Dispose of this class
        /// </summary>
        void Dispose();
    }
}
