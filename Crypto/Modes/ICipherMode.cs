using System;
using VTDev.Projects.CEX.Crypto.Ciphers;

namespace VTDev.Projects.CEX.Crypto.Modes
{
    /// <summary>
    /// Cipher Mode Interface
    /// </summary>
    public interface ICipherMode : IDisposable
    {
        /// <summary>
        /// Unit block size of internal cipher.
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Used as encryptor, false for decryption. 
        /// </summary>
        bool IsEncryption { get; }

        /// <summary>
        /// Cipher name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Underlying Cipher
        /// </summary>
        IBlockCipher Cipher { get; set; }

        /// <summary>
        /// Intitialization Vector
        /// </summary>
        byte[] Vector { get; set; }

        /// <summary>
        /// Initialize the Cipher
        /// </summary>
        /// <param name="Encryptor">Cipher is used for encryption, false to decrypt</param>
        /// <param name="Transform">Underlying encryption engine</param>
        /// <param name="KeyParam">Cipher key and Vector</param>
        void Init(bool Encryptor, KeyParams KeyParam);

        /// <summary>
        /// Transform a block of bytes.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="Output">Encrypted bytes</param>
        void Transform(byte[] Input, byte[] Output);

        /// <summary>
        /// Transform a block of bytes within an array.
        /// </summary>
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset with the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset with the Output array</param>
        void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset);

        /// <summary>
        /// Dispose of this class
        /// </summary>
        void Dispose();
    }
}
