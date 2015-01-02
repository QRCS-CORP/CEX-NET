#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Ciphers
{
    /// <summary>
    /// Stream Cipher Interface
    /// </summary>
    public interface IStreamCipher : IDisposable
    {
        /// <summary>
        /// Get: Cipher is ready to transform data
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Get: Cipher name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Initialize the Cipher.
        /// </summary>
        /// 
        /// <param name="KeyParam">Cipher key container. The <see cref="LegalKeySizes"/> property contains valid sizes.</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null key ot iv is used.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an invalid key or iv size is used.</exception>
        void Init(KeyParams KeyParam);

        /// <summary>
        /// Encrypt/Decrypt an array of bytes
        /// </summary>
        /// 
        /// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
        /// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
        void Transform(byte[] Input, byte[] Output);

        /// <summary>
        /// Encrypt/Decrypt an array of bytes.
        /// <para><see cref="Init(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
        /// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if an input and output arrays do not align or are too small.</exception>
        void Transform(byte[] Input, int InOffset, byte[] Output, int OutOffset);

        /// <summary>
        /// Encrypt/Decrypt an array of bytes.
        /// <para><see cref="Init(KeyParams)"/> must be called before this method can be used.</para>
        /// </summary>
        /// 
        /// <param name="Input">Bytes to Encrypt</param>
        /// <param name="InOffset">Offset within the Input array</param>
        /// <param name="Output">Encrypted bytes</param>
        /// <param name="OutOffset">Offset within the Output array</param>
        /// 
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if input array is smaller then the ouput array.</exception>
        void Transform(byte[] Input, int InOffset, int Length, byte[] Output, int OutOffset);

        /// <summary>
        /// Dispose of this class
        /// </summary>
        void Dispose();
    }
}
