using System;

namespace VTDev.Projects.CEX.Cryptographic.Ciphers
{
    /// <summary>
    /// Block Cipher Interface
    /// </summary>
    public interface IStreamCipher : IDisposable
    {
        /// <summary>
        /// Key has been expanded
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// Encryption Key, read only
        /// </summary>
        byte[] Key { get; }

        /// <summary>
        /// Encryption Key Sizes in bits
        /// </summary>
        int[] KeySizes { get; }

        /// <summary>
        /// Cipher name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Initialize the algorithm, must be called before processing
        /// </summary>
        /// <param name="Seed">Random seed value</param>
        void Init(byte[] Seed);

        /// <summary>
        /// Encrypt/Decrypt an array of bytes
        /// </summary>
        /// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
        /// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
        void Transform(byte[] Input, byte[] Output);

        /// <summary>
        /// Transform a range of bytes
        /// </summary>
        /// <param name="Input">Bytes to transform</param>
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
