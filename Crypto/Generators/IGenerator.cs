using System;

namespace VTDev.Libraries.CEXEngine.Crypto.Generators
{
    public interface IGenerator : IDisposable
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Initialize the Generator
        /// </summary>
        /// <param name="Salt">Cipher is used for encryption, false to decrypt</param>
        void Init(byte[] Salt);

        /// <summary>
        /// Initialize the algorithm
        /// </summary>
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        void Init(byte[] Salt, byte[] Ikm);

        /// <summary>
        /// Initialize the algorithm
        /// </summary>
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// <param name="Ikm">Nonce value</param>
        void Init(byte[] Salt, byte[] Ikm, byte[] Info);

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// <param name="Output">Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// <returns>Number of bytes generated</returns>
        int Generate(int Size, byte[] Output);

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// <param name="Output">Output array</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// <returns>Number of bytes generated</returns>
        int Generate(int Size, byte[] Output, int OutOffset);

        /// <summary>
        /// Dispose of this class and underlying resources
        /// </summary>
        void Dispose();
    }
}
