using System;

namespace VTDev.Projects.CEX.Crypto.Generators
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
        /// <param name="Seed">Cipher is used for encryption, false to decrypt</param>
        void Init(byte[] Seed);

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// <param name="Output">Output array</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// <returns>Number of bytes generated</returns>
        int Generate(byte[] Output, int OutOffset, int Size);

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// <param name="Output">Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// <returns>Number of bytes generated</returns>
        int Generate(byte[] Output, int Size);

        /// <summary>
        /// Dispose of this class and underlying resources
        /// </summary>
        void Dispose();
    }
}
