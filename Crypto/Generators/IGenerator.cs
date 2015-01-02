#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generators
{
    /// <summary>
    /// Random Generator Interface
    /// </summary>
    public interface IGenerator : IDisposable
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null salt is used.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Salt does not contain enough material for Key and Vector creation.</exception>
        void Init(byte[] Salt);

        /// <summary>
        /// Initialize the generator
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null salt or ikm is used.</exception>
        void Init(byte[] Salt, byte[] Ikm);

        /// <summary>
        /// Initialize the algorithm
        /// </summary>
        /// 
        /// <param name="Salt">Salt value</param>
        /// <param name="Ikm">Key material</param>
        /// <param name="Ikm">Nonce value</param>
        void Init(byte[] Salt, byte[] Ikm, byte[] Info);

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        int Generate(int Size, byte[] Output);

        /// <summary>
        /// Generate a block of bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        int Generate(int Size, byte[] Output, int OutOffset);

        /// <summary>
        /// Dispose of this class, and dependant resources
        /// </summary>
        void Dispose();
    }
}
