#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Generator
{
    /// <summary>
    /// Random Generator Interface
    /// </summary>
    public interface IGenerator : IDisposable
    {
        /// <summary>
        /// Get: Generator is ready to produce data
        /// </summary>
        bool IsInitialized { get; }

        /// <summary>
        /// <para>Minimum initialization key size in bytes; 
        /// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
        /// </summary>
        int KeySize { get; }

        /// <summary>
        /// Get: The generators type name
        /// </summary>
        Generators Enumeral { get; }

        /// <summary>
        /// Algorithm name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Initialize the generator with a MacParams structure containing the key, and optional salt, and info string
        /// </summary>
        /// 
        /// <param name="GenParam">The MacParams containing the generators keying material</param>
        void Initialize(MacParams GenParam);

        /// <summary>
        /// Initialize the generator with a key
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Salt is used</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Salt does not contain enough material for Key and Vector creation</exception>
        void Initialize(byte[] Key);

        /// <summary>
        /// Initialize the generator with key and salt arrays
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// <param name="Salt">The salt value containing an additional source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if an invalid or null key or salt is used</exception>
        void Initialize(byte[] Key, byte[] Salt);

        /// <summary>
        /// Initialize the generator with a key, a salt array, and an information string or nonce
        /// </summary>
        /// 
        /// <param name="Key">The primary key array used to seed the generator</param>
        /// <param name="Salt">The salt value used as an additional source of entropy</param>
        /// <param name="Info">The information string or nonce used as a third source of entropy</param>
        /// 
        /// <exception cref="CryptoGeneratorException">Thrown if a null key, salt, or info string is used</exception>
        void Initialize(byte[] Salt, byte[] Ikm, byte[] Nonce);

        /// <summary>
        /// Generate a block of pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        int Generate(byte[] Output);

        /// <summary>
        /// Generate pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Output array filled with random bytes</param>
        /// <param name="OutOffset">Position within Output array</param>
        /// <param name="Size">Number of bytes to generate</param>
        /// 
        /// <returns>Number of bytes generated</returns>
        int Generate(byte[] Output, int OutOffset, int Size);

        /// <summary>
        /// Update the Seed material
        /// </summary>
        /// 
        /// <param name="Seed">Pseudo random seed material</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Seed is used</exception>
        void Update(byte[] Seed);
    }
}
