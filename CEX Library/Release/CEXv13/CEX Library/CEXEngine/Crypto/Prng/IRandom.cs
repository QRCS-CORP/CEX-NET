#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Prng
{
    /// <summary>
    /// Pseudo Random Number Generator Interface
    /// </summary>
    public interface IRandom : IDisposable
    {
        /// <summary>
        /// Get: Algorithm name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Fill an array with cryptographically secure pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Data">Array to fill with random bytes</param>
        void GetBytes(byte[] Data);

        /// <summary>
        /// Fill an array with cryptographically secure pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>Random byte array</returns>
        byte[] GetBytes(int Size);

        /// <summary>
        /// Get a cryptographically secure pseudo random 32bit integer
        /// </summary>
        /// 
        /// <returns>Random Int32</returns>
        Int32 Next();

        /// <summary>
        /// Get a cryptographically secure pseudo random 64bit integer
        /// </summary>
        /// 
        /// <returns>Random Int64</returns>
        Int64 NextLong();

        /// <summary>
        /// Reset the internal state
        /// </summary>
        void Reset();
    }
}
