namespace VTDev.Projects.CEX.Crypto.Digests
{
    public interface IDigest
    {
        /// <summary>
        /// The Digest name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// The Digests internal blocksize in bytes
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Size of returned digest in bytes
        /// </summary>
        int DigestSize { get; }

        /// <summary>
        /// Update the buffer
        /// </summary>
        /// <param name="Input">Input data [bytes]</param>
        /// <param name="InputOffset">Offset within Input</param>
        /// <param name="Length">Amount of data to process in bytes</param>
        void BlockUpdate(byte[] Input, int InputOffset, int Length);

        /// <summary>
        /// Get the Hash value
        /// </summary>
        /// <param name="Input"></param>
        /// <returns>Hash value [32 bytes]</returns>
        byte[] ComputeHash(byte[] Input);

        /// <summary>
        /// Do final processing
        /// </summary>
        /// <param name="Output">Inputs the final block, and returns the Hash value</param>
        /// <param name="OutOffset">The starting positional offset within the Output array</param>
        /// <returns>Size of Hash value, Always 32 bytes</returns>
        int DoFinal(byte[] Output, int OutOffset);

        /// <summary>
        /// Reset the internal state
        /// </summary>
        void Reset();

        /// <summary>
        /// Update the message digest with a single byte
        /// </summary>
        /// <param name="Input">Input byte</param>
        void Update(byte input);

        /// <summary>
        /// Dispose of this class
        /// </summary>
        void Dispose();
    }
}
