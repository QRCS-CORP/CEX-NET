namespace VTDev.Projects.CEX.Cryptographic.Padding
{
    /// <summary>
    /// Padding Interface
    /// </summary>
    public interface IPadding
    {
        /// <summary>
        /// Block size of Cipher
        /// </summary>
        int BlockSize { get; set; }

        /// <summary>
        /// Initialize padding
        /// </summary>
        void Init();

        /// <summary>
        /// Padding name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Add padding to input array
        /// </summary>
        /// <param name="Input">Array to modify</param>
        /// <param name="Offset">Offset into array</param>
        void AddPadding(byte[] Input, int Offset);

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// <param name="Input">Padded array of bytes</param>
        /// <returns>Length of padding</returns>
        int GetPaddingLength(byte[] Input);
    }
}
