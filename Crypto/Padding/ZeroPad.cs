using System;

namespace VTDev.Projects.CEX.Crypto.Padding
{
    /// <summary>
    /// Zero Padding
    /// </summary>
    public class ZeroPad : IPadding
    {
        #region Properties
        /// <summary>
        /// Block size of Cipher
        /// </summary>
        public int BlockSize { get; set; }

        /// <summary>
        /// Padding name
        /// </summary>
        public string Name
        {
            get { return "Zeros"; }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Initialize padding
        /// </summary>
        public void Init()
        {
        }

        /// <summary>
        /// Add padding to input array
        /// </summary>
        /// <param name="Input">Array to modify</param>
        /// <param name="Offset">Offset into array</param>
        public void AddPadding(byte[] Input, int Offset)
        {
            byte code = (byte)0;

            while (Offset < Input.Length)
            {
                Input[Offset] = code;
                Offset++;
            }
        }

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// <param name="Input">Padded array of bytes</param>
        /// <returns>Length of padding</returns>
        public int GetPaddingLength(byte[] Input)
        {
            int len = Input.Length - 1;
            byte code = (byte)0;

            for (int i = len; i > 0; i--)
            {
                if (Input[i] != code)
                    return (len - i);
            }

            return 0;
        }
        #endregion
    }
}
