using System;
using System.Security.Cryptography;

namespace VTDev.Projects.CEX.CryptoGraphic
{
    /// <summary>
    /// X923 Padding
    /// </summary>
    public class X923 : IPadding
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
            get { return "X923"; }
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
            byte code = (byte)(Input.Length - Offset);
            int len = (Input.Length - Offset) - 1;
            byte[] data = new byte[len];

            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
                random.GetBytes(data);

            Buffer.BlockCopy(data, 0, Input, Offset, len);
            Input[Input.Length - 1] = code;
        }

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// <param name="Input">Padded array of bytes</param>
        /// <returns>Length of padding</returns>
        public int GetPaddingLength(byte[] Input)
        {
            return Input[Input.Length - 1] & 0xff;
        }
        #endregion
    }
}
