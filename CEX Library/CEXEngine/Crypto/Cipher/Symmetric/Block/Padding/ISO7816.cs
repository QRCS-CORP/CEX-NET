#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding
{
    /// <summary>
    /// <h3>The ISO7816 Padding Scheme.</h3>
    /// </summary>
    public sealed class ISO7816 : IPadding
    {
        #region Constants
        private const string ALG_NAME = "ISO7816";
        #endregion

        #region Properties
        /// <summary>
        /// Get: Padding name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Add padding to input array
        /// </summary>
        /// 
        /// <param name="Input">Array to modify</param>
        /// <param name="Offset">Offset into array</param>
        /// 
        /// <returns>Length of padding</returns>
        public int AddPadding(byte[] Input, int Offset)
        {
            int len = (Input.Length - Offset);

            Input[Offset] = (byte)0x80;
            Offset++;

            while (Offset < Input.Length)
            {
                Input[Offset] = (byte)0;
                Offset++;
            }

            return len;
        }

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// 
        /// <param name="Input">Padded array of bytes</param>
        /// 
        /// <returns>Length of padding</returns>
        public int GetPaddingLength(byte[] Input)
        {
            int len = Input.Length - 1;

            while (len > 0 && Input[len] == 0)
                len--;

            return Input.Length - len;
        }

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// 
        /// <param name="Input">Padded array of bytes</param>
        /// <param name="Offset">Offset into array</param>
        /// 
        /// <returns>Length of padding</returns>
        public int GetPaddingLength(byte[] Input, int Offset)
        {
            int len = Input.Length - 1;

            while (len > 0 && Input[len] == 0)
                len--;

            return Input.Length - len;
        }
        #endregion
    }
}
