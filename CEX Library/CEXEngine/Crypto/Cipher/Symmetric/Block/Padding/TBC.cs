#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding
{
    /// <summary>
    /// <h3>The Trailing Bit Compliment Padding Scheme.</h3>
    /// </summary>
    public sealed class TBC : IPadding
    {
        #region Constants
        private const string ALG_NAME = "TBC";
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
            int len = Input.Length - Offset;
            byte code;

            if (Offset > 0)
                code = (byte)((Input[Offset - 1] & 0x01) == 0 ? 0xff : 0x00);
            else
                code = (byte)((Input[Input.Length - 1] & 0x01) == 0 ? 0xff : 0x00);

            while (Offset < Input.Length)
            {
                Input[Offset] = code;
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
            byte code = Input[Input.Length - 1];
            int len = Input.Length - 1;

            for (int i = len; i > 0; i--)
            {
                if (Input[i] != code)
                    return (len - i);
            }

            return 0;
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
            int len = Input.Length - (Offset + 1);
            byte code = Input[Input.Length - 1];

            for (int i = len; i > 0; i--)
            {
                if (Input[Offset + i] != code)
                    return (len - i);
            }

            return 0;
        }
        #endregion
    }
}
