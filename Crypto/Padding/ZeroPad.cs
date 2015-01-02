#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Padding
{
    /// <summary>
    /// Zero Padding (Not Recommended)
    /// </summary>
    public class ZeroPad : IPadding
    {
        #region Properties
        /// <summary>
        /// Get: Block size of Cipher
        /// </summary>
        public int BlockSize { get; set; }

        /// <summary>
        /// Get: Padding name
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
        /// 
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
        /// 
        /// <param name="Input">Padded array of bytes</param>
        /// 
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
            byte code = (byte)0;

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
