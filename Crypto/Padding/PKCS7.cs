using System;

namespace VTDev.Libraries.CEXEngine.Crypto.Padding
{
    /// <summary>
    /// PKCS7 Padding
    /// </summary>
    public class PKCS7 : IPadding
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
            get { return "PKCS7"; }
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
            byte code = Input[len];

            if ((int)code > len)
                return 0;

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
        /// <param name="Input">Padded array of bytes</param>
        /// <param name="Offset">Offset into array</param>
        /// <returns>Length of padding</returns>
        public int GetPaddingLength(byte[] Input, int Offset)
        {
            int len = Input.Length - (Offset + 1);
            byte code = Input[Input.Length - 1];

            if ((int)code > len)
                return 0;

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
