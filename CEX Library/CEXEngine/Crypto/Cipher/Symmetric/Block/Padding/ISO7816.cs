#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding
{
    /// <summary>
    /// <h3>The <cite>ISO 7816</cite> Padding Scheme</h3>
    /// </summary>
    public sealed class ISO7816 : IPadding
    {
        #region Constants
        private const string ALG_NAME = "ISO7816";
        private const byte ZBCODE = (byte)0x00;
        private const byte MKCODE = (byte)0x80;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The padding modes type name
        /// </summary>
        public PaddingModes Enumeral
        {
            get { return PaddingModes.ISO7816; }
        }

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

	        Input[Offset++] = MKCODE;

            while (Offset < Input.Length)
		        Input[Offset++] = ZBCODE;

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

	        if (Input[len] == MKCODE)
		        return 1;
	        else if (Input[len] != ZBCODE)
		        return 0;

	        while (len > 0 && Input[len] == ZBCODE)
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
            int len = Input.Length - (Offset + 1);

	        if (Input[Offset + len] == MKCODE)
		        return 1;
	        else if (Input[Offset + len] != ZBCODE)
		        return 0;

	        while (len > 0 && Input[Offset + len] == ZBCODE)
		        len--;

            return (Input.Length - Offset) - len;
        }
        #endregion
    }
}
