#region Directives
using System;
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
            int plen = (Input.Length - Offset);

	        Input[Offset++] = MKCODE;

            while (Offset < Input.Length)
		        Input[Offset++] = ZBCODE;

	        return plen;
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
            int plen = Input.Length - 1;

	        if (Input[plen] == MKCODE)
		        return 1;
	        else if (Input[plen] != ZBCODE)
		        return 0;

	        while (plen > 0 && Input[plen] == ZBCODE)
		        plen--;

            return Input.Length - plen;
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
            int plen = Input.Length - (Offset + 1);

	        if (Input[Offset + plen] == MKCODE)
		        return 1;
	        else if (Input[Offset + plen] != ZBCODE)
		        return 0;

	        while (plen > 0 && Input[Offset + plen] == ZBCODE)
		        plen--;

            return (Input.Length - Offset) - plen;
        }
        #endregion
    }
}
