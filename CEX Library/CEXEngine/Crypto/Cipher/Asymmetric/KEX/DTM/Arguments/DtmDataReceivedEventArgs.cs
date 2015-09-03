#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments
{
    /// <summary>
    /// An event arguments class containing the error state information.
    /// </summary>
    public class DtmDataReceivedEventArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// The stream containing decrypted data from a post-exchange channel
        /// </summary>
        public MemoryStream Message;
        /// <summary>
        /// The option flag containing optional state information
        /// </summary>
        public long OptionFlag = 0;
        /// <summary>
        /// The Cancel token; setting this value to true instructs the server to shutdown the exchange (Terminate)
        /// </summary>
        public bool Cancel = false;
        #endregion

        #region Constructor
        /// <summary>
        /// The DTM error event args constructor; contains the current error state
        /// </summary>
        /// 
        /// <param name="Message">The <see cref="Exception"/></param>
        /// <param name="OptionFlag">The option flag containing optional state information</param>
        public DtmDataReceivedEventArgs(MemoryStream Message, long OptionFlag)
        {
            this.Message = Message;
            this.OptionFlag = OptionFlag;
            this.Cancel = false;
        }
        #endregion
    }
}
