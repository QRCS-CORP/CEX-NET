#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments
{
    /// <summary>
    /// An event arguments class containing the exchange state information.
    /// </summary>
    public class DtmPacketEventArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// The <see cref="DtmServiceFlags">Exchange State</see> (Auth or Primary), from which this message originated
        /// </summary>
        public short Message = 1;
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
        /// The DTM packet event args constructor; contains the current exchange state
        /// </summary>
        /// 
        /// <param name="Message">The <see cref="DtmServiceFlags">Exchange State</see> (Auth or Primary), from which this message originated</param>
        /// <param name="OptionFlag">The option flag containing optional state information</param>
        public DtmPacketEventArgs(short Message, long OptionFlag)
        {
            this.Message = Message;
            this.OptionFlag = OptionFlag;
            this.Cancel = false;
        }
        #endregion
    }
}
