#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments
{
    /// <summary>
    /// An event arguments class containing the error state information.
    /// </summary>
    public class DtmErrorEventArgs : EventArgs
    {
        #region Fields
        /// <summary>
        /// The <see cref="DtmServiceFlags">Exchange State</see> (Auth or Primary), from which this message originated
        /// </summary>
        public Exception Message;
        /// <summary>
        /// The <see cref="DtmErrorSeverity"/> flag indicating the operational impact of the error
        /// </summary>
        public DtmErrorSeverity Severity;
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
        /// <param name="Severity">The <see cref="DtmErrorSeverity"/> flag indicating the operational impact of the error</param>
        public DtmErrorEventArgs(Exception Message, DtmErrorSeverity Severity)
        {
            this.Message = Message;
            this.Severity = Severity;
            this.Cancel = false;
        }
        #endregion
    }
}
