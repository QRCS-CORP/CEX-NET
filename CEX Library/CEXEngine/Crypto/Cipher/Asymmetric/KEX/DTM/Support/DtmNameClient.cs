#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
using VTDev.Libraries.CEXEngine.Networking;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Support
{
    public class DtmNameClient
    {
        #region Constructor
        public DtmNameClient(TcpSocket Client)
        {

        }
        
        ~DtmNameClient()
        {

        }
        #endregion

        #region Public Methods
        public bool Authenticate(byte[] Challenge, byte[] PassPhrase)
        {
            return false;
        }

        public byte[] ListRequest(DtmClientStruct[] ClientList)
        {
            return null;
        }

        public byte[] QueryRequest(byte[] Term, DtmClientStruct[] ClientList)
        {
            return null;
        }

        public void Connect()
        {

        }

        public void Disconnect()
        {

        }
        #endregion
    }
}
