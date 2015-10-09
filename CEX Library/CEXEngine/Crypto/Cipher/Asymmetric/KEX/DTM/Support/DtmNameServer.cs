#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
using VTDev.Libraries.CEXEngine.Networking;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Support
{
    public class DtmNameServer
    {
        #region Constructor
        public DtmNameServer(TcpSocket Client)
        {

        }

        ~DtmNameServer()
        {

        }
        #endregion

        #region Public Methods
        public bool Authenticate(byte[] Challenge, byte[] PassPhrase)
        {
            return false;
        }

        public byte[] ListResponse(DtmClientStruct[] ClientList)
        {
            return null;
        }

        public byte[] QueryResponse(byte[] Term, DtmClientStruct[] ClientList)
        {
            return null;
        }

        public void Listen()
        {

        }

        public void Stop()
        {

        }
        #endregion


    }
}
