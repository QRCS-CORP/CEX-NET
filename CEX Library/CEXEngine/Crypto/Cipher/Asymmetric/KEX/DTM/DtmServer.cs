using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using VTDev.Libraries.CEXEngine.Networking;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures;

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX
{
    public class DtmServer
    {
        public DtmServer(TcpSocket Client)
        {

        }

        public bool Authenticate(byte[] Challenge, byte[] PassPhrase)
        {
            return false;
        }

        public byte[] List(DtmClient[] ClientList)
        {
            return null;
        }

        public byte[] Query(byte[] Term, DtmClient[] ClientList)
        {
            return null;
        }

        public void Listen()
        {

        }

        public void Stop()
        {

        }

    }
}
