#region Directives
using System.Net.Sockets;
using Network.Support;
using System.Net;
using System.IO;
using System;
#endregion

#region Notes
/* rabbit is coming..
 *  () ()
 * =(-,-)=
 *  (   ) 
 * (")_(")
 */
#endregion

namespace Network
{
    // A basic key exchange operation using CTKEX:
    // 
    // c->Negotiate: client sends a proposed parameter set
    // s->Accept: server accepts params 
    // OR
    // s->Decline: server refuses, spawns mutual Disconnect
    //
    // c->PublicKey: client sends public key
    // s->Acknowledge: server has received the public key
    // s->PublicKey: server sends public key
    // c->Acknowledge: client has received the public key
    //
    // s->SymmetricKey: server sends symmetric key encrypted with clients public key
    // c->Acknowledge: client has received the symmetric key
    // c->SymmetricKey: client encrypts and sends symmetric key
    // s->Acknowledge: server has received the symmetric key
    //
    // s->Ready: server is ready to stream encrypted data
    // c->Ready: client is ready and acknowledges
    //
    // c->Data: client begins transmission of encrypted data
    // s->Acknowledge: data has been received
    // s->Data: server returns encrypted data
    // c->Acknowledge: data has been received
    //
    // c->Disconnect: end the session
    // s->Disconnect: ending the session
    class Program
    {
        private const int PORT = 14400;
        private static int TIMEOUT = 2000;

        enum PacketFlags : byte
        {
            Negotiate = 1,
            Accept = 2,
            Decline = 3,
            PublicKey = 4,
            SymmetricKey = 5,
            Ready = 6,
            Acknowledge = 7,
            Data = 8,
            Error = 9,
            Disconnect = 10,
        }

        private static TcpServer _tcpServer = new TcpServer();
        private static TcpClient _tcpClient = new TcpClient();
        private static IPAddress _ipAddress = NetworkUtils.ResolveName(System.Environment.MachineName);
        private static IPAddress _loopBack = NetworkUtils.ResolveName("127.0.0.1");

        static void Main(string[] args)
        {
            _tcpServer.ServerDataReceived += new TcpServer.ServerDataReceivedDelegate(OnServerDataReceived);
            _tcpServer.Listen(_loopBack, PORT);

            _tcpClient.ClientDataReceived += new TcpClient.ClientDataReceivedDelegate(OnClientDataReceived);
            _tcpClient.Connect(_loopBack, PORT, TIMEOUT);

            // start negotiation
            Send(new byte[] { (byte)PacketFlags.Negotiate });

            Console.ReadKey();

            _tcpClient.Disconnect();
            _tcpClient.Dispose();
            _tcpServer.Dispose();
        }

        static void ClientProcess(byte[] buffer)
        {
            PacketFlags flag = GetFlag(buffer);

            switch (flag)
            {
                case PacketFlags.Accept:
                    {
                        // public key accepted; send your public key
                        Send(new byte[] { (byte)PacketFlags.PublicKey });
                        break;
                    }
                case PacketFlags.PublicKey:
                    {
                        // send the encrypted symmetric key
                        Send(new byte[] { (byte)PacketFlags.SymmetricKey });
                        break;
                    }
                case PacketFlags.SymmetricKey:
                    {
                        // decrypt and store the symmetric key and send ready
                        Send(new byte[] { (byte)PacketFlags.Ready });
                        break;
                    }
                case PacketFlags.Ready:
                    {
                        // start sending encrypted data
                        Send(new byte[] { (byte)PacketFlags.Data });
                        break;
                    }
                case PacketFlags.Data:
                    {
                        // process encrypted data
                        break;
                    }
            }
        }

        static void ServerProcess(SocketAsyncEventArgs e)//getting correct data
        {
            if (e.Buffer.Length < 1)
                return;
            PacketFlags flag = GetFlag(e.Buffer);

            switch (flag)
            {
                case PacketFlags.Negotiate:
                    {
                        // accept the exchange
                        Respond(new byte[] { (byte)PacketFlags.Accept }, e);
                        break;
                    }
                case PacketFlags.Accept:
                    {
                        // send public key
                        Respond(new byte[] { (byte)PacketFlags.PublicKey }, e);
                        break;
                    }
                case PacketFlags.PublicKey:
                    {
                        // encrypt symmetric w/ public key key and send back 
                        Respond(new byte[] { (byte)PacketFlags.SymmetricKey }, e);
                        break;
                    }
                case PacketFlags.SymmetricKey:
                    {
                        // have the symmetric key, ready to encrypt
                        Respond(new byte[] { (byte)PacketFlags.Ready }, e);
                        break;
                    }
                case PacketFlags.Data:
                    {
                        // process encrypted data
                        break;
                    }
            }
        }

        static void Respond(byte[] buffer, SocketAsyncEventArgs e)
        {
            if (_tcpServer != null)
            {
                if (_tcpServer.IsListening)
                {
                    Token token = e.UserToken as Token;
                    token.Connection.SendTo(buffer, token.Connection.RemoteEndPoint);
                }
            }
        }

        static void Send(byte[] buffer)
        {
            if (_tcpClient != null)
            {
                //if (!_tcpClient.IsConnected)
                //_tcpClient.Disconnect();
                //    _tcpClient.Connect(_loopBack, PORT, TIMEOUT);

                _tcpClient.Send(buffer);
            }
        }

        static void OnClientDataReceived(object sender, byte[] buffer)
        {
            ClientProcess(buffer);
        }

        static void OnServerDataReceived(object sender, SocketAsyncEventArgs e)
        {
            ServerProcess(e);
        }

        static PacketFlags GetFlag(byte[] Data)
        {
            return (PacketFlags)Data[0];
        }
    }
}
