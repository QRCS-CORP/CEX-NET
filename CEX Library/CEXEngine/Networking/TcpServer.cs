#region Directives
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Networking
{
    /// <summary>
    /// This class listens for an incoming connection.
    /// <para>Start listening for a connection with the Listen method, when a host connects the Connected event is fired.
    /// The Connected event contains the connected socket instance in a SocketAsyncEventArgs class.</para>
    /// </summary>
    public class TcpServer
    {
        #region Fields
        private ManualResetEvent _opDone = new ManualResetEvent(false);
        private bool _isDisposed = false;
        private bool _isListening = false;
        private Socket _lsnSocket;
        private NetworkStream _tcpStream = null;
        #endregion

        #region Delegates/Events
        /// <summary>
        /// The Client Connected delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="SocketAsyncEventArgs"/> class</param>
        public delegate void ConnectedDelegate(object owner, SocketAsyncEventArgs args);
        /// <summary>
        /// The Client Connected event; fires each time a connection has been established
        /// </summary>
        public event ConnectedDelegate Connected;

        /// <summary>
        /// The Packet Received delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="Flag">The socket error flag</param>
        public delegate void DisConnectedDelegate(object owner, SocketError Flag);
        /// <summary>
        /// The Client Connected event; fires each time a connection has been established
        /// </summary>
        public event DisConnectedDelegate DisConnected;

        /// <summary>
        /// The Packet Received delegate
        /// </summary>
        /// <param name="args">A <see cref="DataReceivedEventArgs"/> class</param>
        public delegate void DataReceivedDelegate(DataReceivedEventArgs args);
        /// <summary>
        /// The Data Received event; fires each time data has been received
        /// </summary>
        public event DataReceivedDelegate DataReceived;
        #endregion

        #region Listen
        /// <summary>
        /// Start Blocking listen on a port for an incoming connection
        /// </summary>
        /// 
        /// <param name="HostName">The Host Name assigned to this server</param>
        /// <param name="Port">The Port number assigned to this server</param>
        /// <param name="MaxConnections">The maximum number of connections</param>
        /// <param name="Timeout">The wait timeout period</param>
        /// 
        /// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
        public void Listen(string HostName, int Port, int MaxConnections = 10, int Timeout = Timeout.Infinite)
        {
            IPHostEntry host;
            IPAddress[] ipList;
            IPAddress ip;

            try
            {
                // address of the host
                host = Dns.GetHostEntry(HostName);
                ipList = host.AddressList;
                ip = ipList[ipList.Length - 1];
            }
            catch (SocketException se)
            {
                throw new CryptoSocketException("TcpSocket:Listen", "The Tcp listener has failed!", se);
            }
            catch (Exception)
            {
                throw;
            }

            Listen(ip, Port, MaxConnections);
        }

        /// <summary>
        /// Start Blocking listen on a port for an incoming connection
        /// </summary>
        /// 
        /// <param name="Address">The IP address assigned to this server</param>
        /// <param name="Port">The Port number assigned to this server</param>
        /// <param name="MaxConnections">The maximum number of connections</param>
        /// 
        /// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
        public void Listen(IPAddress Address, int Port, int MaxConnections = 10)
        {
            try
            {
                IPEndPoint ipEP = new IPEndPoint(Address, Port);
                _lsnSocket = new Socket(ipEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                if (ipEP.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    _lsnSocket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)27, false);
                    _lsnSocket.Bind(ipEP);
                }
                else
                {
                    // associate the socket with the local endpoint
                    _lsnSocket.Bind(ipEP);
                }

                _isListening = true;
                // accept the incoming client
                _lsnSocket.Listen(MaxConnections);
                // assign client and stream
                Socket cltSocket = _lsnSocket.Accept();

                // get the socket for the accepted client connection and put it into the ReadEventArg object user token
                SocketAsyncEventArgs readEventArgs = new SocketAsyncEventArgs();
                // store the socket
                readEventArgs.UserToken = cltSocket;

                if (Connected != null)
                    Connected(this, readEventArgs);

                _opDone.WaitOne(1);
            }
            catch (SocketException se)
            {
                throw new CryptoSocketException("TcpSocket:Listen", "The Tcp listener has failed!", se);
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// Start Non-Blocking listen on a port for an incoming connection
        /// </summary>
        /// 
        /// <param name="HostName">The Host Name assigned to this server</param>
        /// <param name="Port">The Port number assigned to this server</param>
        /// <param name="MaxConnections">The maximum number of connections</param>
        /// <param name="Timeout">The wait timeout period</param>
        /// 
        /// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
        public void ListenAsync(string HostName, int Port, int MaxConnections = 10, int Timeout = Timeout.Infinite)
        {
            IPHostEntry host;
            IPAddress[] ipList;
            IPAddress ip;

            try
            {
                host = Dns.GetHostEntry(HostName);
                ipList = host.AddressList;
                ip = ipList[ipList.Length - 1];
            }
            catch (SocketException se)
            {
                throw new CryptoSocketException("TcpSocket:Listen", "The Tcp listener has failed!", se);
            }
            catch (Exception)
            {
                throw;
            }

            ListenAsync(ip, Port, MaxConnections, Timeout);
        }

        /// <summary>
        /// Start Non-Blocking listen on a port for an incoming connection
        /// </summary>
        /// 
        /// <param name="Address">The IP address assigned to this server</param>
        /// <param name="Port">The Port number assigned to this server</param>
        /// <param name="MaxConnections">The maximum number of simultaneous connections allowed (default is 10)</param>
        /// <param name="Timeout">The wait timeout period</param>
        /// 
        /// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
        public void ListenAsync(IPAddress Address, int Port, int MaxConnections = 10, int Timeout = Timeout.Infinite)
        {
            try
            {
                IPEndPoint ipEP = new IPEndPoint(Address, Port);
                _lsnSocket = new Socket(ipEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                if (ipEP.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    _lsnSocket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)27, false);
                    _lsnSocket.Bind(ipEP);
                }
                else
                {
                    // associate the socket with the local endpoint
                    _lsnSocket.Bind(ipEP);
                }

                _isListening = true;
                _lsnSocket.Listen(MaxConnections);
                // create the state object.
                StateToken state = new StateToken(_lsnSocket);
                // accept the incoming clients
                _lsnSocket.BeginAccept(new AsyncCallback(ListenCallback), state);
                // blocks the current thread to receive incoming messages
                _opDone.WaitOne(Timeout);
            }
            catch (SocketException se)
            {
                throw new CryptoSocketException("TcpSocket:ListenAsync", "The Tcp listener has failed!", se);
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// The Listen callback
        /// </summary>
        /// 
        /// <param name="Ar">The IAsyncResult</param>
        /// 
        /// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
        private void ListenCallback(IAsyncResult Ar)
        {
            // retrieve the state object and the client socket from the asynchronous state object
            StateToken state = (StateToken)Ar.AsyncState;
            Socket srv = state.Client;

            try
            {
                // get the socket for the accepted client connection and put it into the ReadEventArg object user token
                Socket cltSocket = srv.EndAccept(Ar);

                // store the socket
                SocketAsyncEventArgs readEventArgs = new SocketAsyncEventArgs();
                readEventArgs.UserToken = cltSocket;

                if (Connected != null)
                    Connected(this, readEventArgs);
            }
            catch (ObjectDisposedException)
            {
                // disconnected
                if (DisConnected != null)
                    DisConnected(this, SocketError.ConnectionAborted);
            }
            catch (SocketException se)
            {
                throw new CryptoSocketException("TcpSocket:ListenCallback", "The Tcp listener has failed!", se);
            }
            catch (Exception)
            {
                if (_isListening)
                    throw;
            }
        }

        /// <summary>
        /// Stop listening for a connection
        /// </summary>
        public void ListenStop()
        {
            try
            {
                _lsnSocket.Close(1);
                _opDone.WaitOne(10);
                _isListening = false;
            }
            catch (SocketException se)
            {
                throw new CryptoSocketException("TcpSocket:ListenStop", "The Tcp listen stop had an error!", se);
            }
            catch (Exception)
            {
                throw;
            }
        }
        #endregion
    }
}
