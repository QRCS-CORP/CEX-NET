#region Directives
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
#endregion

namespace Network.Support
{
    /// <summary>
    /// Implements the connection logic for the socket client
    /// </summary>
    /// 
    /// <remarks>Based on the codeproject article by Marcos Hidalgo Nunes: 
    /// <see href="http://www.codeproject.com/Articles/22918/How-To-Use-the-SocketAsyncEventArgs-Class"/>
    /// </remarks>
    internal sealed class SocketClient : IDisposable
    {
        #region Constants
        private const int ReceiveOperation = 1;
        private const int SendOperation = 0;
        #endregion

        #region Events
        /// <summary>
        /// 
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="e"></param>
        public delegate void DataReceivedDelegate(object sender, byte[] buffer);

        /// <summary>
        /// 
        /// </summary>
        public event DataReceivedDelegate DataReceived;
        #endregion

        #region Fields
        // The socket used to send/receive messages
        private Socket _clientSocket;
        // Flag for connected socket
        private bool _isConnected = false;
        // Listener endpoint
        private IPEndPoint _hostEndPoint;
        // Signals a connection
        private static AutoResetEvent _autoConnectEvent = new AutoResetEvent(false);
        // Signals the send/receive operation
        private static AutoResetEvent[] _autoSendReceiveEvents = new AutoResetEvent[]
        {
            new AutoResetEvent(false),
            new AutoResetEvent(false)
        };
        // buffer
        private ReceiveBuffer _rcvBuffer = new ReceiveBuffer();
        #endregion

        #region Properties
        public bool IsConnected
        {
            get { return _isConnected; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Create an uninitialized client instance.  
        /// <para>To start the send/receive processing call the Connect method followed by SendReceive method.</para>
        /// </summary>
        /// 
        /// <param name="Host">Name of the host where the listener is running</param>
        /// <param name="Port">Number of the TCP port from the listener</param>
        internal SocketClient(IPAddress IP, int Port, Int32 Timeout = -1)
        {
            // Instantiates the endpoint and socket
            _hostEndPoint = new IPEndPoint(IP, Port);
            _clientSocket = new Socket(_hostEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            _clientSocket.ReceiveTimeout = Timeout;
            _clientSocket.SendTimeout = Timeout;
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Connect to the host
        /// </summary>
        /// 
        /// <returns>True if connection has succeded, else false</returns>
        internal void Connect()
        {
            SocketAsyncEventArgs connectArgs = new SocketAsyncEventArgs();

            connectArgs.UserToken = _clientSocket;
            connectArgs.RemoteEndPoint = _hostEndPoint;
            connectArgs.Completed += new EventHandler<SocketAsyncEventArgs>(OnConnect);
            _clientSocket.ConnectAsync(connectArgs);
            _autoConnectEvent.WaitOne();

            SocketError errorCode = connectArgs.SocketError;

            if (errorCode != SocketError.Success)
                throw new SocketException((Int32)errorCode);
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Disconnect from the host
        /// </summary>
        internal void Disconnect()
        {
            _clientSocket.Disconnect(false);
            _isConnected = false;
        }

        /// <summary>
        /// Exchange a message with the host
        /// </summary>
        /// 
        /// <param name="Message">Message to send</param>
        /// 
        /// <returns>Message sent by the host</returns>
        internal void SendReceive(byte[] Message)
        {
            if (_isConnected)
            {
                // Prepare arguments for send/receive operation.
                SocketAsyncEventArgs completeArgs = new SocketAsyncEventArgs();
                completeArgs.SetBuffer(Message, 0, Message.Length);
                completeArgs.UserToken = _clientSocket;
                completeArgs.RemoteEndPoint = _hostEndPoint;
                completeArgs.Completed += new EventHandler<SocketAsyncEventArgs>(OnSend);
                _clientSocket.SendAsync(completeArgs);

                // Wait for the send/receive completed.
                AutoResetEvent.WaitAll(_autoSendReceiveEvents);

                if (DataReceived != null)
                    DataReceived(this, _rcvBuffer.GetArray());

                _rcvBuffer.Reset();
            }
            else
            {
                throw new SocketException((int)SocketError.NotConnected);
            }
        }
        #endregion

        #region Private Methods
        private void OnConnect(object sender, SocketAsyncEventArgs e)
        {
            // Signals the end of connection.
            _autoConnectEvent.Set();
            // Set the flag for socket connected.
            _isConnected = (e.SocketError == SocketError.Success);
        }

        private void OnReceive(object sender, SocketAsyncEventArgs e)
        {
            Socket s = e.UserToken as Socket;
            _rcvBuffer.AddBytes(e.Buffer, e.Offset, e.BytesTransferred);

            if (s.Available == 0)
            {
                // Signals the end of receive
                _autoSendReceiveEvents[SendOperation].Set();
            }
            else
            {
                if (s.Available > _rcvBuffer.ReceiveBufferLimit)
                {
                    e.SetBuffer(e.Offset, _rcvBuffer.ReceiveBufferLimit);
                    _rcvBuffer.RemainingBytes = _rcvBuffer.ReceiveBufferLimit;
                }
                else
                {
                    e.SetBuffer(e.Offset, s.Available);
                    _rcvBuffer.RemainingBytes = s.Available;
                }

                // Read the next block of data sent by client
                s.ReceiveAsync(e);
            }
        }

        private void OnSend(object sender, SocketAsyncEventArgs e)
        {
            // Signals the end of send.
            _autoSendReceiveEvents[ReceiveOperation].Set();

            if (e.SocketError == SocketError.Success)
            {
                if (e.LastOperation == SocketAsyncOperation.Send)
                {
                    // Prepare receiving.
                    Socket s = e.UserToken as Socket;
                    byte[] receiveBuffer = new byte[_rcvBuffer.ReceiveBufferLimit];
                    e.SetBuffer(receiveBuffer, 0, receiveBuffer.Length);
                    e.Completed += new EventHandler<SocketAsyncEventArgs>(OnReceive);
                    s.ReceiveAsync(e);
                }
            }
            else
            {
                ProcessError(e);
            }
        }

        /// <summary>
        /// Close socket in case of failure and throws a SockeException according to the SocketError.
        /// </summary>
        /// <param name="e">SocketAsyncEventArg associated with the failed operation.</param>
        private void ProcessError(SocketAsyncEventArgs e)
        {
            Socket s = e.UserToken as Socket;
            if (s.Connected)
            {
                // close the socket associated with the client
                try
                {
                    _isConnected = false;
                    s.Shutdown(SocketShutdown.Both);
                }
                catch { }
                finally
                {
                    if (s.Connected)
                        s.Close();
                }
            }

            // Throw the SocketException
            throw new SocketException((Int32)e.SocketError);
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Disposes the instance of SocketClient.
        /// </summary>
        public void Dispose()
        {
            _autoConnectEvent.Close();
            _autoSendReceiveEvents[SendOperation].Close();
            _autoSendReceiveEvents[ReceiveOperation].Close();

            if (_clientSocket.Connected)
                _clientSocket.Close();
        }
        #endregion
    }
}