#region Directives
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
#endregion

namespace Network.Support
{
    /// <summary>
    /// Implements the connection logic for the socket server
    /// <para>After accepting a connection, all data read from the client is sent back. 
    /// The read and echo back to the client pattern is continued until the client disconnects.</para>
    /// </summary>
    /// 
    /// <remarks>Based on the codeproject article by Marcos Hidalgo Nunes: 
    /// <see href="http://www.codeproject.com/Articles/22918/How-To-Use-the-SocketAsyncEventArgs-Class"/>
    /// </remarks>
    internal sealed class SocketListener : IDisposable
    {
        #region Events
        /// <summary>
        /// The server data received delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="e">The SocketAsyncEventArgs object</param>
        public delegate void DataReceivedDelegate(object sender, SocketAsyncEventArgs e);

        /// <summary>
        /// The server data received event
        /// </summary>
        public event DataReceivedDelegate DataReceived;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private bool _isListening = false;
        // The socket used to listen for incoming connection requests
        private Socket _listenSocket;
        // Mutex to synchronize server execution
        private static Mutex _mutex = new Mutex();
        // Buffer size to use for each socket I/O operation
        private int _bufferSize;
        // The total number of clients connected to the server
        private int _numConnectedSockets;
        // the maximum number of connections the sample is designed to handle simultaneously
        private int _numConnections;
        // Pool of reusable SocketAsyncEventArgs objects for write, read and accept socket operations
        private SocketAsyncEventArgsPool _readWritePool;
        // Controls the total number of clients connected to the server
        private Semaphore _semaphoreAcceptedClients;
        #endregion

        #region Properties
        public int BufferSize
        {
            get { return _bufferSize; }
        }

        public bool IsListening
        {
            get { return _isListening; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Create an uninitialized server instance.  
        /// <para>To start the server listening for connection requests call the Init method followed by Start method.</para>
        /// </summary>
        /// 
        /// <param name="MaxConnections">Maximum number of connections to be handled simultaneously</param>
        /// <param name="BufferSize">Buffer size to use for each socket I/O operation</param>
        internal SocketListener(int MaxConnections, int BufferSize)
        {
            _numConnectedSockets = 0;
            _numConnections = MaxConnections;
            _bufferSize = BufferSize;
            _readWritePool = new SocketAsyncEventArgsPool(MaxConnections);
            _semaphoreAcceptedClients = new Semaphore(MaxConnections, MaxConnections);

            // Preallocate pool of SocketAsyncEventArgs objects.
            for (int i = 0; i < _numConnections; i++)
            {
                SocketAsyncEventArgs readWriteEventArg = new SocketAsyncEventArgs();
                readWriteEventArg.Completed += new EventHandler<SocketAsyncEventArgs>(OnIOCompleted);
                readWriteEventArg.SetBuffer(new Byte[_bufferSize], 0, _bufferSize);
                // Add SocketAsyncEventArg to the pool.
                _readWritePool.Push(readWriteEventArg);
            }
        }

        ~SocketListener()
        {
            Dispose(false);
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Starts the server listening for incoming connection requests
        /// </summary>
        /// 
        /// <param name="Port">Port where the server will listen for connection requests</param>
        internal void Start(Int32 Port)
        {
            // Get host address
            IPAddress[] addressList = Dns.GetHostEntry(Environment.MachineName).AddressList;
            Start(addressList[addressList.Length - 1], Port);
        }

        /// <summary>
        /// Starts the server listening for incoming connection requests
        /// </summary>
        /// 
        /// <param name="Port">Port where the server will listen for connection requests</param>
        /// <param name="Address">The IP Address of the interface to start listening on</param>
        internal void Start(IPAddress Address, Int32 Port, Int32 Timeout = -1)
        {
            // Get endpoint for the listener.
            IPEndPoint localEndPoint = new IPEndPoint(Address, Port);
            // Create the socket which listens for incoming connections.
            _listenSocket = new Socket(localEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            _listenSocket.ReceiveBufferSize = _bufferSize;
            _listenSocket.SendBufferSize = _bufferSize;
            //_listenSocket.ReceiveTimeout = Timeout;
            //_listenSocket.SendTimeout = Timeout;

            if (localEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // Set dual-mode (IPv4 & IPv6) for the socket listener.
                // 27 is equivalent to IPV6_V6ONLY socket option in the winsock snippet below,
                // based on http://blogs.msdn.com/wndp/archive/2006/10/24/creating-ip-agnostic-applications-part-2-dual-mode-sockets.aspx
                _listenSocket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)27, false);
                _listenSocket.Bind(new IPEndPoint(IPAddress.IPv6Any, localEndPoint.Port));
            }
            else
            {
                // Associate the socket with the local endpoint
                _listenSocket.Bind(localEndPoint);
            }

            // Start the server.
            _listenSocket.Listen(_numConnections);
            // Post accepts on the listening socket.
            StartAccept(null);
            // Blocks the current thread to receive incoming messages.
            _mutex.WaitOne();
            // online
            _isListening = true;
        }

        /// <summary>
        /// Stop the server
        /// </summary>
        internal void Stop()
        {
            _listenSocket.Close();
            _mutex.ReleaseMutex();
            _isListening = false;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Close the socket associated with the client
        /// </summary>
        /// 
        /// <param name="e">SocketAsyncEventArg associated with the completed send/receive operation</param>
        private void CloseClientSocket(SocketAsyncEventArgs e)
        {
            Token token = e.UserToken as Token;
            CloseClientSocket(token, e);
        }

        private void CloseClientSocket(Token token, SocketAsyncEventArgs e)
        {
            token.Dispose();

            // Decrement the counter keeping track of the total number of clients connected to the server.
            _semaphoreAcceptedClients.Release();
            Interlocked.Decrement(ref _numConnectedSockets);
            Console.WriteLine("A client has been disconnected from the server. There are {0} clients connected to the server", _numConnectedSockets);

            // Free the SocketAsyncEventArg so they can be reused by another client.
            _readWritePool.Push(e);
        }

        /// <summary>
        /// Callback method associated with Socket.AcceptAsync operations and is invoked when an accept operation is complete
        /// </summary>
        /// 
        /// <param name="sender">Object who raised the event</param>
        /// <param name="e">SocketAsyncEventArg associated with the completed accept operation</param>
        private void OnAcceptCompleted(object sender, SocketAsyncEventArgs e)
        {
            ProcessAccept(e);
        }

        /// <summary>
        /// Callback called whenever a receive or send operation is completed on a socket
        /// </summary>
        /// 
        /// <param name="sender">Object who raised the event</param>
        /// <param name="e">SocketAsyncEventArg associated with the completed send/receive operation</param>
        private void OnIOCompleted(object sender, SocketAsyncEventArgs e)
        {
            // Determine which type of operation just completed and call the associated handler
            switch (e.LastOperation)
            {
                case SocketAsyncOperation.Receive:
                    ProcessReceive(e);
                    break;
                case SocketAsyncOperation.Send:
                    ProcessSend(e);
                    break;
                default:
                    throw new ArgumentException("The last operation completed on the socket was not a receive or send!");
            }
        }

        /// <summary>
        /// Process the accept for the socket listener
        /// </summary>
        /// 
        /// <param name="e">SocketAsyncEventArg associated with the completed accept operation</param>
        private void ProcessAccept(SocketAsyncEventArgs e)
        {
            Socket s = e.AcceptSocket;
            if (s.Connected)
            {
                try
                {
                    SocketAsyncEventArgs readEventArgs = _readWritePool.Pop();
                    if (readEventArgs != null)
                    {
                        // Get the socket for the accepted client connection and put it into the ReadEventArg object user token
                        readEventArgs.UserToken = new Token(s, _bufferSize);

                        Interlocked.Increment(ref _numConnectedSockets);
                        Console.WriteLine("Client connection accepted. There are {0} clients connected to the server", _numConnectedSockets);

                        if (!s.ReceiveAsync(readEventArgs))
                            ProcessReceive(readEventArgs);
                    }
                    else
                    {
                        Console.WriteLine("There are no more available sockets to allocate.");
                    }
                }
                catch (SocketException ex)
                {
                    Token token = e.UserToken as Token;
                    Console.WriteLine("Error when processing data received from {0}:\r\n{1}", token.Connection.RemoteEndPoint, ex.ToString());
                }
                catch
                {
                    throw;
                }

                // Accept the next connection request.
                StartAccept(e);
            }
        }

        private void ProcessError(SocketAsyncEventArgs e)
        {
            Token token = e.UserToken as Token;
            IPEndPoint localEp = token.Connection.LocalEndPoint as IPEndPoint;
            CloseClientSocket(token, e);

            throw new SocketException((Int32)e.SocketError);
        }

        /// <summary>
        /// This method is invoked when an asynchronous send operation completes.  
        /// <para>The method issues another receive on the socket to read any additional data sent from the client.</para>
        /// </summary>
        /// 
        /// <param name="e">SocketAsyncEventArg associated with the completed send operation</param>
        private void ProcessSend(SocketAsyncEventArgs e)
        {
            if (e.SocketError == SocketError.Success)
            {
                // Done echoing data back to the client.
                Token token = e.UserToken as Token;

                // Read the next block of data send from the client.
                if (!token.Connection.ReceiveAsync(e))
                    ProcessReceive(e);
            }
            else
            {
                ProcessError(e);
            }
        }

        /// <summary>
        /// This method is invoked when an asynchronous receive operation completes. 
        /// <para>If the remote host closed the connection, then the socket is closed. 
        /// If data was received then the data is echoed back to the client</para>
        /// </summary>
        /// 
        /// <param name="e">SocketAsyncEventArg associated with the completed receive operation</param>
        private void ProcessReceive(SocketAsyncEventArgs e)
        {
            // Check if the remote host closed the connection.
            if (e.BytesTransferred > 0)
            {
                if (e.SocketError == SocketError.Success)
                {
                    Token token = e.UserToken as Token;
                    token.SetData(e);

                    Socket s = token.Connection;
                    if (s.Available == 0)
                    {
                        // Set return buffer.
                        byte[] buf = token.ReadData(e);
                        if (buf.Length > 0)
                        {
                            SocketAsyncEventArgs f = new SocketAsyncEventArgs();
                            f.UserToken = token;
                            f.SetBuffer(buf, 0, buf.Length);
                            if (DataReceived != null)
                                DataReceived(this, f);
                        }
                        if (!s.SendAsync(e))
                        {
                            // Set the buffer to send back to the client.
                            this.ProcessSend(e);
                        }

                    }
                    else if (!s.ReceiveAsync(e))
                   {
                         // Read the next block of data sent by client.
                        this.ProcessReceive(e);
                    }
                }
                else
                {
                    this.ProcessError(e);
                }
            }
            else
            {
                this.CloseClientSocket(e);
            }
        }

        public void Send(SocketAsyncEventArgs e)
        {
            Token token = e.UserToken as Token;
            token.SetData(e);
            Socket s = token.Connection;

            if (s.Available == 0)
            {
                // Set return buffer.
                token.ReadData(e);
                // Set the buffer to send back to the client.
                if (!s.SendAsync(e))
                    ProcessSend(e);
            }
        }

        /// <summary>
        /// Begins an operation to accept a connection request from the client
        /// </summary>
        /// 
        /// <param name="acceptEventArg">The context object to use when issuing the accept operation on the server's listening socket</param>
        private void StartAccept(SocketAsyncEventArgs acceptEventArg)
        {
            if (acceptEventArg == null)
            {
                acceptEventArg = new SocketAsyncEventArgs();
                acceptEventArg.Completed += new EventHandler<SocketAsyncEventArgs>(OnAcceptCompleted);
            }
            else
            {
                // Socket must be cleared since the context object is being reused
                acceptEventArg.AcceptSocket = null;
            }

            _semaphoreAcceptedClients.WaitOne();

            if (!_listenSocket.AcceptAsync(acceptEventArg))
                ProcessAccept(acceptEventArg);
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_listenSocket != null)
                    {
                        _listenSocket.Close();
                        _listenSocket.Dispose();
                    }
                    /*if (_semaphoreAcceptedClients != null)
                    {
                        _semaphoreAcceptedClients.Close();
                        _semaphoreAcceptedClients.Dispose();
                    }
                    _readWritePool = null;*/
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
