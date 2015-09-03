#region Directives
using System;
using System.Net;
using System.Net.Sockets;
using Network.Support;
#endregion

namespace Network
{
    public sealed class TcpServer : IDisposable
    {
        #region Constants
        private const int DEFAULT_PORT = 9900;
        private const int DEFAULT_CONNECTIONS = 4;
        private const int DEFAULT_BUFFER = Int16.MaxValue;
        #endregion

        #region Events
        /// <summary>
        /// The server data received delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="e">The SocketAsyncEventArgs object</param>
        public delegate void ServerDataReceivedDelegate(object sender, SocketAsyncEventArgs e);

        /// <summary>
        /// Fires when data has been received by the server
        /// </summary>
        public event ServerDataReceivedDelegate ServerDataReceived;
        #endregion

        #region Fields
        private int _bufferSize = 256;
        private bool _isDisposed = false;
        private int _maxConnections = 10;
        private static SocketListener _sckListener;
        #endregion

        #region Properties
        public bool IsListening
        {
            get
            {
                if (_sckListener != null)
                    return _sckListener.IsListening;

                return false;
            }
        }
        #endregion

        #region Constructor
        public TcpServer()
        {
        }

        ~TcpServer()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Start listening for a connection
        /// </summary>
        /// <param name="IP">The ip address of the server</param>
        /// <param name="Port">The target port number</param>
        /// <param name="Connections">The maximum number of simultaneous connections</param>
        /// <param name="BufferSize">The size of each receive buffer</param>
        public void Listen(IPAddress IP, int Port, int Connections = 4, int BufferSize = 255, int TimeOut = -1)
        {
            try
            {
                _maxConnections = Connections;
                _bufferSize = BufferSize;
                _sckListener = new SocketListener(Connections, BufferSize);
                _sckListener.DataReceived += new SocketListener.DataReceivedDelegate(OnServerDataReceived);
                _sckListener.Start(IP, Port, TimeOut);
            }
            catch
            {
                throw;
            }
        }
        private void OnServerDataReceived(object sender, System.Net.Sockets.SocketAsyncEventArgs e)
        {
            if (ServerDataReceived != null)
                ServerDataReceived(this, e);
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
                    if (_sckListener != null)
                    {
                        _sckListener.Dispose();
                    }
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
