#region Directives
using System;
using System.Net;
using System.Net.Sockets;
using Network.Support;
#endregion

namespace Network
{
    public sealed class TcpClient : IDisposable
    {
        #region Events
        /// <summary>
        /// The client data received delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="e">The data buffer</param>
        public delegate void ClientDataReceivedDelegate(object sender, byte[] buffer);

        /// <summary>
        /// Fires when data has been received by the client
        /// </summary>
        public event ClientDataReceivedDelegate ClientDataReceived;
        #endregion

        #region Fields
        private int _bufferSize = 256;
        private bool _isDisposed = false;
        private int _maxConnections = 10;
        private static SocketClient _sckClient;
        #endregion

        #region Properties
        public bool IsConnected
        {
            get
            {
                if (_sckClient != null)
                    return _sckClient.IsConnected;

                return false;
            }
        }
        #endregion

        #region Constructor
        public TcpClient()
        {
        }

        ~TcpClient()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Connect to a server
        /// </summary>
        /// 
        /// <param name="IP">The ip address of the server</param>
        /// <param name="Port">The target port number</param>
        public void Connect(IPAddress IP, int Port, int Timeout = -1)
        {
            try
            {
                _sckClient = new SocketClient(IP, Port, Timeout);
                _sckClient.DataReceived += new SocketClient.DataReceivedDelegate(OnClientDataReceived);
                _sckClient.Connect();
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Disconnect the client from the server
        /// </summary>
        public void Disconnect()
        {
            try
            {
                if (_sckClient != null)
                    _sckClient.Disconnect();
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Send a message to the server
        /// </summary>
        /// 
        /// <param name="Message">The message bytes</param>
        public void Send(byte[] Message)
        {
            if (_sckClient.IsConnected)
                _sckClient.SendReceive(Message);
        }
        #endregion

        #region Event Handlers
        private void OnClientDataReceived(object sender, byte[] buffer)
        {
            if (ClientDataReceived != null)
                ClientDataReceived(this, buffer);
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
                    if (_sckClient != null)
                    {
                        _sckClient.Dispose();
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
