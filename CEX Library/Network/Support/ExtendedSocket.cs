using System;
using System.Net;
using System.Net.Sockets;

namespace Network.Support
{
    internal sealed class ExtendedSocket : IDisposable
    {
        private Socket _socket;
        private int _bufferSize;

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

        internal ExtendedSocket(IPAddress IP, int Port, int BufferSize = 256, int TimeOut = -1)
        {
            // Instances a socket
            IPEndPoint hostEP = new IPEndPoint(IP, Port);//addressList[addressList.Length - 1]
            _socket = new Socket(hostEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            _bufferSize = BufferSize;
            // Defines time-out
            _socket.SendTimeout = TimeOut;
            _socket.ReceiveTimeout = TimeOut;

            // Open a connection
            _socket.Connect(hostEP);
        }

        internal void Send(byte[] Buffer)
        {
            byte[] rcdBuffer = null;

            int bytesSent = _socket.Send(Buffer);

            if (bytesSent > 0)
            {
                // Recieve the response from a listener.
                byte[] retBuffer = new byte[_bufferSize];
                int rcdBytes = _socket.Receive(retBuffer);

                rcdBuffer = new byte[rcdBytes];
                Array.Copy(retBuffer, 0, rcdBuffer, 0, rcdBytes);

                if (DataReceived != null && rcdBuffer.Length > 0)
                    DataReceived(this, rcdBuffer);
            }
        }

        #region IDisposable Members

        public void Dispose()
        {
            if (this._socket != null)
            {
                try
                {
                    if (_socket.Connected)
                        _socket.Shutdown(SocketShutdown.Both);
                }
                finally
                {
                    _socket.Close();
                }
            }
        }

        #endregion
    }
}
