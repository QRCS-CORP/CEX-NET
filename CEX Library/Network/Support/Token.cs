#region Directives
using System;
using System.Globalization;
using System.Net.Sockets;
using System.Text;
#endregion

namespace Network.Support
{
    #region Delegates
    /// <summary>
    /// The process data delegate
    /// </summary>
    /// 
    /// <param name="args">The SocketAsyncEventArgs arguments</param>
    internal delegate void ProcessData(SocketAsyncEventArgs args);
    #endregion

    /// <summary>
    /// Token for use with SocketAsyncEventArgs
    /// </summary>
    internal sealed class Token : IDisposable
    {
        #region Fields
        private bool _isReady = false;
        private Socket _sckConnection;
        private byte[] _pktBuffer;
        private int _curIndex;
        private int _bfrSize;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Connection">Socket to accept incoming data.</param>
        /// <param name="BufferSize">Buffer size for accepted data.</param>
        internal Token(Socket Connection, int BufferSize)
        {
            _pktBuffer = new byte[BufferSize];
            _sckConnection = Connection;
            _bfrSize = BufferSize;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Accept socket.
        /// </summary>
        internal Socket Connection
        {
            get { return _sckConnection; }
        }

        /// <summary>
        /// Buffer is ready for reading
        /// </summary>
        internal bool IsBufferReady
        {
            get { return _isReady; }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Process data received from the client
        /// </summary>
        /// 
        /// <param name="args">SocketAsyncEventArgs used in the operation</param>
        internal byte[] ReadData(SocketAsyncEventArgs args, bool ResetBuffer = true)
        {
            byte[] buf = new byte[_curIndex];
            Array.Copy(_pktBuffer, buf, buf.Length);

            if (ResetBuffer)
                Array.Clear(_pktBuffer, 0, _curIndex);

            //args.SetBuffer(buf, 0, _curIndex);

            _curIndex = 0;
            return buf;
        }

        /// <summary>
        /// Set data received from the client
        /// </summary>
        /// 
        /// <param name="args">SocketAsyncEventArgs used in the operation</param>
        internal void SetData(SocketAsyncEventArgs args)
        {
            int count = args.BytesTransferred;

            if ((_curIndex + count) > _pktBuffer.Length)
                throw new ArgumentOutOfRangeException("count", String.Format(CultureInfo.CurrentCulture, "Adding {0} bytes on buffer which has {1} bytes, the listener buffer will overflow.", count, _curIndex));

            Array.Copy(args.Buffer, args.Offset, _pktBuffer, _curIndex, count);
            _curIndex += count;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of class resources
        /// </summary>
        public void Dispose()
        {
            try
            {
                _sckConnection.Shutdown(SocketShutdown.Send);
            }
            catch { }
            finally
            {
                _sckConnection.Close();
            }
        }
        #endregion
    }
}
