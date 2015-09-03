#region Directives
using System;
using System.Collections.Generic;
#endregion

namespace Network.Support
{
    /// <summary>
    /// An expanding buffer implementation
    /// </summary>
    internal class ReceiveBuffer
    {
        #region Fields
        private int _receiveBufferLimit;
        private int _remainingBytes;
        private List<byte> _receivedBytes;
        #endregion

        #region Properties
        /// <summary>
        /// Get/Set: The buffer size limit
        /// </summary>
        public int ReceiveBufferLimit
        {
            get { return _receiveBufferLimit; }
            set { _receiveBufferLimit = value; }
        }

        /// <summary>
        /// Get/Set: The remaining bytes in the buffer
        /// </summary>
        public int RemainingBytes 
        {
            get { return _receiveBufferLimit; }
            set { _receiveBufferLimit = value; } 
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public ReceiveBuffer(int BufferSize = 0)
        {
            ReceiveBufferLimit = 1024;
            RemainingBytes = 1024;
            _receivedBytes = new List<byte>();
        }
        #endregion

        #region Methods
        /// <summary>
        /// Add bytes to the buffer
        /// </summary>
        /// 
        /// <param name="Buffer">The buffer to add</param>
        /// <param name="Offset">The offset within the buffer</param>
        /// <param name="Count">The number of bytes to add</param>
        public void AddBytes(byte[] Buffer, int Offset, int Count)
        {
            for (int i = 0; i < Count; i++)
                _receivedBytes.Add(Buffer[Offset + i]);

            //RemainingBytes -= Count;
            //var segment = new ArraySegment<byte>(Buffer, Offset, Count);
            //_receivedBytes.AddRange(segment.Array);
        }

        /// <summary>
        /// Get the buffer as an array
        /// </summary>
        /// 
        /// <returns></returns>
        public byte[] GetArray()
        {
            return _receivedBytes.ToArray();
        }

        /// <summary>
        /// Reset the buffer
        /// </summary>
        public void Reset()
        {
            //_receivedBytes.Clear();
            _receivedBytes = new List<byte>();
        }
        #endregion
    }
}
