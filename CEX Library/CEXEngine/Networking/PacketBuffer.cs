#region Directives
using System;
using System.Collections.Generic;
using System.IO;
using VTDev.Libraries.CEXEngine.CryptoException;
using System.Collections.Concurrent;
#endregion

namespace VTDev.Libraries.CEXEngine.Networking
{
    /// <summary>
    /// A class that contains a searchable list of packet streams
    /// </summary>
    public sealed class PacketBuffer : IDisposable
    {
        #region Fields
        private bool _isDisposed = false;
        private ConcurrentDictionary<long, MemoryStream> _pktBuffer;
        private int _queueDepth;
        private object _threadLock = new object();
        #endregion

        #region Properties
        /// <summary>
        /// Get: The number of packet streams in the buffer
        /// </summary>
        public int Count
        {
            get 
            { 
                if (_pktBuffer != null)
                    return _pktBuffer.Count;
                else
                    return 0;
            }
        }

        /// <summary>
        /// Get/Set: The size of the buffer queue
        /// </summary>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if the queue depth is less than 1</exception>
        public int Depth
        {
            get { return _queueDepth; }
            set 
            {
                if (value < 1)
                    throw new CryptoNetworkingException("PacketBuffer:Depth", "Depth can not be less than 1!", new ArgumentException());

                _queueDepth = value; 
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="QueueDepth">The maximum queue depth</param>
        public PacketBuffer(int QueueDepth)
        {
            _queueDepth = QueueDepth;
            _pktBuffer = new ConcurrentDictionary<long, MemoryStream>();
        }

        private PacketBuffer()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~PacketBuffer()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Clear the buffer, disposing of each element
        /// </summary>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if the clearing the queue produced an error</exception>
        public void Clear()
        {
            try
            {
                if (_pktBuffer != null)
                {
                    List<MemoryStream> vals = new List<MemoryStream>(_pktBuffer.Values);

                    foreach (MemoryStream pkt in vals)
                    {
                        if (pkt != null)
                            pkt.Dispose();
                    }

                    _pktBuffer.Clear();
                }
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Remove and Dispose of a packet stream from the buffer
        /// </summary>
        /// 
        /// <param name="Sequence">The packet sequence number</param>
        /// 
        /// <returns>Returns true if the packet was destroyed, otherwise false</returns>
        public bool Destroy(long Sequence)
        {
            try
            {
                MemoryStream pkt = Peek(Sequence);

                if (Remove(Sequence))
                {
                    if (pkt != null)
                        pkt.Dispose();

                    return true;
                }
            }
            catch
            {
                throw;
            }

            return false;
        }

        /// <summary>
        /// Check if the buffer contains a packet with this key
        /// </summary>
        /// 
        /// <param name="Sequence">The packet sequence number</param>
        /// 
        /// <returns>Returns <c>true</c> if the key exists, otherwise <c>false</c></returns>
        public bool Exists(long Sequence)
        {
            return _pktBuffer == null ? false : _pktBuffer.ContainsKey(Sequence);
        }

        /// <summary>
        /// Get the key with the lowest sequence number
        /// </summary>
        /// 
        /// <returns>The lowest key, or -1 for empty</returns>
        public long GetHighKey()
        {
            long lstSeq = -1;

            lock (_threadLock)
            {
                List<long> keys = new List<long>(_pktBuffer.Keys);

                foreach (long key in keys)
                {
                    if (key > lstSeq)
                        lstSeq = key;
                }
            }

            return lstSeq;
        }

        /// <summary>
        /// Get the key with the highest sequence number
        /// </summary>
        /// 
        /// <returns>The highest key, or -1 for empty</returns>
        public long GetLowKey()
        {
            long lstSeq = long.MaxValue;

            lock (_threadLock)
            {
                List<long> keys = new List<long>(_pktBuffer.Keys);

                foreach (long key in keys)
                {
                    if (key < lstSeq)
                        lstSeq = key;
                }
            }

            if (lstSeq == long.MaxValue)
                return -1;
            else
                return lstSeq;
        }

        /// <summary>
        /// Return the packet stream with the specified sequence number
        /// </summary>
        /// 
        /// <param name="Sequence">The packet sequence number</param>
        /// 
        /// <returns>Returns the packet stream, or if not found, an empty MemoryStream object</returns>
        public MemoryStream Peek(long Sequence)
        {
            MemoryStream pkt = null;

            if (Exists(Sequence))
            {
                _pktBuffer.TryGetValue(Sequence, out pkt);

                if (pkt.Position != 0)
                    pkt.Seek(0, SeekOrigin.Begin);
            }

            return pkt;
        }

        /// <summary>
        /// Return the packet stream with the specified sequence number and removes it from the buffer
        /// </summary>
        /// 
        /// <param name="Sequence">The packet sequence number</param>
        /// 
        /// <returns>Returns the packet stream, or if not found, an empty MemoryStream object</returns>
        public MemoryStream Pop(long Sequence)
        {
            MemoryStream pkt = new MemoryStream();

            if (Exists(Sequence))
            {
                if (_pktBuffer.TryGetValue(Sequence, out pkt))
                    Remove(Sequence);

                if (pkt.Position != 0)
                    pkt.Seek(0, SeekOrigin.Begin);
            }

            return pkt;
        }

        /// <summary>
        /// Returns the position of a packet within the buffer, <c>-1</c> is returned if the sequence number can not be found
        /// </summary>
        /// 
        /// <param name="Sequence">The packet sequence number</param>
        /// 
        /// <returns>Returns the index of the packet within the buffer, or if not found, returns the value <c>-1</c></returns>
        public int Position(long Sequence)
        {
            if (!Exists(Sequence))
                return -1;

            int count = 0;

            lock (_threadLock)
            {
                List<long> keys = new List<long>(_pktBuffer.Keys);
                foreach (var key in keys)
                {
                    if (Sequence.Equals(key))
                        return count;

                    count++;
                }
            }

            return -1;
        }
        
        /// <summary>
        /// Add a packet stream to the buffer.
        /// <para>If a packet is added and the buffer size exceeds the Queue Depth, 
        /// the packet with the lowest sequence number is removed</para>
        /// </summary>
        /// 
        /// <param name="Sequence">The packet sequence number</param>
        /// <param name="Packet">The packet stream</param>
        public void Push(long Sequence, MemoryStream Packet)
        {
            if (_pktBuffer == null)
                return;

            if (Packet.Position != 0)
                Packet.Seek(0, SeekOrigin.Begin);

            // remove first in queue
            if (_pktBuffer.Count > _queueDepth)
            {
                long fstSeq = GetLowKey();

                if (fstSeq > -1)
                    Remove(fstSeq);
            }

            // possible resend
            if (Exists(Sequence))
                Remove(Sequence);

            _pktBuffer.TryAdd(Sequence, Packet);
        }

        /// <summary>
        /// Remove a packet stream from the buffer
        /// </summary>
        /// 
        /// <param name="Sequence">The packet sequence number</param>
        /// 
        /// <returns>Returns true if the packet was removed, otherwise false</returns>
        public bool Remove(long Sequence)
        {
            if (_pktBuffer == null)
                return false;
            else if (_pktBuffer.Count < 1)
                return false;

            MemoryStream pkt =  null;
            _pktBuffer.TryRemove(Sequence, out pkt);

            if (pkt != null)
                return true;

            return false;
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
                    if (_pktBuffer != null)
                    {
                        Clear();
                        _pktBuffer = null;
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
