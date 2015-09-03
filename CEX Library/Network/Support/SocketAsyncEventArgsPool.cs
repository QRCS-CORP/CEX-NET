#region Directives
using System;
using System.Collections.Generic;
using System.Net.Sockets;
#endregion

namespace Network.Support
{
    /// <summary>
    /// Represents a collection of reusable SocketAsyncEventArgs objects
    /// </summary>
    internal sealed class SocketAsyncEventArgsPool
    {
        // Pool of SocketAsyncEventArgs.
        Stack<SocketAsyncEventArgs> _stkPool;

        /// <summary>
        /// Initializes the object pool to the specified size
        /// </summary>
        /// 
        /// <param name="capacity">Maximum number of SocketAsyncEventArgs objects the pool can hold</param>
        internal SocketAsyncEventArgsPool(Int32 capacity)
        {
            _stkPool = new Stack<SocketAsyncEventArgs>(capacity);
        }

        /// <summary>
        /// Removes a SocketAsyncEventArgs instance from the pool
        /// </summary>
        /// 
        /// <returns>SocketAsyncEventArgs removed from the pool</returns>
        internal SocketAsyncEventArgs Pop()
        {
            lock (_stkPool)
            {
                if (_stkPool.Count > 0)
                    return _stkPool.Pop();
                else
                    return null;
            }
        }

        /// <summary>
        /// Add a SocketAsyncEventArg instance to the pool.
        /// </summary>
        /// 
        /// <param name="item">SocketAsyncEventArgs instance to add to the pool</param>
        internal void Push(SocketAsyncEventArgs item)
        {
            if (item == null)
                throw new ArgumentNullException("Items added to a SocketAsyncEventArgsPool cannot be null");
            
            lock (_stkPool)
            {
                _stkPool.Push(item);
            }
        }
    }
}
