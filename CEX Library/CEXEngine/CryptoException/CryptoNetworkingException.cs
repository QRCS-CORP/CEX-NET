﻿#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.CryptoException
{
    /// <summary>
    /// Wraps exceptions thrown within a Networking operational context.
    /// <para>This exception is used in the PacketBuffer class.</para>
    /// </summary>
    public sealed class CryptoNetworkingException : Exception
    {
        /// <summary>
        /// The origin of the exception in the format Class:Method
        /// </summary>
        public string Origin { get; set; }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Message">A custom message or error data</param>
        public CryptoNetworkingException(String Message) :
            base(Message)
        {
        }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Message">A custom message or error data</param>
        /// <param name="InnerException">The underlying exception</param>
        public CryptoNetworkingException(String Message, Exception InnerException) :
            base(Message, InnerException)
        {
        }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Origin">The origin of the exception</param>
        /// <param name="Message">A custom message or error data</param>
        public CryptoNetworkingException(String Origin, String Message) :
            base(Message)
        {
            this.Origin = Origin;
        }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Origin">The origin of the exception</param>
        /// <param name="Message">A custom message or error data</param>
        /// <param name="InnerException">The underlying exception</param>
        public CryptoNetworkingException(String Origin, String Message, Exception InnerException) :
            base(Message, InnerException)
        {
            this.Origin = Origin;
        }
    }
}
