#region Directives
using System;
using System.Security.Cryptography;
using System.Threading;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Implementation Details:
// An implementation of a Jitter Queue.
// Written by John Underhill, December 3, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Queue
{
    /// <summary>
    /// <h3>JitterQueue: Adds a small amount of random delay time to a queuing operation.</h3>
    /// <para>Note v1.3: Not Tested</para>
    /// </summary>
    public sealed class JitterQueue : IDisposable
    {
        #region Fields
        private int _Count = 0;
        private bool _isDisposed = false;
        private Int16 _MaxDelay = 0;
        private byte[] _Queue;
        private int _Size = 0;
        private byte[] _Temp;
        private EventWaitHandle _evtWait;
        private RNGCryptoServiceProvider _rngCrypto;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Size">Queue size, should be a multible of cipher block size, e.g. 16 block = 1440 queue</param>
        /// <param name="MaxTime">Maximum delay time in milliseconds. Range is 1 to 65535</param>
        public JitterQueue(int Size, Int16 MaxTime)
        {
            _Size = Size;
            _MaxDelay = MaxTime;
            _Queue = new byte[Size];
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~JitterQueue()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Empty the queue
        /// </summary>
        /// 
        /// <returns>Queued values</returns>
        public byte[] DeQueue()
        {
            _Count = 0;
            return _Queue;
        }

        /// <summary>
        /// Process a partial queue size, then trigger wait
        /// </summary>
        /// 
        /// <param name="Data">Queue input</param>
        public void Final(byte[] Data)
        {
            Array.Resize<byte>(ref _Queue, _Count + Data.Length);
            Buffer.BlockCopy(Data, Data.Length, _Queue, _Count, Data.Length);
            _Count = _Size;
            Wait();

            _Count = 0;
        }

        /// <summary>
        /// Initialize the queue
        /// </summary>
        public void Initialize()
        {
            _evtWait = new AutoResetEvent(true);
        }

        /// <summary>
        /// Add data to the queue
        /// </summary>
        /// 
        /// <param name="Data">Queue input</param>
        /// 
        /// <returns>Returns true if queue is full</returns>
        public bool Queue(byte[] Data)
        {
            int len = Data.Length;

            if (_Temp != null)
            {
                Buffer.BlockCopy(_Temp, 0, _Queue, 0, _Temp.Length);
                _Count += _Temp.Length;
                _Temp = null;
                Wait();
            }

            if (len + _Count > _Size)
            {
                len = _Size - _Count;
                int tlen = Data.Length - len;
                _Temp = new byte[tlen];
                Buffer.BlockCopy(Data, len, _Temp, 0, tlen);
            }

            Buffer.BlockCopy(Data, 0, _Queue, _Count, len);
            _Count += len;

            return Wait();
        }
        #endregion

        #region Private Methods
        private void GetBytes(byte[] Data)
        {
            _rngCrypto.GetBytes(Data);
        }

        private byte[] GetByteRange(Int16 Maximum)
        {
            byte[] data;

            if (Maximum < 256)
                data = new byte[1];
            else
                data = new byte[2];

            GetBytes(data);

            return GetBits(data, Maximum);
        }

        private byte[] GetBits(byte[] Data, Int16 Maximum)
        {
            UInt16[] val = new UInt16[1];
            Buffer.BlockCopy(Data, 0, val, 0, Data.Length);
            int bits = Data.Length * 8;

            while (val[0] > Maximum && bits > 0)
            {
                val[0] >>= 1;
                bits--;
            }

            byte[] ret = new byte[Data.Length];
            Buffer.BlockCopy(val, 0, ret, 0, Data.Length);

            return ret;
        }

        private Int16 NextInt16(Int16 Maximum)
        {
            byte[] rand;
            Int16[] num = new Int16[1];

            do
            {
                rand = GetByteRange(Maximum);
                Buffer.BlockCopy(rand, 0, num, 0, rand.Length);
            } while (num[0] > Maximum);

            if (num[0] == -1)
                num[0] = 0;

            return num[0];
        }

        private bool Wait()
        {
            if (_Count >= _Size)
            {
                _evtWait.WaitOne(NextInt16(_MaxDelay));
                _Count = 0;

                return true;
            }

            return false;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class, and dependant resources
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
                    if (_Queue != null)
                    {
                        Array.Clear(_Queue, 0, _Queue.Length);
                        _Queue = null;
                    }
                    if (_Temp != null)
                    {
                        Array.Clear(_Temp, 0, _Temp.Length);
                        _Temp = null;
                    }
                    if (_evtWait != null)
                    {
                        _evtWait.Dispose();
                        _evtWait = null;
                    }
                    if (_rngCrypto != null)
                    {
                        _rngCrypto.Dispose();
                        _rngCrypto = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
