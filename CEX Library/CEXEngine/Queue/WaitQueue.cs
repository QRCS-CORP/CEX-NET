#region Directives
using System;
using System.Diagnostics;
using System.Threading;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
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
// An implementation of a delayed Wait Queue.
// Written by John Underhill, December 3, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Queue
{
    /// <summary>
    /// <h3>WaitQueue: An implementation of a delayed Wait Queue.</h3>
    /// </summary>
    public class WaitQueue : IDisposable
    {
        #region Structs
        /// <summary>
        /// Contains high and low processing times
        /// </summary>
        public struct ProcessingTimes
        {
            /// <summary>
            /// Low order time
            /// </summary>
            public double Low;
            /// <summary>
            /// Maximum time
            /// </summary>
            public double High;
        }
        #endregion

        #region Fields
        private int _Count = 0;
        private double _Delay = 0.0;
        private double _Elapsed = 0;
        private bool _isDisposed = false;
        private byte[] _Queue;
        private int _Size = 0;
        private byte[] _Temp;
        private Stopwatch _stpWatch;
        private EventWaitHandle _evtWait;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Size">Queue size, should be a multible of cipher block size, e.g. 16 block = 1440 queue</param>
        /// <param name="CTime">Constant time value for each queue processed</param>
        public WaitQueue(int Size, double CTime)
        {
            _Size = Size;
            _Delay = CTime;
            _Queue = new byte[Size];
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~ WaitQueue()
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

            _stpWatch.Stop();
            _stpWatch.Reset();
            _Count = 0;
        }

        /// <summary>
        /// Initialize the queue
        /// </summary>
        public virtual void Initialize()
        {
            _stpWatch = new Stopwatch();
            _evtWait = new AutoResetEvent(true);
            _stpWatch.Start();
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
        private double GetElapsed()
        {
            double tms = _stpWatch.Elapsed.TotalMilliseconds;
            double cms = tms - _Elapsed;
            _Elapsed = tms;

            return cms;
        }

        private bool Wait()
        {
            if (_Count >= _Size)
            {
                int cms = (int)GetElapsed();
                if (cms > 0)
                    _evtWait.WaitOne(cms);
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
                    if (_stpWatch != null)
                    {
                        if (_stpWatch.IsRunning)
                            _stpWatch.Stop();
                        _stpWatch = null;
                    }
                    if (_evtWait != null)
                    {
                        _evtWait.Dispose();
                        _evtWait = null;
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion

        /// <summary>
        /// <h3>Test WaitQueue to calculate time threshhold measurements.</h3>
        /// </summary>
        public class SampleQueue : WaitQueue
        {
            #region Public Methods
            /// <summary>
            /// Timing samples, maximum and minimum times
            /// </summary>
            public ProcessingTimes Samples;
            #endregion

            #region Public Methods
            /// <summary>
            /// Initialize the class
            /// </summary>
            /// 
            /// <param name="Size">Size of queue</param>
            /// <param name="CTime">Not used</param>
            public SampleQueue(int Size, double CTime)
                : base(Size, CTime)
            {
                _Size = Size;
                _Delay = CTime;
                _Queue = new byte[Size];
            }
            #endregion

            #region Public Methods
            /// <summary>
            /// Initialize the queue
            /// </summary>
            public override void Initialize()
            {
                base.Initialize();
                Samples = new ProcessingTimes();
            }

            /// <summary>
            /// Add data to the queue
            /// </summary>
            /// 
            /// <param name="Data">Queue input</param>
            public void SQueue(byte[] Data)
            {
                int len = Data.Length;

                if (_Temp != null)
                {
                    Buffer.BlockCopy(_Temp, 0, _Queue, 0, _Temp.Length);
                    _Count += _Temp.Length;
                    _Temp = null;
                    if (_Count >= _Size)
                        SampleTime();
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

                SampleTime();
            }
            #endregion

            #region Private Methods
            private void SampleTime()
            {
                if (_Count >= _Size)
                {
                    double ms = GetElapsed();

                    if (Samples.Low == 0 || Samples.Low > ms)
                        Samples.Low = ms;
                    if (Samples.High == 0 || Samples.High < ms)
                        Samples.High = ms;

                    _Count = 0;
                }
            }
            #endregion
        }
    }
}
