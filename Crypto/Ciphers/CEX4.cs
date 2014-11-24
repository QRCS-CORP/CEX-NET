using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace VTDev.Projects.Evolution.CryptoGraphic.Algorithms
{
    public class CEX4 : IDisposable
    {
        #region Fields
        private bool _Disposed = false;
        private UInt32[][] _TMState;
        private Int32[] _TDS;
        #endregion

        public CEX4(byte[] Seed)
        {

            TSA(Seed);
        }

        public byte[] Transform(byte[] Input)
        {
            // data in
            // produce p-rand via RTM
            // mix with input
            return null;
        }

        /// <summary>
        /// Traspositional State Assembler
        /// </summary>
        /// <param name="Seed"></param>
        private UInt32[][] TSA(byte[] Seed)
        {
            // build 8 * 1024 uint tables with R_Kx(Cx)
            _TMState = new UInt32[8][];

            // build the 8 * 128 counter array
            _TDS = new Int32[8];

            return null;
        }

        /// <summary>
        /// Differential Manager
        /// </summary>
        /// <param name="Counter"></param>
        private void DM(byte[] Counter)
        {

        }

        /// <summary>
        /// Rotating Transpositional Matrix diffusion algorithm
        /// </summary>
        /// <param name="Counter"></param>
        private byte[] RTM(byte[] Counter)
        {
            byte[] outputMatrix = new byte[128];
            return outputMatrix;
        }

        /// <summary>
        /// Entropy Pool Collector
        /// </summary>
        /// <param name="State"></param>
        /// <returns></returns>
        private byte[] EPC(byte[] State)
        {
            return null;
        }

        #region IDispose
        public void Dispose()
        {
            Dispose(true);
        }

        void IDisposable.Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!_Disposed)
            {
                if (disposing)
                {

                }
                _Disposed = true;
            }
        }
        #endregion
    }
}
