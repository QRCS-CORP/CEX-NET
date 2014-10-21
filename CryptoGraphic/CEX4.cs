using System;

// CT = table counter
// RTM = transposition matrix
// kec = keccak or suitable
// CTR_8 builds the 8 tables for the transposition network
// DM = differential switch
// In s = 1024 ->(kec(S)) out: CT(8 * 640) + DM(8 * 128) + CM(256)
// CTR_8(CT) * 4096 (R512(Dx)) = RTM (0-7) (rotating transpositional matrix M[8,1024])

// So, in state of 1024 bytes
// state through keccak out 6400
// builds 8 table/ 1024 member matrix, each table created with R512_x(CTx)
// Diffusion matrix is 8 independant counters off of a sliding differential
// Diffusion match triggers a table re-build
// RTM(C256) out random
// ca, cb [r,c] are shuffled from 2 * 16 member uint array

namespace Evolution.CryptoGraphic
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
            UInt32[] a = new UInt32[8];
            UInt32[] b = new UInt32[8];
            byte[] Output = new byte[32];

            int ct = 0;
            int NR = 28;

            // Round 0
            a[0] = (((UInt32)Counter[0] << 24) | ((UInt32)Counter[1] << 16) | ((UInt32)Counter[2] << 8) | (UInt32)Counter[3]) ^ _TMState[0][(UInt32)Counter[0] << 24];
            a[1] = (((UInt32)Counter[4] << 24) | ((UInt32)Counter[5] << 16) | ((UInt32)Counter[6] << 8) | (UInt32)Counter[7]) ^ _TMState[1][(UInt32)Counter[4] << 16];
            a[2] = (((UInt32)Counter[8] << 24) | ((UInt32)Counter[9] << 16) | ((UInt32)Counter[10] << 8) | (UInt32)Counter[11]) ^ _TMState[2][(UInt32)Counter[8] << 8];
            a[3] = (((UInt32)Counter[12] << 24) | ((UInt32)Counter[13] << 16) | ((UInt32)Counter[14] << 8) | (UInt32)Counter[15]) ^ _TMState[3][(UInt32)Counter[12]];
            a[4] = (((UInt32)Counter[16] << 24) | ((UInt32)Counter[17] << 16) | ((UInt32)Counter[18] << 8) | (UInt32)Counter[19]) ^ _TMState[4][(UInt32)Counter[16] << 24];
            a[5] = (((UInt32)Counter[20] << 24) | ((UInt32)Counter[21] << 16) | ((UInt32)Counter[22] << 8) | (UInt32)Counter[23]) ^ _TMState[5][(UInt32)Counter[20] << 16];
            a[6] = (((UInt32)Counter[24] << 24) | ((UInt32)Counter[25] << 16) | ((UInt32)Counter[26] << 8) | (UInt32)Counter[27]) ^ _TMState[6][(UInt32)Counter[24] << 8];
            a[7] = (((UInt32)Counter[28] << 24) | ((UInt32)Counter[29] << 16) | ((UInt32)Counter[30] << 8) | (UInt32)Counter[31]) ^ _TMState[7][(UInt32)Counter[28]];

            // Round 1
            b[0] = _TMState[0][a[0] >> 24] ^ _TMState[1][(byte)(a[1] >> 16)] ^ _TMState[2][(byte)(a[2] >> 8)] ^ _TMState[3][(byte)a[3]];
            b[1] = _TMState[0][a[1] >> 24] ^ _TMState[1][(byte)(a[2] >> 16)] ^ _TMState[2][(byte)(a[3] >> 8)] ^ _TMState[3][(byte)a[4]];
            b[2] = _TMState[0][a[2] >> 24] ^ _TMState[1][(byte)(a[3] >> 16)] ^ _TMState[2][(byte)(a[4] >> 8)] ^ _TMState[3][(byte)a[5]];
            b[3] = _TMState[0][a[3] >> 24] ^ _TMState[1][(byte)(a[4] >> 16)] ^ _TMState[2][(byte)(a[5] >> 8)] ^ _TMState[3][(byte)a[6]];
            b[4] = _TMState[0][a[4] >> 24] ^ _TMState[1][(byte)(a[5] >> 16)] ^ _TMState[2][(byte)(a[6] >> 8)] ^ _TMState[3][(byte)a[7]];
            b[5] = _TMState[0][a[5] >> 24] ^ _TMState[1][(byte)(a[6] >> 16)] ^ _TMState[2][(byte)(a[7] >> 8)] ^ _TMState[3][(byte)a[0]];
            b[6] = _TMState[0][a[6] >> 24] ^ _TMState[1][(byte)(a[7] >> 16)] ^ _TMState[2][(byte)(a[0] >> 8)] ^ _TMState[3][(byte)a[1]];
            b[7] = _TMState[0][a[7] >> 24] ^ _TMState[1][(byte)(a[0] >> 16)] ^ _TMState[2][(byte)(a[1] >> 8)] ^ _TMState[3][(byte)a[2]];

            while (ct < NR)
            {
                a[0] = _TMState[0][b[0] >> 24] ^ _TMState[1][(byte)(b[1] >> 16)] ^ _TMState[2][(byte)(b[2] >> 8)] ^ _TMState[3][(byte)b[3]];
                a[1] = _TMState[0][b[1] >> 24] ^ _TMState[1][(byte)(b[2] >> 16)] ^ _TMState[2][(byte)(b[3] >> 8)] ^ _TMState[3][(byte)b[4]];
                a[2] = _TMState[0][b[2] >> 24] ^ _TMState[1][(byte)(b[3] >> 16)] ^ _TMState[2][(byte)(b[4] >> 8)] ^ _TMState[3][(byte)b[5]];
                a[3] = _TMState[0][b[3] >> 24] ^ _TMState[1][(byte)(b[4] >> 16)] ^ _TMState[2][(byte)(b[5] >> 8)] ^ _TMState[3][(byte)b[6]];
                a[4] = _TMState[0][b[4] >> 24] ^ _TMState[1][(byte)(b[5] >> 16)] ^ _TMState[2][(byte)(b[6] >> 8)] ^ _TMState[3][(byte)b[7]];
                a[5] = _TMState[0][b[5] >> 24] ^ _TMState[1][(byte)(b[6] >> 16)] ^ _TMState[2][(byte)(b[7] >> 8)] ^ _TMState[3][(byte)b[0]];
                a[6] = _TMState[0][b[6] >> 24] ^ _TMState[1][(byte)(b[7] >> 16)] ^ _TMState[2][(byte)(b[0] >> 8)] ^ _TMState[3][(byte)b[1]];
                a[7] = _TMState[0][b[7] >> 24] ^ _TMState[1][(byte)(b[0] >> 16)] ^ _TMState[2][(byte)(b[1] >> 8)] ^ _TMState[3][(byte)b[2]];

                b[0] = _TMState[4][a[0] >> 24] ^ _TMState[5][(byte)(a[1] >> 16)] ^ _TMState[6][(byte)(a[2] >> 8)] ^ _TMState[7][(byte)a[3]];
                b[1] = _TMState[4][a[1] >> 24] ^ _TMState[5][(byte)(a[2] >> 16)] ^ _TMState[6][(byte)(a[3] >> 8)] ^ _TMState[7][(byte)a[4]];
                b[2] = _TMState[4][a[2] >> 24] ^ _TMState[5][(byte)(a[3] >> 16)] ^ _TMState[6][(byte)(a[4] >> 8)] ^ _TMState[7][(byte)a[5]];
                b[3] = _TMState[4][a[3] >> 24] ^ _TMState[5][(byte)(a[4] >> 16)] ^ _TMState[6][(byte)(a[5] >> 8)] ^ _TMState[7][(byte)a[6]];
                b[4] = _TMState[4][a[4] >> 24] ^ _TMState[5][(byte)(a[5] >> 16)] ^ _TMState[6][(byte)(a[6] >> 8)] ^ _TMState[7][(byte)a[7]];
                b[5] = _TMState[4][a[5] >> 24] ^ _TMState[5][(byte)(a[6] >> 16)] ^ _TMState[6][(byte)(a[7] >> 8)] ^ _TMState[7][(byte)a[0]];
                b[6] = _TMState[4][a[6] >> 24] ^ _TMState[5][(byte)(a[7] >> 16)] ^ _TMState[6][(byte)(a[0] >> 8)] ^ _TMState[7][(byte)a[1]];
                b[7] = _TMState[4][a[7] >> 24] ^ _TMState[5][(byte)(a[0] >> 16)] ^ _TMState[6][(byte)(a[1] >> 8)] ^ _TMState[7][(byte)a[2]];
            }

            // Final Round
            Output[0] = (byte)(_TMState[0][b[0] >> 24] ^ (byte)(_TMState[7][a[7]] >> 24));
            Output[1] = (byte)(_TMState[1][(byte)(b[1] >> 16)] ^ (byte)(_TMState[6][a[6]] >> 16));
            Output[2] = (byte)(_TMState[2][(byte)(b[2] >> 8)] ^ (byte)(_TMState[5][a[5]] >> 8));
            Output[3] = (byte)(_TMState[3][(byte)b[3]] ^ (byte)_TMState[4][a[4]]);

            Output[4] = (byte)(_TMState[4][b[4] >> 24] ^ (byte)(_TMState[3][a[3]] >> 24));
            Output[5] = (byte)(_TMState[5][(byte)(b[5] >> 16)] ^ (byte)(_TMState[2][a[2]] >> 16));
            Output[6] = (byte)(_TMState[6][(byte)(b[6] >> 8)] ^ (byte)(_TMState[1][a[1]] >> 8));
            Output[7] = (byte)(_TMState[7][(byte)b[7]] ^ (byte)_TMState[0][a[0]]);

            Output[8] = (byte)(_TMState[1][b[1] >> 24] ^ (byte)(_TMState[6][a[6]] >> 24));
            Output[9] = (byte)(_TMState[2][(byte)(b[2] >> 16)] ^ (byte)(_TMState[5][a[5]] >> 16));
            Output[10] = (byte)(_TMState[3][(byte)(b[3] >> 8)] ^ (byte)(_TMState[4][a[4]] >> 8));
            Output[11] = (byte)(_TMState[4][(byte)b[4]] ^ (byte)_TMState[3][a[3]]);

            Output[12] = (byte)(_TMState[5][b[5] >> 24] ^ (byte)(_TMState[2][a[2]] >> 24));
            Output[13] = (byte)(_TMState[6][(byte)(b[6] >> 16)] ^ (byte)(_TMState[1][a[1]] >> 16));
            Output[14] = (byte)(_TMState[7][(byte)(b[7] >> 8)] ^ (byte)(_TMState[0][a[0]] >> 8));
            Output[15] = (byte)(_TMState[0][(byte)b[0]] ^ (byte)_TMState[7][a[7]]);

            Output[16] = (byte)(_TMState[2][b[2] >> 24] ^ (byte)(_TMState[5][a[5]] >> 24));
            Output[17] = (byte)(_TMState[3][(byte)(b[3] >> 16)] ^ (byte)(_TMState[4][a[4]] >> 16));
            Output[18] = (byte)(_TMState[4][(byte)(b[4] >> 8)] ^ (byte)(_TMState[3][a[3]] >> 8));
            Output[19] = (byte)(_TMState[5][(byte)b[5]] ^ (byte)_TMState[2][a[2]]);

            Output[20] = (byte)(_TMState[6][b[6] >> 24] ^ (byte)(_TMState[1][a[1]] >> 24));
            Output[21] = (byte)(_TMState[7][(byte)(b[7] >> 16)] ^ (byte)(_TMState[0][a[0]] >> 16));
            Output[22] = (byte)(_TMState[0][(byte)(b[0] >> 8)] ^ (byte)(_TMState[7][a[7]] >> 8));
            Output[23] = (byte)(_TMState[1][(byte)b[1]] ^ (byte)_TMState[6][a[6]]);

            Output[24] = (byte)(_TMState[3][b[3] >> 24] ^ (byte)(_TMState[4][a[4]] >> 24));
            Output[25] = (byte)(_TMState[4][(byte)(b[4] >> 16)] ^ (byte)(_TMState[3][a[3]] >> 16));
            Output[26] = (byte)(_TMState[5][(byte)(b[5] >> 8)] ^ (byte)(_TMState[2][a[2]] >> 8));
            Output[27] = (byte)(_TMState[6][(byte)b[6]] ^ (byte)_TMState[1][a[1]]);

            Output[28] = (byte)(_TMState[7][b[7] >> 24] ^ (byte)(_TMState[0][a[0]] >> 24));
            Output[29] = (byte)(_TMState[0][(byte)(b[0] >> 16)] ^ (byte)(_TMState[7][a[7]] >> 16));
            Output[30] = (byte)(_TMState[1][(byte)(b[1] >> 8)] ^ (byte)(_TMState[6][a[6]] >> 8));
            Output[31] = (byte)(_TMState[2][(byte)b[2]] ^ (byte)_TMState[5][a[5]]);

            return Output;
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
