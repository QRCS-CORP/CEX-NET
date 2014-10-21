using System;

// H(K XOR opad, H(K XOR ipad, text))
namespace VTDev.Projects.CEX.CryptoGraphic
{
    internal class HMAC
    {
        private const byte IPAD = (byte)0x36;
        private const byte OPAD = (byte)0x5C;
        private readonly SHA256Digest _ShaDigest;
        private readonly int _digestSize;
        private readonly int _blockLength;
        private readonly byte[] _inputPad;
        private readonly byte[] _outputPad;

        public HMAC(SHA256Digest Hash)
        {
            this._ShaDigest = Hash;
            this._digestSize = 32;
            this._blockLength = 64;
            this._inputPad = new byte[_blockLength];
            this._outputPad = new byte[_blockLength];
        }

        public HMAC()
        {
            this._ShaDigest = new SHA256Digest();
            this._digestSize = 32;
            this._blockLength = 64;
            this._inputPad = new byte[_blockLength];
            this._outputPad = new byte[_blockLength];
        }

        public void Init(byte[] Key)
        {
            _ShaDigest.Reset();

            int keyLength = Key.Length;

            if (keyLength > _blockLength)
            {
                _ShaDigest.BlockUpdate(Key, 0, Key.Length);
                _ShaDigest.DoFinal(_inputPad, 0);

                keyLength = _digestSize;
            }
            else
            {
                Array.Copy(Key, 0, _inputPad, 0, keyLength);
            }

            Array.Clear(_inputPad, keyLength, _blockLength - keyLength);
            Array.Copy(_inputPad, 0, _outputPad, 0, _blockLength);

            xor(_inputPad, IPAD);
            xor(_outputPad, OPAD);

            // Initialise the digest
            _ShaDigest.BlockUpdate(_inputPad, 0, _inputPad.Length);
        }

        public int GetMacSize()
        {
            return _digestSize;
        }

        public void Update(byte input)
        {
            _ShaDigest.Update(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            _ShaDigest.BlockUpdate(input, inOff, len);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            byte[] tmp = new byte[_digestSize];
            _ShaDigest.DoFinal(tmp, 0);

            _ShaDigest.BlockUpdate(_outputPad, 0, _outputPad.Length);
            _ShaDigest.BlockUpdate(tmp, 0, tmp.Length);

            int len = _ShaDigest.DoFinal(output, outOff);
            // Initialise the digest
            _ShaDigest.BlockUpdate(_inputPad, 0, _inputPad.Length);

            return len;
        }

        public void Reset()
        {
            // Reset underlying digest
            _ShaDigest.Reset();
            // Initialise the digest
            _ShaDigest.BlockUpdate(_inputPad, 0, _inputPad.Length);
        }

        private static void xor(byte[] a, byte n)
        {
            for (int i = 0; i < a.Length; ++i)
                a[i] ^= n;
        }
    }
}
