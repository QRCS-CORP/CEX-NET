using System;
using System.Linq;
using VTDev.Projects.Evolution.CryptoGraphic;

namespace VTDev.Projects.Evolution.Tests
{
    class MonteCarloTest2
    {
        private int _iterations;
        private AesFastEngine _engine;
        private byte[] _key;
        private byte[] _input;
        private byte[] _output;

        public MonteCarloTest2(int Iterations, string Key, string Input, string Output)
        {
            this._key = Hex.Decode(Key);
            this._input = Hex.Decode(Input);
            this._output = Hex.Decode(Output);
            this._engine = new AesFastEngine();
            this._iterations = Iterations;
        }

        private void PerformTest()
        {
            _engine.Init(true, _key);

            byte[] outBytes = new byte[_input.Length];

            Array.Copy(_input, 0, outBytes, 0, outBytes.Length);

            for (int i = 0; i != _iterations; i++)
                _engine.ProcessBlock(outBytes, 0, outBytes, 0);

            if (!outBytes.SequenceEqual(_output))
                throw new Exception ("Arrays are not equal!");

            _engine.Init(false, _key);

            for (int i = 0; i != _iterations; i++)
                _engine.ProcessBlock(outBytes, 0, outBytes, 0);

            if (!outBytes.SequenceEqual(_input))
                throw new Exception("Arrays are not equal!");
        }
    }
}
