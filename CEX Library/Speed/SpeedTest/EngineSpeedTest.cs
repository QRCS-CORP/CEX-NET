using System;
using System.Diagnostics;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;

namespace Speed.SpeedTest
{
    public class EngineSpeedTest : ISpeedTest
    {
        #region Constants
        private const int MB1 = 1000000;
        private const int MB10 = MB1 * 10;
        private const int MB100 = MB1 * 100;
        #endregion

        #region Enums
        public enum TestTypes : int
        {
            FileIO,
            ByteIO
        }
        #endregion

        #region Events
        public delegate void SpeedDelegate(string Result);
        public event SpeedDelegate SpeedResult;
        #endregion

        #region Fields
        private int _blockSize;
        private ICipherMode _cipherEngine;
        private CipherModes _cipherType;
        private int _dataSize;
        private SymmetricEngines _engineType;
        private bool _isEncryption;
        private bool _isParallel;
        byte[] _inputBuffer;
        private KeyParams _keyParam;
        private int _keySize;
        byte[] _outputBuffer;
        private int _roundCount;
        private IStreamCipher _streamCipher;
        private TestTypes _testType;
        #endregion

        #region Constructor
        public EngineSpeedTest(SymmetricEngines Engine, CipherModes Mode, int DataSize, int KeySize, int Rounds, bool Encryption, bool Parallel, TestTypes TestType = TestTypes.FileIO)
        {
            _cipherType = Mode;
            _dataSize = DataSize;
            _roundCount = Rounds;
            _engineType = Engine;
            _isEncryption = Encryption;
            _isParallel = Parallel;
            _keySize = KeySize;
            _keyParam = GetKeyParams();
            _testType = TestType;

            if (IsStreamCipher())
            {
                _streamCipher = GetStreamEngine();
                _streamCipher.Initialize(_keyParam);

                if (_isParallel && _engineType == SymmetricEngines.ChaCha || _engineType == SymmetricEngines.Salsa)
                {
                    if (_dataSize > MB100)
                        _blockSize = MB100;
                    else if (DataSize > MB10)
                        _blockSize = MB10;
                    else if (DataSize > MB1)
                        _blockSize = MB1;
                    else
                        _blockSize = 1024;

                    // align block
                    if (_isParallel)
                        _blockSize -= (_blockSize % (64 * Environment.ProcessorCount));
                }
                else
                {
                    _blockSize = 64000;
                }
            }
            else
            {
                _cipherEngine = GetCipher();
                _cipherEngine.Initialize(_isEncryption, _keyParam);

                // set parallel
                if (_cipherEngine.GetType().Equals(typeof(CTR)))
                    ((CTR)_cipherEngine).IsParallel = _isParallel;
                else if (_cipherEngine.GetType().Equals(typeof(CBC)))
                    ((CBC)_cipherEngine).IsParallel = _isParallel;
                else if (_cipherEngine.GetType().Equals(typeof(CFB)))
                    ((CFB)_cipherEngine).IsParallel = _isParallel;

                // set block
                if (_isParallel && (_cipherType.Equals(CipherModes.CTR) || 
                    _cipherType.Equals(CipherModes.CBC) && !_isEncryption ||
                    _cipherType.Equals(CipherModes.CFB) && !_isEncryption))
                {
                    if (_dataSize > MB100)
                        _blockSize = MB100;
                    else if (DataSize > MB10)
                        _blockSize = MB10;
                    else if (DataSize > MB1)
                        _blockSize = MB1;
                    else
                        _blockSize = 1024;

                    // align block
                    if (_isParallel)
                        _blockSize -= (_blockSize % (16 * Environment.ProcessorCount));

                    if (_cipherEngine.GetType().Equals(typeof(CTR)))
                        ((CTR)_cipherEngine).ParallelBlockSize = _blockSize;
                    else if (_cipherEngine.GetType().Equals(typeof(CBC)))
                        ((CBC)_cipherEngine).ParallelBlockSize = _blockSize;
                    else if (_cipherEngine.GetType().Equals(typeof(CFB)))
                        ((CFB)_cipherEngine).ParallelBlockSize = _blockSize;
                }
                else
                {
                    _blockSize = _cipherEngine.BlockSize;
                }
            }

            _inputBuffer = new byte[_blockSize];
            _outputBuffer = new byte[_blockSize];
        }

        ~EngineSpeedTest()
        {
            if (_cipherEngine != null)
            {
                _cipherEngine.Dispose();
                _cipherEngine = null;
            }
            if (_streamCipher != null)
            {
                _streamCipher.Dispose();
                _streamCipher = null;
            }
        }
        #endregion

        #region Public
        /// <summary>
        /// Get time elapsed to encrypt a file
        /// </summary>
        /// 
        /// <returns>Elapsed milliseconds [string]</returns>
        public void Test()
        {
            string ft = @"m\:ss\.ff";
            Stopwatch runTimer = new Stopwatch();
            KeyParams keyParam = GetKeyParams();

            try
            {
                if (_testType == TestTypes.FileIO)
                {
                    string inputPath = FileGetTemp();
                    string outputPath = FileGetTemp();

                    CreateFile(inputPath);

                    if (!File.Exists(inputPath))
                    {
                        if (SpeedResult != null)
                            SpeedResult("File could not be created!");
                    }

                    if (IsStreamCipher())
                    {
                        runTimer.Start();
                        StreamCipherFileTest(inputPath, outputPath);
                        runTimer.Stop();
                    }
                    else
                    {
                        runTimer.Start();
                        BlockCipherFileTest(inputPath, outputPath);
                        runTimer.Stop();
                    }

                    DestroyFile(inputPath);
                    DestroyFile(outputPath);
                }
                else
                {
                    if (IsStreamCipher())
                    {
                        runTimer.Start();
                        StreamCipherArrayTest();
                        runTimer.Stop();
                    }
                    else
                    {
                        runTimer.Start();
                        BlockCipherArrayTest();
                        runTimer.Stop();
                    }
                }

                if (SpeedResult != null)
                    SpeedResult(TimeSpan.FromMilliseconds(runTimer.Elapsed.TotalMilliseconds).ToString(ft));
            }
            catch (Exception ex)
            {
                SpeedResult("An exception has occured! " + ex.Message);
            }
        }
        #endregion

        #region Tests
        #region Block Ciphers
        private void BlockCipherArrayTest()
        {
            int counter = 0;

            while (counter < _dataSize)
            {
                _cipherEngine.Transform(_inputBuffer, 0, _outputBuffer, 0);
                counter += _blockSize;
            }
        }

        private void BlockCipherFileTest(string InputPath, string OutputPath)
        {
            using (FileStream inputReader = new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                int bytesRead = 0;

                using (FileStream outputWriter = new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    outputWriter.SetLength(inputReader.Length);

                    while ((bytesRead = inputReader.Read(_inputBuffer, 0, _blockSize)) > 0)
                    {
                        _cipherEngine.Transform(_inputBuffer, _outputBuffer);
                        outputWriter.Write(_outputBuffer, 0, bytesRead);
                    }
                }
            }
        }
        #endregion

        #region Stream Ciphers
        private void StreamCipherArrayTest()
        {
            int remainder = _dataSize;

            while (remainder > 0)
            {
                _streamCipher.Transform(_inputBuffer, _outputBuffer);
                remainder -= _inputBuffer.Length;
            }
        }

        private void StreamCipherFileTest(string InputPath, string OutputPath)
        {
            using (FileStream inputReader = new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                int bytesRead = 0;

                using (FileStream outputWriter = new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    while ((bytesRead = inputReader.Read(_inputBuffer, 0, _inputBuffer.Length)) > 0)
                    {
                        _streamCipher.Transform(_inputBuffer, _outputBuffer);
                        outputWriter.Write(_outputBuffer, 0, bytesRead);
                    }
                }
            }
        }
        #endregion
        #endregion

        #region Helpers
        private void CreateFile(string FilePath)
        {
            byte[] data = new byte[1000];
            int ct = 0;

            for (int i = 0; i < 1000; i++)
            {
                data[i] = (byte)ct;
                if (i % 255 == 0)
                    ct = 0;

                ct++;
            }

            ct = 0;
            using (FileStream fs = new FileStream(FilePath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                while (ct < _dataSize)
                {
                    fs.Write(data, 0, data.Length);
                    ct += data.Length;
                }
            }
        }

        private void DestroyFile(string FilePath)
        {
            if (File.Exists(FilePath))
                File.Delete(FilePath);
        }

        private string FileGetTemp()
        {
            return Path.GetTempFileName();
        }

        private IBlockCipher GetBlockEngine()
        {
            if (_engineType == SymmetricEngines.RHX)
                return new RHX(16, _roundCount);
            else if (_engineType == SymmetricEngines.SHX)
                return new SHX(_roundCount);
            else if (_engineType == SymmetricEngines.THX)
                return new THX(_roundCount);
            else
                return null;
        }

        private ICipherMode GetCipher()
        {
            if (_cipherType == CipherModes.CBC)
                return new CBC(GetBlockEngine());
            else if (_cipherType == CipherModes.CFB)
                return new CFB(GetBlockEngine());
            else if (_cipherType == CipherModes.OFB)
                return new OFB(GetBlockEngine());
            else
                return new CTR(GetBlockEngine());
        }

        private IStreamCipher GetStreamEngine()
        {
            if (_engineType == SymmetricEngines.ChaCha)
                return new ChaCha();
            else if (_engineType == SymmetricEngines.Salsa)
                return new Salsa20();
            else
                return null;
        }

        private KeyParams GetKeyParams()
        {
            if (_engineType == SymmetricEngines.ChaCha)
                return new KeyGenerator().GetKeyParams(_keySize, 8);
            else if (_engineType == SymmetricEngines.Salsa)
                return new KeyGenerator().GetKeyParams(_keySize, 8);

            if (_keySize != 0)
                return new KeyGenerator().GetKeyParams(_keySize, 16);
            else if (_engineType == SymmetricEngines.RHX)
                return new KeyGenerator().GetKeyParams(_keySize, 16);
            else if (_engineType == SymmetricEngines.SHX)
                return new KeyGenerator().GetKeyParams(_keySize, 16);
            else if (_engineType == SymmetricEngines.THX)
                return new KeyGenerator().GetKeyParams(_keySize, 16);
            else
                return null;
        }

        private bool IsStreamCipher()
        {
            return _engineType == SymmetricEngines.ChaCha ||
                _engineType == SymmetricEngines.Salsa;
        }
        #endregion
    }
}
