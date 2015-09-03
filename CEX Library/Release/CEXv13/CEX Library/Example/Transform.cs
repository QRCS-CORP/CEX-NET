using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Padding;
using VTDev.Projects.CEX.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Helper;

namespace VTDev.Projects.CEX
{
    /// <summary>
    /// Encryption/Decryption wrapper
    /// </summary>
    internal class Transform : IDisposable
    {
        #region Constants
        private const int DCS_BLOCK = 10240;
        private const int PRG_INTV = 4096;
        private const int MAX_SIGNED = 1000000;
        #endregion

        #region Events
        internal delegate void ProgressCounterDelegate(int Count);
        internal event ProgressCounterDelegate ProgressCounter;
        #endregion

        #region Properties
        private Engines Engine { get; set; }
        internal int BlockSize { get; set; }
        private CipherModes CipherMode { get; set; }
        private long FileSize { get; set; }
        private byte[] IV { get; set; }
        private byte[] Key { get; set; }
        private string KeyPath { get; set; }
        private KeySizes KeySize { get; set; }
        private bool IsEncryption { get; set; }
        internal bool IsParallel { get; set; }
        internal bool IsSigned { get; set; }
        private PaddingModes PaddingMode { get; set; }
        private long ProgressInterval { get; set; }
        private RoundCounts RoundCount { get; set; }
        #endregion

        #region Fields
        private IBlockCipher BlockCipher;
        private ICipherMode Mode;
        private IPadding Padding;
        private IStreamCipher StreamCipher;
        private bool _isDisposed = false;
        #endregion

        #region Constructor
        internal Transform(string KeyPath)
        {
            if (!File.Exists(KeyPath)) return;
            // get key and algorithm
            this.ProgressInterval = PRG_INTV;
            this.KeyPath = KeyPath;
            this.Engine = KeyHeader.GetEngineType(KeyPath);
            this.Key = GetKey(KeyPath);
            int rounds = GetRoundsSize(KeyPath);

            // stream ciphers
            if (this.Engine == Engines.ChaCha)
                StreamCipher = new ChaCha(rounds);
            else if (this.Engine == Engines.DCS)
                StreamCipher = new DCS();
            if (this.Engine == Engines.Salsa)
                StreamCipher = new Salsa20(rounds);
            if (this.Engine == Engines.Fusion)
                StreamCipher = new Fusion(rounds);

            this.BlockSize = 64;

            // get iv
            if (this.Engine != Engines.DCS )
                this.IV = GetIV(KeyPath);
            else
                this.BlockSize = (DCS_BLOCK * 4);

            // dcs, chacha and salsa are stream ciphers
            if (this.Engine == Engines.DCS || this.Engine == Engines.ChaCha || this.Engine == Engines.Salsa || this.Engine == Engines.Fusion)
                return;

            this.IsParallel = Environment.ProcessorCount > 1;

            // set params from key data
            this.BlockSize = KeyHeader.GetBlockSize(KeyPath) == BlockSizes.B128 ? 16 : 32;
            this.CipherMode = KeyHeader.GetCipherType(KeyPath);
            this.PaddingMode = KeyHeader.GetPaddingType(KeyPath);

            // block size
            if (this.IV != null && this.IV.Length > 0)
                this.BlockSize = this.IV.Length;
            else
                this.CipherMode = CipherModes.ECB;

            // padding selection
            if (this.PaddingMode == PaddingModes.PKCS7)
                Padding = new PKCS7();
            else if (this.PaddingMode == PaddingModes.X923)
                Padding = new X923();
            else if (this.PaddingMode == PaddingModes.Zeros)
                Padding = new ZeroPad();

            // create engine
            if (this.Engine == Engines.RDX)
                this.BlockCipher = new RDX(this.BlockSize);
            else if (this.Engine == Engines.RSM)
                this.BlockCipher = new RSM(rounds, this.BlockSize);
            else if (this.Engine == Engines.RSX)
                this.BlockCipher = new RSX(this.BlockSize);
            else if (this.Engine == Engines.RHX)
                this.BlockCipher = new RHX(rounds, this.BlockSize);
            else if (this.Engine == Engines.SPX)
                this.BlockCipher = new SPX(rounds);
            else if (this.Engine == Engines.SHX)
                this.BlockCipher = new SHX(rounds);
            else if (this.Engine == Engines.TFX)
                this.BlockCipher = new TFX(rounds);
            else if (this.Engine == Engines.THX)
                this.BlockCipher = new THX(rounds);
            else if (this.Engine == Engines.TSM)
                this.BlockCipher = new TSM(rounds);

            // create cipher
            if (this.CipherMode == CipherModes.CBC)
                this.Mode = new CBC(this.BlockCipher);
            else if (this.CipherMode == CipherModes.CTR)
                this.Mode = new CTR(this.BlockCipher);
            else if (this.CipherMode == CipherModes.ECB)
                this.Mode = new ECB(this.BlockCipher);
        }
        #endregion

        #region Public Methods
        internal void Decrypt(string InputPath, string OutputPath)
        {
            this.FileSize = GetFileSize(InputPath);
            CalculateInterval();
            this.IsEncryption = false;

            if (this.Engine == Engines.ChaCha || this.Engine == Engines.DCS || this.Engine == Engines.Salsa || this.Engine == Engines.Fusion)
            {
                // stream cipher
                ProcessStream(InputPath, OutputPath);
            }
            else
            {
                // init block cipher
                this.Mode.Init(false, new KeyParams(this.Key, this.IV));

                if (this.Mode.Name == "CTR" && this.IsParallel)
                    ParallelCTR(InputPath, OutputPath);
                else if (this.Mode.Name == "CBC" && this.IsParallel)
                    ParallelCBC(InputPath, OutputPath);
                else
                    DecryptFile(InputPath, OutputPath);
            }
        }

        internal void Encrypt(string InputPath, string OutputPath)
        {
            byte[] hashKey = KeyHeader.GetMessageKey(this.KeyPath);
            byte[] checkSum = new byte[64];
            MemoryStream header = new MemoryStream(MessageHeader.Create(this.KeyPath, Path.GetExtension(InputPath), checkSum));

            this.FileSize = GetFileSize(InputPath);
            this.IsEncryption = true;

            //calculate progress interval
            CalculateInterval();

            if (this.Engine == Engines.ChaCha || this.Engine == Engines.DCS || this.Engine == Engines.Salsa || this.Engine == Engines.Fusion)
            {
                // stream cipher
                ProcessStream(InputPath, OutputPath, header);
            }
            else
            {
                // init block cipher
                this.Mode.Init(true, new KeyParams(this.Key, this.IV));
                if (this.Mode.Name == "CTR" && this.IsParallel)
                    ParallelCTR(InputPath, OutputPath, header);
                else
                    EncryptFile(InputPath, OutputPath, header);
            }

            // create checksum and sign
            checkSum = GetChecksum(OutputPath, hashKey);
            MessageHeader.SetMessageHash(OutputPath, checkSum);
        }
        #endregion

        #region Stream Ciphers
        private void ProcessStream(string InputPath, string OutputPath, MemoryStream Header = null)
        {
            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                int blockSize = (DCS_BLOCK * 4);
                long bytesRead = 0;
                long bytesTotal = 0;

                if (inputReader.BaseStream.Length < blockSize)
                    blockSize = (int)inputReader.BaseStream.Length;

                using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None)))
                {
                    byte[] inputBuffer = new byte[blockSize];
                    byte[] outputBuffer = new byte[blockSize];

                    if (Header != null)
                        outputWriter.Write(Header.ToArray());
                    else
                        inputReader.BaseStream.Position = MessageHeader.GetHeaderSize;

                    // initialize the cipher
                    StreamCipher.Init(new KeyParams(this.Key, this.IV));

                    // loop through file
                    while ((bytesRead = inputReader.Read(inputBuffer, 0, blockSize)) == blockSize)
                    {
                        StreamCipher.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer);
                        bytesTotal += bytesRead;

                        if (bytesTotal % this.ProgressInterval == 0)
                            CalculateProgress(bytesTotal);
                    }
                    // last block
                    if (bytesRead > 0)
                    {
                        outputBuffer = new byte[bytesRead];
                        StreamCipher.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer);
                        CalculateProgress(bytesTotal + bytesRead);
                    }
                }
            }
        }
        #endregion

        #region Block Ciphers
        private void DecryptFile(string InputPath, string OutputPath)
        {
            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                byte[] inputBuffer = new byte[this.BlockSize];
                byte[] outputBuffer = new byte[this.BlockSize];
                long bytesRead = 0;
                long bytesTotal = 0;

                // move past header
                inputReader.BaseStream.Position = MessageHeader.GetHeaderSize;

                using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None)))
                {
                    int maxOut = (int)inputReader.BaseStream.Length - MessageHeader.GetHeaderSize;

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, this.BlockSize)) > 0)
                    {
                        bytesTotal += bytesRead;

                        if (bytesTotal < maxOut)
                        {
                            this.Mode.Transform(inputBuffer, outputBuffer);
                            outputWriter.Write(outputBuffer);

                            if (bytesTotal % this.ProgressInterval == 0)
                                CalculateProgress(bytesTotal);
                        }
                        else
                        {
                            this.Mode.Transform(inputBuffer, outputBuffer);
                            int size = this.BlockSize - Padding.GetPaddingLength(outputBuffer);
                            outputWriter.Write(outputBuffer, 0, size);
                            CalculateProgress(bytesTotal + size);
                        }
                    }
                }
            }
        }

        private void EncryptFile(string InputPath, string OutputPath, MemoryStream Header)
        {
            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                byte[] inputBuffer = new byte[this.BlockSize];
                byte[] outputBuffer = new byte[this.BlockSize];
                long bytesRead = 0;
                long bytesTotal = 0;

                using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None)))
                {
                    // write message header
                    outputWriter.Write(Header.ToArray());

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, this.BlockSize)) == this.BlockSize)
                    {
                        this.Mode.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer);
                        bytesTotal += bytesRead;

                        if (bytesTotal % this.ProgressInterval == 0)
                            CalculateProgress(bytesTotal);
                    }

                    if (bytesRead > 0)
                    {
                        if (bytesRead < this.BlockSize)
                            Padding.AddPadding(inputBuffer, (int)bytesRead);

                        this.Mode.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer);
                        CalculateProgress(bytesTotal + bytesRead);
                    }
                }
            }
        }

        private void ParallelCBC(string InputPath, string OutputPath)
        {
            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                int blockSize = ((CBC)this.Mode).ParallelMinimumSize;
                long bytesRead = 0;
                long bytesTotal = 0;

                if (inputReader.BaseStream.Length < blockSize)
                    blockSize = (int)inputReader.BaseStream.Length;

                using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None)))
                {
                    byte[] inputBuffer = new byte[blockSize];
                    byte[] outputBuffer = new byte[blockSize];

                    inputReader.BaseStream.Position = MessageHeader.GetHeaderSize;

                    // large blocks
                    while ((bytesRead = inputReader.Read(inputBuffer, 0, blockSize)) == blockSize)
                    {
                        this.Mode.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer);
                        bytesTotal += bytesRead;

                        if (bytesTotal % this.ProgressInterval == 0)
                            CalculateProgress(bytesTotal);
                    }

                    // last blocks
                    if (bytesRead > 0)
                    {
                        outputBuffer = new byte[bytesRead];
                        int count = 0;

                        while (count < bytesRead)
                        {
                            this.Mode.Transform(inputBuffer, count, outputBuffer, count);
                            // remove padding
                            if (count > bytesRead - (this.BlockSize + 1))
                            {
                                int size = this.BlockSize - Padding.GetPaddingLength(outputBuffer, count);
                                outputWriter.Write(outputBuffer, count, size);
                            }
                            else
                            {
                                outputWriter.Write(outputBuffer, count, this.BlockSize);
                            }
                            count += this.BlockSize;
                        }

                        CalculateProgress(bytesTotal + bytesRead);
                    }
                }
            }
        }

        private void ParallelCTR(string InputPath, string OutputPath, MemoryStream Header = null)
        {
            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                // block must be divisible of 1024
                int blockSize = CalculateBlockSize();
                long bytesRead = 0;
                long bytesTotal = 0;

                if (inputReader.BaseStream.Length < blockSize)
                    blockSize = (int)inputReader.BaseStream.Length;

                using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None)))
                {
                    byte[] inputBuffer = new byte[blockSize];
                    byte[] outputBuffer = new byte[blockSize];

                    if (Header != null)
                        outputWriter.Write(Header.ToArray());
                    else
                        inputReader.BaseStream.Position = MessageHeader.GetHeaderSize;

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, blockSize)) == blockSize)
                    {
                        this.Mode.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer);
                        bytesTotal += bytesRead;

                        if (bytesTotal % this.ProgressInterval == 0)
                            CalculateProgress(bytesTotal);
                    }

                    if (bytesRead > 0)
                    {
                        outputBuffer = new byte[blockSize];
                        this.Mode.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer, 0, (int)bytesRead);
                        CalculateProgress(bytesTotal + bytesRead);
                    }
                }
            }
        }
        #endregion

        #region Message Authentication
        /// <summary>
        /// Returns the SHA512 HMAC hash for the file
        /// </summary>
        /// <param name="FilePath">Path to input file</param>
        /// <param name="HashKey">HMAC key</param>
        /// <returns>Computed hash value [byte[]]</returns>
        internal byte[] GetChecksum(string FilePath, byte[] HashKey)
        {
            using (SHA512HMAC hmac = new SHA512HMAC(HashKey))
            {
                int blockSize = hmac.BlockSize;
                int bytesTotal = 0;
                byte[] buffer = new byte[blockSize];
                byte[] chkSum = new byte[hmac.DigestSize];

                using (BinaryReader inputReader = new BinaryReader(new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.None)))
                {
                    // start of file bytes
                    inputReader.BaseStream.Position = MessageHeader.GetHeaderSize;
                    int bytesRead = 0;

                    // read into mac
                    while ((bytesRead = inputReader.Read(buffer, 0, blockSize)) == blockSize)
                    {
                        hmac.BlockUpdate(buffer, 0, bytesRead);
                        bytesTotal += bytesRead;

                        if (bytesTotal > MAX_SIGNED)
                            break;
                    }

                    // last block
                    if (bytesRead > 0)
                        hmac.BlockUpdate(buffer, 0, bytesRead);

                    // get the hash
                    hmac.DoFinal(chkSum, 0);
                }

                return chkSum;
            }
        }

        /// <summary>
        /// Verify the hash value for a file
        /// </summary>
        /// <param name="InputPath">Encrypted file path</param>
        /// <param name="OutputPath">Decrypted file path</param>
        /// <param name="KeyPath">Full path to key file</param>
        /// <returns>Verified [bool]</returns>
        internal bool Verify(string InputPath, string KeyPath)
        {
            byte[] hashKey = KeyHeader.GetMessageKey(KeyPath);
            byte[] msgHash = MessageHeader.GetMessageHash(InputPath);
            byte[] hash = GetChecksum(InputPath, hashKey);

            return IsEqual(msgHash, hash);
        }
        #endregion

        #region Helpers
        private int CalculateBlockSize()
        {
            if (this.Mode.Name == "CTR" && this.FileSize >= ((CTR)this.Mode).ParallelMinimumSize)
            {
                if (this.FileSize > ((CTR)this.Mode).ParallelMaximumSize)
                    return ((CTR)this.Mode).ParallelMaximumSize;
                else
                    return ((CTR)this.Mode).ParallelMinimumSize;
            }
            else if (this.Mode.Name == "CBC" && this.IsEncryption == false && this.FileSize >= ((CTR)this.Mode).ParallelMinimumSize)
            {
                if (this.FileSize > ((CTR)this.Mode).ParallelMaximumSize)
                    return ((CTR)this.Mode).ParallelMaximumSize;
                else
                    return ((CTR)this.Mode).ParallelMinimumSize;
            }
            else
            {
                return this.BlockSize;
            }
        }

        private void CalculateInterval()
        {
            if (this.Engine == Engines.DCS)
            {
                this.ProgressInterval = PRG_INTV;
            }
            else
            {
                long interval = this.FileSize / 100;

                if (interval == 0)
                    this.ProgressInterval = this.FileSize;
                else
                    this.ProgressInterval = interval - (interval % this.BlockSize);

                if (this.ProgressInterval == 0)
                    this.ProgressInterval = this.FileSize;
            }
        }

        private void CalculateProgress(long Count)
        {
            if (ProgressCounter != null)
            {
                double progress = 100.0 * (double)Count / this.FileSize;
                ProgressCounter((int)progress);
            }
        }

        private long GetFileSize(string FilePath)
        {
            try
            {
                return File.Exists(FilePath) ? new FileInfo(FilePath).Length : 0;
            }
            catch { }
            return -1;
        }

        private byte[] GetKey(string KeyPath)
        {
            int size = GetKeySize(KeyPath);
            byte[] key = new byte[size];

            using (BinaryReader inputReader = new BinaryReader(new FileStream(KeyPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                inputReader.BaseStream.Position = KeyHeader.GetHeaderSize;
                key = inputReader.ReadBytes(size);
            }

            return key;
        }

        private int GetKeySize(string KeyPath)
        {
            KeySizes keySize = KeyHeader.GetKeySize(KeyPath);

            if (this.Engine == Engines.DCS)
                return 96;

            if (keySize == KeySizes.K128)
                return 16;
            else if (keySize == KeySizes.K192)
                return 24;
            else if (keySize == KeySizes.K192)
                return 24;
            else if (keySize == KeySizes.K256)
                return 32;
            else if (keySize == KeySizes.K384)
                return 48;
            else if (keySize == KeySizes.K448)
                return 56;
            else if (keySize == KeySizes.K512)
                return 64;
            else if (keySize == KeySizes.K1024)
                return 128;
            else if (keySize == KeySizes.K1536)
                return 192;
            else if (keySize == KeySizes.K2560)
                return 320;
            else if (keySize == KeySizes.K3584)
                return 448;
            else if (keySize == KeySizes.K4608)
                return 576;
            else
                return 32;
        }

        private byte[] GetIV(string KeyPath)
        {
            int ivSize = GetIvSize(KeyPath);
            int keySize = GetKeySize(KeyPath);
            byte[] iv = new byte[ivSize];

            using (BinaryReader inputReader = new BinaryReader(new FileStream(KeyPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                int pos = KeyHeader.GetHeaderSize + keySize;
                if (pos > inputReader.BaseStream.Length)
                    return null;

                inputReader.BaseStream.Position = pos;
                iv = inputReader.ReadBytes(ivSize);
            }

            return iv;
        }

        private int GetIvSize(string KeyPath)
        {
            IVSizes ivSize = KeyHeader.GetIvSize(KeyPath);

            if (ivSize == IVSizes.V128)
                return 16;
            else if (ivSize == IVSizes.V256)
                return 32;
            else
                return 8;
        }

        private int GetRoundsSize(string KeyPath)
        {
            this.RoundCount = KeyHeader.GetRoundCount(KeyPath);

            if (this.RoundCount == RoundCounts.R8)
                return 8;
            else if (this.RoundCount == RoundCounts.R10)
                return 10;
            else if (this.RoundCount == RoundCounts.R12)
                return 12;
            else if (this.RoundCount == RoundCounts.R14)
                return 14;
            else if (this.RoundCount == RoundCounts.R16)
                return 16;
            else if (this.RoundCount == RoundCounts.R18)
                return 18;
            else if (this.RoundCount == RoundCounts.R20)
                return 20;
            else if (this.RoundCount == RoundCounts.R22)
                return 22;
            else if (this.RoundCount == RoundCounts.R24)
                return 24;
            else if (this.RoundCount == RoundCounts.R26)
                return 26;
            else if (this.RoundCount == RoundCounts.R28)
                return 28;
            else if (this.RoundCount == RoundCounts.R30)
                return 30;
            else if (this.RoundCount == RoundCounts.R32)
                return 32;
            else if (this.RoundCount == RoundCounts.R34)
                return 34;
            else if (this.RoundCount == RoundCounts.R38)
                return 38;
            else if (this.RoundCount == RoundCounts.R40)
                return 40;
            else if (this.RoundCount == RoundCounts.R42)
                return 42;
            else if (this.RoundCount == RoundCounts.R48)
                return 48;
            else if (this.RoundCount == RoundCounts.R56)
                return 56;
            else if (this.RoundCount == RoundCounts.R64)
                return 64;
            else if (this.RoundCount == RoundCounts.R80)
                return 80;
            else if (this.RoundCount == RoundCounts.R96)
                return 96;
            else if (this.RoundCount == RoundCounts.R128)
                return 128;
            else
                return 20;
        }

        internal static bool IsEqual(byte[] a, byte[] b)
        {
            int i = a.Length;

            if (i != b.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (a[i] != b[i])
                    return false;
            }

            return true;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        void IDisposable.Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {

                // destroys cipher and engine
                if (this.Mode != null)
                    this.Mode.Dispose();

                if (this.StreamCipher != null)
                    StreamCipher.Dispose();

                if (this.Key != null)
                {
                    Array.Clear(this.Key, 0, this.Key.Length);
                    this.Key = null;
                }
                if (this.IV != null)
                {
                    Array.Clear(this.IV, 0, this.IV.Length);
                    this.IV = null;
                }
                _isDisposed = true;
            }
        }
        #endregion
    }
}
