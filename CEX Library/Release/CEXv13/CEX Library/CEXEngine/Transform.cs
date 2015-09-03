using System.IO;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Ciphers;
using VTDev.Libraries.CEXEngine.Crypto.Helpers;
using VTDev.Libraries.CEXEngine.Crypto.Macs;
using VTDev.Libraries.CEXEngine.Crypto.Modes;
using VTDev.Libraries.CEXEngine.Crypto.Padding;

namespace VTDev.Libraries.CEXEngine
{
    /// <summary>
    /// Wrapper for encryption methods
    /// </summary>
    public class Transform
    {
        #region Constants
        private const int DCS_BLOCK = 10240;
        private const int PRG_INTV = 4096;
        private const int MAX_SIGNED = 1000000;
        #endregion

        #region Events
        public delegate void ProgressCounterDelegate(int count);
        public event ProgressCounterDelegate ProgressCounter;
        #endregion

        #region Properties
        public int BlockSize { get; private set; }
        public bool IsParallel { get; set; }
        public bool IsSigned { get; set; }
        private bool IsStream { get; set; }
        private long FileSize { get; set; }
        private bool IsEncryption { get; set; }
        private PaddingModes PaddingMode { get; set; }
        private long ProgressInterval { get; set; }
        #endregion

        #region Fields
        private IBlockCipher BlockCipher;
        private ICipherMode CipherMode;
        private IPadding Padding;
        private IStreamCipher StreamCipher;
        private KeyParams KeyParam;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class as a Stream Cipher
        /// </summary>
        /// <param name="Cipher">Stream Cipher instance</param>
        /// <param name="KeyParam">Key and vector material</param>
        public Transform(IStreamCipher Cipher, KeyParams KeyParam)
        {
            this.KeyParam = KeyParam;
            this.StreamCipher = Cipher;
            this.IsStream = true;
        }

        /// <summary>
        /// Initialize the class as a Block Cipher
        /// </summary>
        /// <param name="Cipher">Block Cipher instance</param>
        /// <param name="KeyParam">Key and vector material</param>
        /// <param name="Mode">Cipher mode</param>
        /// <param name="Padding">Padding type</param>
        public Transform(IBlockCipher Cipher, KeyParams KeyParam, CipherModes Mode = CipherModes.CTR, PaddingModes Padding = PaddingModes.X923)
        {
            this.KeyParam = KeyParam;

            if (Mode == CipherModes.CBC)
                this.CipherMode = new CBC(Cipher);
            else
                this.CipherMode = new CTR(Cipher);

            if (Padding == PaddingModes.PKCS7)
                this.Padding = new PKCS7();
            else if (Padding == PaddingModes.X923)
                this.Padding = new X923();

            this.IsStream = false;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a file
        /// </summary>
        /// <param name="InputPath">Encrypted input file path</param>
        /// <param name="OutputPath">Decrypted output file path</param>
        /// <param name="Offset">Begin decryption at specified offset</param>
        public void Decrypt(string InputPath, string OutputPath, int Offset = 0)
        {
            this.FileSize = GetFileSize(InputPath);
            CalculateInterval();
            this.IsEncryption = false;

            if (this.IsStream)
            {
                this.StreamCipher.Init(this.KeyParam);
                // stream cipher
                ProcessStream(InputPath, OutputPath, Offset);
            }
            else
            {
                // init block cipher
                this.CipherMode.Init(false, this.KeyParam);

                if (this.CipherMode.Name == "CTR" && this.IsParallel)
                    ParallelCTR(InputPath, OutputPath, Offset);
                else if (this.CipherMode.Name == "CBC" && this.IsParallel)
                    ParallelCBC(InputPath, OutputPath, Offset);
                else
                    DecryptFile(InputPath, OutputPath, Offset);
            }
        }

        /// <summary>
        /// Encrypt a file
        /// </summary>
        /// <param name="InputPath">Path to input file</param>
        /// <param name="OutputPath">Path to encrypted output file</param>
        /// <param name="Header">Optional header to write to start of file</param>
        public void Encrypt(string InputPath, string OutputPath, MemoryStream Header = null)
        {
            this.FileSize = GetFileSize(InputPath);
            this.IsEncryption = true;

            // calculate progress interval
            CalculateInterval();

            if (this.IsStream)
            {
                // stream cipher
                ProcessStream(InputPath, OutputPath, 0, Header);
            }
            else
            {
                // init block cipher
                this.CipherMode.Init(true, this.KeyParam);
                if (this.CipherMode.Name == "CTR" && this.IsParallel)
                    ParallelCTR(InputPath, OutputPath, 0, Header);
                else
                    EncryptFile(InputPath, OutputPath, Header);
            }
        }
        #endregion

        #region Stream Ciphers
        private void ProcessStream(string InputPath, string OutputPath, int Offset = 0, MemoryStream Header = null)
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
                    else if (Offset > 0)
                        inputReader.BaseStream.Position = Offset;

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
        private void DecryptFile(string InputPath, string OutputPath, int Offset = 0)
        {
            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                byte[] inputBuffer = new byte[this.BlockSize];
                byte[] outputBuffer = new byte[this.BlockSize];
                long bytesRead = 0;
                long bytesTotal = 0;

                // move past header
                inputReader.BaseStream.Position = Offset; // MessageHeader.GetHeaderSize;

                using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None)))
                {
                    int maxOut = (int)inputReader.BaseStream.Length - MessageHeader.GetHeaderSize;

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, this.BlockSize)) > 0)
                    {
                        bytesTotal += bytesRead;

                        if (bytesTotal < maxOut)
                        {
                            this.CipherMode.Transform(inputBuffer, outputBuffer);
                            outputWriter.Write(outputBuffer);

                            if (bytesTotal % this.ProgressInterval == 0)
                                CalculateProgress(bytesTotal);
                        }
                        else
                        {
                            this.CipherMode.Transform(inputBuffer, outputBuffer);
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
                    if (Header != null)
                        outputWriter.Write(Header.ToArray());

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, this.BlockSize)) == this.BlockSize)
                    {
                        this.CipherMode.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer);
                        bytesTotal += bytesRead;

                        if (bytesTotal % this.ProgressInterval == 0)
                            CalculateProgress(bytesTotal);
                    }

                    if (bytesRead > 0)
                    {
                        if (bytesRead < this.BlockSize)
                            Padding.AddPadding(inputBuffer, (int)bytesRead);

                        this.CipherMode.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer);
                        CalculateProgress(bytesTotal + bytesRead);
                    }
                }
            }
        }

        private void ParallelCBC(string InputPath, string OutputPath, int Offset = 0)
        {
            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                int blockSize = CBC.MinParallelSize;
                long bytesRead = 0;
                long bytesTotal = 0;

                if (inputReader.BaseStream.Length < blockSize)
                    blockSize = (int)inputReader.BaseStream.Length;

                using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None)))
                {
                    byte[] inputBuffer = new byte[blockSize];
                    byte[] outputBuffer = new byte[blockSize];

                    inputReader.BaseStream.Position = Offset; // MessageHeader.GetHeaderSize;

                    // large blocks
                    while ((bytesRead = inputReader.Read(inputBuffer, 0, blockSize)) == blockSize)
                    {
                        this.CipherMode.Transform(inputBuffer, outputBuffer);
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
                            this.CipherMode.Transform(inputBuffer, count, outputBuffer, count);
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

        private void ParallelCTR(string InputPath, string OutputPath, int Offset = 0, MemoryStream Header = null)
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
                    else if (Offset > 0)
                        inputReader.BaseStream.Position = Offset; // MessageHeader.GetHeaderSize;

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, blockSize)) == blockSize)
                    {
                        this.CipherMode.Transform(inputBuffer, outputBuffer);
                        outputWriter.Write(outputBuffer);
                        bytesTotal += bytesRead;

                        if (bytesTotal % this.ProgressInterval == 0)
                            CalculateProgress(bytesTotal);
                    }

                    if (bytesRead > 0)
                    {
                        outputBuffer = new byte[blockSize];
                        this.CipherMode.Transform(inputBuffer, outputBuffer);
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
        public byte[] GetChecksum(string FilePath, byte[] HashKey)
        {
            using (SHA512HMAC hmac = new SHA512HMAC(HashKey))
            {
                int blockSize = hmac.BlockSize;
                byte[] buffer = new byte[blockSize];
                byte[] chkSum = new byte[hmac.DigestSize];

                using (BinaryReader inputReader = new BinaryReader(new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.None)))
                {
                    // start of file bytes
                    inputReader.BaseStream.Position = MessageHeader.GetHeaderSize;
                    int bytesRead = 0;

                    // read into mac
                    while ((bytesRead = inputReader.Read(buffer, 0, blockSize)) == blockSize)
                        hmac.BlockUpdate(buffer, 0, bytesRead);

                    // last block
                    if (bytesRead > 0)
                        hmac.BlockUpdate(buffer, 0, bytesRead);

                    // get the hash
                    hmac.DoFinal(chkSum, 0);
                }

                return chkSum;
            }
        }
        #endregion

        #region Helpers
        private int CalculateBlockSize()
        {
            if (this.CipherMode.Name == "CTR" && this.FileSize >= CTR.MinParallelSize)
            {
                if (this.FileSize > CTR.MaxParallelSize)
                    return CTR.MaxParallelSize;
                else
                    return CTR.MinParallelSize;
            }
            else if (this.CipherMode.Name == "CBC" && this.IsEncryption == false && this.FileSize >= CBC.MinParallelSize)
            {
                if (this.FileSize > CBC.MaxParallelSize)
                    return CBC.MaxParallelSize;
                else
                    return CBC.MinParallelSize;
            }
            else
            {
                return this.BlockSize;
            }
        }

        private void CalculateInterval()
        {
            if (this.IsStream)
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
        #endregion
    }
}
