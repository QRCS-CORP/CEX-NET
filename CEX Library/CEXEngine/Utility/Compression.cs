#region Directives
using System;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
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
// An implementation of a File and Folder Archiving and Compression class.
// Written by John Underhill, December 1, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// File and Folder Archiving and Compression
    /// </summary>
    public class Compression
    {
        #region Compression Header
        [Serializable]
        [StructLayout(LayoutKind.Sequential)]
        private struct CompressionHeaderStruct
        {
            internal Int32 Format;
            internal Int32 FileCount;
            internal Int32 NameSize;
            [MarshalAs(UnmanagedType.ByValArray)]
            internal Int64[] FileSizes;
            [MarshalAs(UnmanagedType.ByValArray)]
            internal char[] FileNames;

            internal CompressionHeaderStruct(Int32 Count, Int32 NameLength, Int64[] Sizes, char[] Names, CompressionFormats Formats)
            {
                Format = (Int32)Formats;
                FileCount = Count;
                NameSize = NameLength;
                FileSizes = Sizes;
                FileNames = Names;
            }
        }
        #endregion

        #region Enums
        /// <summary>
        /// Compression types
        /// </summary>
        public enum CompressionFormats : int
        {
            /// <summary>
            /// No compression
            /// </summary>
            None = 0,
            /// <summary>
            /// Deflate algorithm
            /// </summary>
            Deflate = 1,
            /// <summary>
            /// Gzip algorithm
            /// </summary>
            GZip = 2
        }
        #endregion

        #region Constants
        private const int DEF_BLOCK = 1024;
        private const int SEEKTO_FORMAT = 0;
        private const int SEEKTO_COUNT = 4;
        private const int SEEKTO_NAMESZ = 8;
        private const int SEEKTO_SIZES = 12;
        #endregion

        #region Events
        /// <summary>
        /// Progress counter delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="e">Progress changed arguments</param>
        public delegate void ProgressCounterDelegate(object sender, ProgressChangedEventArgs e);

        /// <summary>
        /// Progress counter event
        /// </summary>
        [Description("Progress Counter")]
        public event ProgressCounterDelegate ProgressCounter;
        #endregion

        #region Properties
        private int BlockSize { get; set; }
        private CompressionFormats CompressionFormat { get; set; }
        private long FileSize { get; set; }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Format">Compression engine</param>
        public Compression(CompressionFormats Format = CompressionFormats.Deflate)
        {
            CompressionFormat = Format;
            BlockSize = DEF_BLOCK;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Compress and archive a folder
        /// </summary>
        /// 
        /// <param name="InputPath">Folder path</param>
        /// <param name="OutputFile">Full path to new archive file</param>
        /// 
        /// <returns>Success</returns>
        public bool CompressArchive(string InputPath, string OutputFile)
        {
            if (!Directory.Exists(InputPath))
                throw new ArgumentException("InputPath: A valid folder path is required!");
            if (!Directory.Exists(Path.GetDirectoryName(OutputFile)))
                throw new ArgumentException("OutputFile: Invalid folder path!");

            try
            {
                FileSize = GetFolderSize(InputPath);
                if (FileSize < 1) return false;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    CompressArchiveDf(InputPath, OutputFile);
                else if (CompressionFormat == CompressionFormats.GZip)
                    CompressArchiveGz(InputPath, OutputFile);
                else
                    CompressArchiveNc(InputPath, OutputFile);

                return true;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Decompress an archive
        /// </summary>
        /// 
        /// <param name="InputFile">Full path to new archive file</param>
        /// <param name="OutputPath">Destination directory for expanded files</param>
        /// 
        /// <returns>Success</returns>
        public bool DeCompressArchive(string InputFile, string OutputPath)
        {
            if (!File.Exists(InputFile))
                throw new ArgumentException("InputFile: Invalid input file!");
            if (!Directory.Exists(OutputPath))
                throw new ArgumentException("OutputPath: A valid folder path is required!");

            try
            {
                CompressionFormats format = GetCompressionFormat(InputFile);
                FileSize = GetDeCompressedSize(InputFile);
                if (FileSize < 1) return false;
                BlockSize = GetBlockSize(FileSize);

                if (format == CompressionFormats.Deflate)
                    DeCompressArchiveDf(InputFile, OutputPath);
                else if (format == CompressionFormats.GZip)
                    DeCompressArchiveGz(InputFile, OutputPath);
                else
                    DeCompressArchiveNc(InputFile, OutputPath);

                return true;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Compress a file
        /// </summary>
        /// 
        /// <param name="InputFile">File to compress</param>
        /// <param name="OutputFile">Full path to destination file</param>
        /// 
        /// <returns>Success</returns>
        public bool CompressFile(string InputFile, string OutputFile)
        {
            if (!File.Exists(InputFile))
                throw new ArgumentException("InputFile: Invalid input file!");
            if (!Directory.Exists(Path.GetDirectoryName(OutputFile)))
                throw new ArgumentException("OutputFile: Invalid folder path!");

            try
            {
                FileSize = GetFileSize(InputFile);
                if (FileSize < 1) return false;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    CompressFileDf(InputFile, OutputFile);
                else
                    CompressFileGz(InputFile, OutputFile);

                return true;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Decompress a file
        /// </summary>
        /// 
        /// <param name="InputFile">Compressed file</param>
        /// <param name="OutputPath">Directory path destination</param>
        /// 
        /// <returns>Success</returns>
        public bool DeCompressFile(string InputFile, string OutputPath)
        {
            if (!File.Exists(InputFile))
                throw new ArgumentException("InputFile: Invalid input file!");
            if (!Directory.Exists(OutputPath))
                throw new ArgumentException("OutputPath: A valid folder path is required!");

            try
            {
                FileSize = GetDeCompressedSize(InputFile);
                if (FileSize < 1) return false;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    DeCompressFileDf(InputFile, OutputPath);
                else
                    DeCompressFileGz(InputFile, OutputPath);

                return true;

            }
            catch
            {
                throw;
            }
        }
        #endregion

        #region File Compression/Decompression
        private void CompressFileDf(string InputPath, string OutputPath)
        {
            CompressionHeaderStruct header = CreateFileHeader(InputPath);
            byte[] headerStream = SerializeHeader(header).ToArray();

            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                byte[] inputBuffer = new byte[BlockSize];
                long bytesRead = 0;
                long bytesTotal = 0;

                using (DeflateStream cmpStream = new DeflateStream(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None), CompressionMode.Compress))
                {
                    cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
                
            }
        }

        private void CompressFileGz(string InputPath, string OutputPath)
        {
            CompressionHeaderStruct header = CreateFileHeader(InputPath);
            byte[] headerStream = SerializeHeader(header).ToArray();

            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                byte[] inputBuffer = new byte[BlockSize];
                long bytesRead = 0;
                long bytesTotal = 0;

                using (GZipStream cmpStream = new GZipStream(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None), CompressionMode.Compress))
                {
                    cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
            }
        }

        private void DeCompressFileDf(string InputPath, string OutputPath)
        {
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;
            string fileName = GetFileNames(InputPath);
            int offset = GetHeaderLength(InputPath);
            string path = GetUniquePath(Path.Combine(OutputPath, fileName));

            using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None)))
            {
                using (DeflateStream cmpStream = new DeflateStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None), CompressionMode.Decompress))
                {
                    cmpStream.BaseStream.Position = offset;

                    while ((bytesRead = cmpStream.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
            }
        }

        private void DeCompressFileGz(string InputPath, string OutputPath)
        {
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;
            string fileName = GetFileNames(InputPath);
            int offset = GetHeaderLength(InputPath);
            string path = GetUniquePath(Path.Combine(OutputPath, fileName));

            using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None)))
            {
                using (GZipStream cmpStream = new GZipStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None), CompressionMode.Decompress))
                {
                    cmpStream.BaseStream.Position = offset;

                    while ((bytesRead = cmpStream.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
            }
        }
        #endregion

        #region Folder Archiving
        private void CompressArchiveDf(string InputPath, string OutputPath)
        {
            CompressionHeaderStruct header = CreateFolderHeader(InputPath);
            byte[] headerStream = SerializeHeader(header).ToArray();
            string[] paths = GetFilePaths(InputPath);
            Int64[] sizes = new Int64[paths.Length];
            byte[] inputBuffer = new byte[BlockSize];
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;

            using (DeflateStream cmpStream = new DeflateStream(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None), CompressionMode.Compress))
            {
                cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                for (int i = 0; i < paths.Length; i++)
                {
                    using (BinaryReader inputReader = new BinaryReader(new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.None)))
                    {
                        while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                        {
                            cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;
                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                    sizes[i] = byteCount;
                    byteCount = 0;
                }
            }
        }

        private void CompressArchiveGz(string InputPath, string OutputPath)
        {
            CompressionHeaderStruct header = CreateFolderHeader(InputPath);
            byte[] headerStream = SerializeHeader(header).ToArray();
            string[] paths = GetFilePaths(InputPath);
            Int64[] sizes = new Int64[paths.Length];
            byte[] inputBuffer = new byte[BlockSize];
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;

            using (GZipStream cmpStream = new GZipStream(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None), CompressionMode.Compress))
            {
                cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                for (int i = 0; i < paths.Length; i++)
                {
                    using (BinaryReader inputReader = new BinaryReader(new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.None)))
                    {
                        while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                        {
                            cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;
                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }

                    sizes[i] = byteCount;
                    byteCount = 0;
                }
            }
        }

        private void CompressArchiveNc(string InputPath, string OutputPath)
        {
            CompressionHeaderStruct header = CreateFolderHeader(InputPath);
            byte[] headerStream = SerializeHeader(header).ToArray();
            string[] paths = GetFilePaths(InputPath);
            Int64[] sizes = new Int64[paths.Length];
            byte[] inputBuffer = new byte[BlockSize];
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;

            using (FileStream outputStream = new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                outputStream.Write(headerStream, 0, headerStream.Length);

                for (int i = 0; i < paths.Length; i++)
                {
                    using (BinaryReader inputReader = new BinaryReader(new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.None)))
                    {
                        while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                        {
                            outputStream.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;
                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }

                    sizes[i] = byteCount;
                    byteCount = 0;
                }
            }
        }

        private void DeCompressArchiveDf(string InputPath, string OutputPath)
        {
            CompressionHeaderStruct header = DeSerializeHeader(InputPath);
            string names = new string(header.FileNames);
            string[] fileNames = names.Split('*');
            byte[] inputBuffer = new byte[BlockSize];
            int offset = GetHeaderLength(InputPath);
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            int bytesOut = BlockSize;
            long fileSize = 0;

            using (DeflateStream cmpStream = new DeflateStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None), CompressionMode.Decompress))
            {
                cmpStream.BaseStream.Position = offset;

                for (int i = 0; i < header.FileCount; i++)
                {
                    string path = GetUniquePath(Path.Combine(OutputPath, fileNames[i]));
                    fileSize = header.FileSizes[i];
                    byteCount = 0;

                    if (fileSize < BlockSize)
                        bytesOut = (int)fileSize;
                    else
                        bytesOut = BlockSize;

                    using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None)))
                    {
                        while ((bytesRead = cmpStream.Read(inputBuffer, 0, bytesOut)) > 0)
                        {
                            outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;

                            if (byteCount + BlockSize > fileSize)
                                bytesOut = (int)(fileSize - byteCount);

                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                }
            }
        }

        private void DeCompressArchiveGz(string InputPath, string OutputPath)
        {
            CompressionHeaderStruct header = DeSerializeHeader(InputPath);
            string names = new string(header.FileNames);
            string[] fileNames = names.Split('*');
            byte[] inputBuffer = new byte[BlockSize];
            int offset = GetHeaderLength(InputPath);
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            int bytesOut = BlockSize;
            long fileSize = 0;

            using (GZipStream cmpStream = new GZipStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None), CompressionMode.Decompress))
            {
                cmpStream.BaseStream.Position = offset;

                for (int i = 0; i < header.FileCount; i++)
                {
                    string path = GetUniquePath(Path.Combine(OutputPath, fileNames[i]));
                    fileSize = header.FileSizes[i];
                    byteCount = 0;

                    if (fileSize < BlockSize)
                        bytesOut = (int)fileSize;
                    else
                        bytesOut = BlockSize;

                    using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None)))
                    {
                        while ((bytesRead = cmpStream.Read(inputBuffer, 0, bytesOut)) > 0)
                        {
                            outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;

                            if (byteCount + BlockSize > fileSize)
                                bytesOut = (int)(fileSize - byteCount);

                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                }
            }
            
        }

        private void DeCompressArchiveNc(string InputPath, string OutputPath)
        {
            CompressionHeaderStruct header = DeSerializeHeader(InputPath);
            string names = new string(header.FileNames);
            string[] fileNames = names.Split('*');
            byte[] inputBuffer = new byte[BlockSize];
            int offset = GetHeaderLength(InputPath);
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            int bytesOut = BlockSize;
            long fileSize = 0;

            using (FileStream inputStream = new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                inputStream.Position = offset;

                for (int i = 0; i < header.FileCount; i++)
                {
                    string path = GetUniquePath(Path.Combine(OutputPath, fileNames[i]));
                    fileSize = header.FileSizes[i];
                    byteCount = 0;

                    if (fileSize < BlockSize)
                        bytesOut = (int)fileSize;
                    else
                        bytesOut = BlockSize;

                    using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None)))
                    {
                        while ((bytesRead = inputStream.Read(inputBuffer, 0, bytesOut)) > 0)
                        {
                            outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;

                            if (byteCount + BlockSize > fileSize)
                                bytesOut = (int)(fileSize - byteCount);

                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                }
            }
        }
        #endregion

        #region Compression Header
        private CompressionHeaderStruct CreateFileHeader(string InputFile)
        {
            if (!File.Exists(InputFile)) return new CompressionHeaderStruct();
            CompressionHeaderStruct header = new CompressionHeaderStruct();
            char[] name = Path.GetFileName(InputFile).ToCharArray();

            header.Format = (int)CompressionFormat;
            header.FileCount = 1;
            header.NameSize = name.Length;
            header.FileSizes = new Int64[1];
            header.FileSizes[0] = GetFileSize(InputFile);
            header.FileNames = name;

            return header;
        }

        private CompressionHeaderStruct CreateFolderHeader(string InputPath)
        {
            if (!Directory.Exists(InputPath)) return new CompressionHeaderStruct();
            CompressionHeaderStruct header = new CompressionHeaderStruct();
            char[] names = GetNameArray(InputPath);

            header.Format = (int)CompressionFormat;
            header.FileCount = GetFileCount(InputPath);
            header.NameSize = names.Length;
            header.FileSizes = GetFileSizes(InputPath);
            header.FileNames = names;

            return header;
        }

        private CompressionHeaderStruct DeSerializeHeader(string InputFile)
        {
            CompressionHeaderStruct Header = new CompressionHeaderStruct();
            if (!File.Exists(InputFile)) return Header;

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                // compression format
                Header.Format = reader.ReadInt32();
                // get file count
                int fileCount = reader.ReadInt32();
                Header.FileCount = fileCount;
                // file name array length
                int nameLen = reader.ReadInt32();
                Header.NameSize = nameLen;
                // get start positions in the file
                int btCount = fileCount * 8;
                byte[] temp = reader.ReadBytes(btCount);
                Header.FileSizes = Convert(temp);
                // get file name array
                Header.FileNames = reader.ReadChars(nameLen);
            }

            return Header;
        }

        private MemoryStream SerializeHeader(CompressionHeaderStruct Header)
        {
            try
            {
                MemoryStream stream = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stream);

                // write compression format
                writer.Write(Header.Format);
                // write file count
                writer.Write(Header.FileCount);
                // write name array length
                writer.Write(Header.FileNames.Length);
                // write positions aray
                byte[] temp = Convert(Header.FileSizes);
                writer.Write(temp);
                // write file names array
                writer.Write(Header.FileNames);

                return stream;
            }
            catch
            {
                return new MemoryStream();
            }
        }
        #endregion

        #region Header Properties
        private Int64 GetDeCompressedSize(string InputFile)
        {
            if (!File.Exists(InputFile)) return 0;
            Int64 length = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_COUNT, SeekOrigin.Begin);
                int fileCount = reader.ReadInt32();
                Int64[] sizes = new Int64[fileCount];
                reader.BaseStream.Seek(SEEKTO_SIZES, SeekOrigin.Begin);
                int btSize = fileCount * 8;
                Buffer.BlockCopy(reader.ReadBytes(btSize), 0, sizes, 0, btSize);

                for (int i = 0; i < fileCount; i++)
                    length += sizes[i];
            }

            return length;
        }

        private CompressionFormats GetCompressionFormat(string InputFile)
        {
            if (!File.Exists(InputFile)) return 0;
            CompressionFormats flag = CompressionFormats.None;

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_FORMAT, SeekOrigin.Begin);
                flag = (CompressionFormats)reader.ReadInt32();
            }

            return flag;
        }

        private string GetFileNames(string InputFile)
        {
            if (!File.Exists(InputFile)) return "";
            string flag = "";

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_COUNT, SeekOrigin.Begin);
                int count = reader.ReadInt32();
                reader.BaseStream.Seek(SEEKTO_NAMESZ, SeekOrigin.Begin);
                int size = reader.ReadInt32();
                reader.BaseStream.Seek(SEEKTO_SIZES + (count * 8), SeekOrigin.Begin);
                flag = new string(reader.ReadChars(size));
            }

            return flag;
        }

        private Int32 GetHeaderLength(string InputFile)
        {
            if (!File.Exists(InputFile)) return 0;
            int length = 12;

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.None)))
            {
                reader.BaseStream.Seek(SEEKTO_COUNT, SeekOrigin.Begin);

                int fileCount = reader.ReadInt32();
                length += fileCount * 8;
                int nameLen = reader.ReadInt32();
                length += nameLen;
            }

            return length;
        }
        #endregion

        #region Helpers
        private void CalculateProgress(long ByteCount)
        {
            if (ProgressCounter != null)
            {
                double progress = 100.0 * (double)ByteCount / FileSize;
                ProgressCounter(this, new ProgressChangedEventArgs((int)progress, (object)ByteCount));
            }
        }

        private Int64[] Convert(byte[] Data)
        {
            int inCount = Data.Length / 8;
            Int64[] temp = new Int64[inCount];
            Buffer.BlockCopy(Data, 0, temp, 0, Data.Length);

            return temp;
        }

        private byte[] Convert(Int32[] Data)
        {
            int btCount = Data.Length * 4;
            byte[] temp = new byte[btCount];
            Buffer.BlockCopy(Data, 0, temp, 0, btCount);

            return temp;
        }

        private byte[] Convert(Int64[] Data)
        {
            int btCount = Data.Length * 8;
            byte[] temp = new byte[btCount];
            Buffer.BlockCopy(Data, 0, temp, 0, btCount);

            return temp;
        }

        private Int32 GetBlockSize(Int64 DataSize)
        {
            Int32 size = (Int32)DataSize / 100;
            return size < 1 ? DEF_BLOCK : size;
        }

        private Int32 GetFileCount(string InputPath)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] files = dir.GetFiles("*.*");

            return files.Length;
        }

        private char[] GetNameArray(string InputPath)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] info = dir.GetFiles("*.*");
            string files = "";

            for (int i = 0; i < info.Length; i++)
            {
                if (i < info.Length - 1)
                    files += info[i].Name + "*";
                else
                    files += info[i].Name;
            }

            return files.ToCharArray();
        }

        private string[] GetFilePaths(string InputPath)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] files = dir.GetFiles("*.*");
            string[] fileList = new string[files.Length];

            for (int i = 0; i < fileList.Length; i++)
                fileList[i] = files[i].FullName;

            return fileList;
        }

        private Int64 GetFileSize(string InputFile)
        {
            FileInfo file = new FileInfo(InputFile);
            return file.Length;
        }

        private Int64[] GetFileSizes(string InputPath)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] files = dir.GetFiles("*.*");
            Int64[] fileSizes = new Int64[files.Length];

            for (int i = 0; i < files.Length; i++)
                fileSizes[i] = files[i].Length;

            return fileSizes;
        }

        private Int64 GetFolderSize(string InputPath)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] files = dir.GetFiles("*.*");
            Int64 filesTotal = 0;

            for (int i = 0; i < files.Length; i++)
                filesTotal += files[i].Length;

            return filesTotal;
        }

        private string GetUniquePath(string FilePath)
        {
            string directory = Path.GetDirectoryName(FilePath);
            string fileName = Path.GetFileNameWithoutExtension(FilePath);
            string extension = Path.GetExtension(FilePath);

            for (int j = 1; j < 101; j++)
            {
                // test unique names
                if (File.Exists(FilePath))
                    FilePath = Path.Combine(directory, fileName + j.ToString() + extension);
                else
                    break;
            }
            return FilePath;
        }
        #endregion
    }
}
