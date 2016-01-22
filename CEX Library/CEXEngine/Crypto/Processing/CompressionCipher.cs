#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Tools;
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
// Written by John Underhill, May 18, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing
{
    /// <summary>
    /// <h5>CompressionCipher: Used to compress and cryptographically transform a stream.</h5>
    /// <para>Extends the CipherStream class for encrypting a compressed directory of files.
    /// If the cipher is for encryption, files are compressed and encrypted to the output stream.
    /// If the cipher is for decryption, the input stream contains the compressed and encrypted directory, 
    /// and the directory path is the destination path for the decrypted and inflated files.</para>
    /// 
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example of archiving/encrypting and decrypting/inflating a Directory:</description>
    /// <code>
    /// public static void CompressionCipherTest(string InputDirectory, string OutputDirectory, string CompressedFilePath)
    /// {
    ///     KeyParams kp = new KeyGenerator().GetKeyParams(32, 16);
    ///     // Create an archive //
    ///     // create the cipher
    ///     using (ICipherMode cipher = new CTR(new RDX()))
    ///     {
    ///         // initialize the cipher for encryption
    ///         cipher.Initialize(true, kp);
    /// 
    ///         // create the archive file
    ///         using (FileStream fs = new FileStream(CompressedFilePath, FileMode.Create))
    ///         {
    ///             // compress and encrypt directory
    ///             using (CompressionCipher cc = new CompressionCipher(true, cipher))
    ///             {
    ///                 // set the input folder path and archive output stream
    ///                 cc.Initialize(InputDirectory, fs);
    ///                 // write the compressed and encrypted archive to file
    ///                 cc.Write();
    ///             }
    ///         }
    ///     }
    /// 
    ///     // Inflate an archive //
    ///     // create the cipher
    ///     using (ICipherMode cipher = new CTR(new RDX()))
    ///     {
    ///         // initialize the cipher for decryption
    ///         cipher.Initialize(false, kp);
    /// 
    ///         // open the archive
    ///         using (FileStream decmp = new FileStream(CompressedFilePath, FileMode.Open))
    ///         {
    ///             // decrypt and inflate to output directory
    ///             using (CompressionCipher cc = new CompressionCipher(false, cipher))
    ///             {
    ///                 // set the output folder path and archive path
    ///                 cc.Initialize(OutputDirectory, decmp);
    ///                 // decrypt and inflate the directory
    ///                 cc.Write();
    ///             }
    ///         }
    ///     }
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/05/18" version="1.3.8.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherDescription Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block">VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block Namespace</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">VTDev.Libraries.CEXEngine.Crypto.Engines Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Uses any of the implemented <see cref="ICipherMode">Cipher Mode</see> wrapped <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Block Ciphers</see>, or any of the implemented <see cref="IStreamCipher">Stream Ciphers</see>.</description></item>
    /// <item><description>Cipher Engine can be Disposed when this class is Disposed, set the DisposeEngine parameter in the class Constructor to true to dispose automatically.</description></item>
    /// <item><description>Streams can be Disposed when the class is Disposed, set the DisposeStream parameter in the Initialize(Stream, Stream, bool) call to true to dispose automatically.</description></item>
    /// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per any of the compress/decompress calls.</description></item>
    /// <item><description>Changes to the Cipher or CipherStream ParallelBlockSize must be set after initialization.</description></item>
    /// </list>
    /// </remarks>
    public class CompressionCipher : CipherStream
    {
        #region Fields
        private Compressor _cmpEngine;
        private Compressor.CompressionFormats _cmpFormat = Compressor.CompressionFormats.Deflate;
        private bool _isInitialized =  false;
        #endregion

        #region Properties
        /// <summary>
        /// GetSet: The compression algorithm used to compress a file
        /// </summary>
        public Compressor.CompressionFormats CompressionFormat 
        {
            get { return _cmpFormat; }
            set { _cmpFormat = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class with a CipherDescription Structure; containing the cipher implementation details.
        /// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription. 
        /// Cipher modes, padding, and engine classes are destroyed automatically through this classes Dispose() method.</para>
        /// </summary>
        /// 
        /// <param name="Header">A <see cref="CipherDescription"/> containing the cipher description</param>
        /// 
        /// <exception cref="System.ArgumentException">Thrown if an invalid <see cref="CipherDescription">CipherDescription</see> is used</exception>
        /// <exception cref="System.ArgumentNullException">Thrown if a null <see cref="KeyParams">KeyParams</see> is used</exception>
        public CompressionCipher(CipherDescription Header)
            : base(Header)
        {
        }

        /// <summary>
        /// Initialize the class with a Block Cipher wrapped in a <see cref="ICipherMode">Cipher Mode</see>, and optional <see cref="IPadding">Padding</see> instances.
        /// <para>This constructor requires a fully initialized <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.CipherModes">CipherMode</see> instance.
        /// If the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PaddingModes">PaddingMode</see> parameter is null, X9.23 padding will be used if required.</para>
        /// </summary>
        /// 
        /// <param name="Cipher">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Block Cipher</see> wrapped in a <see cref="ICipherMode">Cipher</see> mode</param>
        /// <param name="Padding">The <see cref="IPadding">Padding</see> instance</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null <see cref="ICipherMode">Cipher</see> is used</exception>
        /// <exception cref="System.ArgumentException">Thrown if an uninitialized Cipher is used</exception>
        public CompressionCipher(ICipherMode Cipher, IPadding Padding = null) :
            base(Cipher, Padding)
        {
        }

        /// <summary>
        /// Initialize the class with a <see cref="IStreamCipher">Stream Cipher</see> instance.
        /// <para>This constructor requires a fully initialized <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">CipherStream</see> instance.</para>
        /// </summary>
        /// 
        /// <param name="Cipher">The initialized <see cref="IStreamCipher">Stream Cipher</see> instance</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null <see cref="IStreamCipher">Stream Cipher</see> is used</exception>
        /// <exception cref="System.ArgumentException">Thrown if an uninitialized Cipher is used</exception>
        public CompressionCipher(IStreamCipher Cipher) :
            base(Cipher)
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the compression cipher
        /// </summary>
        /// 
        /// <param name="Encryption">Archive encryption or decryption</param>
        /// <param name="KeyParam">The class containing the cipher keying material</param>
        /// <param name="Format">The compression algorithm</param>
        public void Initialize(bool Encryption, KeyParams KeyParam, Compressor.CompressionFormats Format = Compressor.CompressionFormats.Deflate)
        {
            _cmpEngine = new Compressor(Format);
            base.Initialize(Encryption, KeyParam);
            _isInitialized = true;
        }

        /// <summary>
        /// Compress a stream
        /// </summary>
        /// 
        /// <param name="InStream">The stream to be processed</param>
        /// 
        /// <returns>The encrypted and compressed stream</returns>
        public Stream Compress(Stream InStream)
        {
            if (!_isInitialized)
                throw new CryptoProcessingException("CompressionCipher:Compress", "The class is not be Initialized!", new ArgumentException());

            // compress
            MemoryStream inStream = _cmpEngine.CompressStream(InStream);
            inStream.Seek(0, SeekOrigin.Begin);
            MemoryStream outStream =  new MemoryStream();
            // encrypt
            base.Write(inStream, outStream);
            outStream.Seek(0, SeekOrigin.Begin);

            return outStream;
        }

        /// <summary>
        /// Decompress a stream
        /// </summary>
        /// 
        /// <param name="InStream">The stream to be processed</param>
        /// 
        /// <returns>The decrypted and decompressed stream</returns>
        public Stream DeCompress(Stream InStream)
        {
            if (!_isInitialized)
                throw new CryptoProcessingException("CompressionCipher:Compress", "The class is not be Initialized!", new ArgumentException());

            // decrypt
            MemoryStream outStream = new MemoryStream();
            base.Write(InStream, outStream);
            outStream.Seek(0, SeekOrigin.Begin);
            // decompress
            MemoryStream retStream = _cmpEngine.DeCompressStream(outStream);
            retStream.Seek(0, SeekOrigin.Begin);

            return retStream;
        }

        /// <summary>
        /// Deflate (compress) an archive
        /// </summary>
        /// 
        /// <param name="DirectoryPath">The directory path to the files to be processed</param>
        /// <param name="OutStream">The stream receiving the compressed and encrypted archive</param>
        public void Deflate(string DirectoryPath, Stream OutStream)
        {
            if (!_isInitialized)
                throw new CryptoProcessingException("CompressionCipher:Compress", "The class is not be Initialized!", new ArgumentException());
            if (!DirectoryTools.Exists(DirectoryPath))
                throw new CryptoProcessingException("CompressionCipher:Deflate", "The directory does not exist!", new ArgumentException());
            if (DirectoryTools.FileCount(DirectoryPath) < 1)
                throw new CryptoProcessingException("CompressionCipher:Deflate", "There are no files in this directory!", new ArgumentException());

            // compress
            MemoryStream inStream = _cmpEngine.CompressArchive(DirectoryPath);
            inStream.Seek(0, SeekOrigin.Begin);
            // encrypt output
            base.Write(inStream, OutStream);
            OutStream.Seek(0, SeekOrigin.Begin);
        }

        /// <summary>
        /// Inflate (decompress) an archive
        /// </summary>
        /// 
        /// <param name="DirectoryPath">The directory path where files will be written</param>
        /// <param name="InStream">The stream containing the compressed archive</param>
        public void Inflate(string DirectoryPath, Stream InStream)
        {
            if (!_isInitialized)
                throw new CryptoProcessingException("CompressionCipher:Compress", "The class is not be Initialized!", new ArgumentException());
            if (!DirectoryTools.Exists(DirectoryPath))
                Directory.CreateDirectory(DirectoryPath);
            if (!DirectoryTools.IsWritable(DirectoryPath))
                throw new CryptoProcessingException("CompressionCipher:InFlate", "Directory path is not writable! Check permissions.", new AccessViolationException());

            // decrypt stream
            MemoryStream outStream = new MemoryStream();
            base.Write(InStream, outStream);
            outStream.Seek(0, SeekOrigin.Begin);
            // decompress
            _cmpEngine.DeCompressArchive(outStream, DirectoryPath);
        }
        #endregion
    }
}
