﻿using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Processing;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Factory;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.Tools;

namespace VTDev.Projects.CEX.Tests
{
    /// <summary>
    /// Examples of the CompressionCipher, PacketCipher, CipherStream, DigestStream, MacStream, and VolumeCipher classes
    /// </summary>
    static class ProcessingTests
    {
        /// <summary>
        /// Compress and encrypt a file, then decrypt and deflate to an output directory
        /// </summary>
        /// 
        /// <param name="InputDirectory">The path of the folder to be archived</param>
        /// <param name="OutputDirectory">The decompressed files output directory</param>
        /// <param name="CompressedFilePath">The name and path of the new compressed and encrypted archive</param>
        public static void CompressionCipherTest(string InputDirectory, string OutputDirectory, string CompressedFilePath)
        {
            KeyParams kp = new KeyGenerator().GetKeyParams(32, 16);
            // Create an archive //
            // create the cipher
            using (ICipherMode cipher = new CTR(new RHX()))
            {
                // create the archive file
                using (FileStream fs = new FileStream(CompressedFilePath, FileMode.Create))
                {
                    // compress and encrypt directory
                    using (CompressionCipher cc = new CompressionCipher(cipher))
                    {
                        // set the input folder path and archive output stream
                        cc.Initialize(true, kp);
                        // write the compressed and encrypted archive to file
                        cc.Deflate(InputDirectory, fs);
                    }
                }
            }

            // Inflate an archive //
            // create the cipher
            using (ICipherMode cipher = new CTR(new RHX()))
            {
                // open the archive
                using (FileStream decmp = new FileStream(CompressedFilePath, FileMode.Open))
                {
                    // decrypt and inflate to output directory
                    using (CompressionCipher cc = new CompressionCipher(cipher))
                    {
                        // set the output folder path and archive path
                        cc.Initialize(false, kp);
                        // decrypt and inflate the directory
                        cc.Inflate(OutputDirectory, decmp);
                    }
                }
            }
            // manual inspection of files..
        }

        /// <summary>
        /// Test the PacketCipher class implementation
        /// <para>Throws an Exception on failure</</para>
        /// </summary>
        public static void PacketCipherTest()
        {
            const int BLSZ = 1024;
            KeyParams key;
            byte[] data;
            MemoryStream instrm;
            MemoryStream outstrm = new MemoryStream();

            using (KeyGenerator kg = new KeyGenerator())
            {
                // get the key
                key = kg.GetKeyParams(32, 16);
                // 2 * 1200 byte packets
                data = kg.GetBytes(BLSZ * 2);
            }
            // data to encrypt
            instrm = new MemoryStream(data);

            // Encrypt a stream //
            // create the outbound cipher
            using (ICipherMode cipher = new CTR(new RHX()))
            {
                // initialize the cipher for encryption
                cipher.Initialize(true, key);
                // set block size
                ((CTR)cipher).ParallelBlockSize = BLSZ;

                // encrypt the stream
                using (PacketCipher pc = new PacketCipher(cipher))
                {
                    byte[] inbuffer = new byte[BLSZ];
                    byte[] outbuffer = new byte[BLSZ];
                    int bytesread = 0;

                    while ((bytesread = instrm.Read(inbuffer, 0, BLSZ)) > 0)
                    {
                        // encrypt the buffer
                        pc.Write(inbuffer, 0, outbuffer, 0, BLSZ);
                        // add it to the output stream
                        outstrm.Write(outbuffer, 0, outbuffer.Length);
                    }
                }
            }

            // reset stream position
            outstrm.Seek(0, SeekOrigin.Begin);
            MemoryStream tmpstrm = new MemoryStream();

            // Decrypt a stream //
            // create the inbound cipher
            using (ICipherMode cipher = new CTR(new RHX()))
            {
                // initialize the cipher for decryption
                cipher.Initialize(false, key);
                // set block size
                ((CTR)cipher).ParallelBlockSize = BLSZ;

                // decrypt the stream
                using (PacketCipher pc = new PacketCipher(cipher))
                {
                    byte[] inbuffer = new byte[BLSZ];
                    byte[] outbuffer = new byte[BLSZ];
                    int bytesread = 0;

                    while ((bytesread = outstrm.Read(inbuffer, 0, BLSZ)) > 0)
                    {
                        // process the encrypted bytes
                        pc.Write(inbuffer, 0, outbuffer, 0, BLSZ);
                        // write to stream
                        tmpstrm.Write(outbuffer, 0, outbuffer.Length);
                    }
                }
            }

            // compare decrypted output with data
            if (!Evaluate.AreEqual(tmpstrm.ToArray(), data))
                throw new Exception();
        }

        /// <summary>
        /// Test the CipherStream class implementation
        /// <para>Throws an Exception on failure</</para>
        /// </summary>
        public static void StreamCipherTest()
        {
            const int BLSZ = 1024;
            KeyParams key;
            byte[] data;
            MemoryStream instrm;
            MemoryStream outstrm = new MemoryStream();

            using (KeyGenerator kg = new KeyGenerator())
            {
                // get the key
                key = kg.GetKeyParams(32, 16);
                // 2048 bytes
                data = kg.GetBytes(BLSZ * 2);
            }
            // data to encrypt
            instrm = new MemoryStream(data);

            // Encrypt a stream //
            // create the outbound cipher
            using (ICipherMode cipher = new CTR(new RHX()))
            {
                // set block size
                ((CTR)cipher).ParallelBlockSize = BLSZ;

                // encrypt the stream
                using (CipherStream sc = new CipherStream(cipher))
                {
                    sc.Initialize(true, key);
                    // encrypt the buffer
                    sc.Write(instrm, outstrm);
                }
            }

            // reset stream position
            outstrm.Seek(0, SeekOrigin.Begin);
            MemoryStream tmpstrm = new MemoryStream();

            // Decrypt a stream //
            // create the decryption cipher
            using (ICipherMode cipher = new CTR(new RHX()))
            {
                // set block size
                ((CTR)cipher).ParallelBlockSize = BLSZ;

                // decrypt the stream
                using (CipherStream sc = new CipherStream(cipher))
                {
                    sc.Initialize(false, key);
                    // process the encrypted bytes
                    sc.Write(outstrm, tmpstrm);
                }
            }

            // compare decrypted output with data
            if (!Evaluate.AreEqual(tmpstrm.ToArray(), data))
                throw new Exception();
        }

        /// <summary>
        /// Test the DigestStream class implementation
        /// <para>Throws an Exception on failure</</para>
        /// </summary>
        public static void StreamDigestTest()
        {
            byte[] data;
            MemoryStream instrm;
            MemoryStream outstrm = new MemoryStream();

            using (KeyGenerator kg = new KeyGenerator())
                data = kg.GetBytes(512);

            // data to digest
            instrm = new MemoryStream(data);
            byte[] code1;
            byte[] code2;

            using (DigestStream sd = new DigestStream(Digests.Keccak512))
            {
                sd.Initialize(instrm);
                code1 = sd.ComputeHash();
            }

            using (Keccak512 kc = new Keccak512())
                code2 = kc.ComputeHash(data);

            // compare the hash codes
            if (!Evaluate.AreEqual(code1, code2))
                throw new Exception();
        }

        /// <summary>
        /// Test the MacStream class implementation
        /// <para>Throws an Exception on failure</</para>
        /// </summary>
        public static void StreamMacTest()
        {
            byte[] data;
            byte[] key;
            MemoryStream instrm;
            MemoryStream outstrm = new MemoryStream();

            using (KeyGenerator kg = new KeyGenerator())
            {
                data = kg.GetBytes(512);
                key = kg.GetBytes(64);
            }

            // data to digest
            instrm = new MemoryStream(data);
            byte[] code1;
            byte[] code2;

            using (MacStream sm = new MacStream(new HMAC(new SHA512(), key)))
            {
                sm.Initialize(instrm);
                code1 = sm.ComputeMac();
            }

            using (HMAC hm = new HMAC(new SHA512()))
            {
                hm.Initialize(key);
                code2 = hm.ComputeMac(data);
            }

            // compare the hash codes
            if (!Evaluate.AreEqual(code1, code2))
                throw new Exception();
        }

        /// <summary>
        /// Test the VolumeCipher class implementation
        /// </summary>
        public static void VolumeCipherTest(string InputDirectory)
        {
            string[] paths = DirectoryTools.GetFiles(InputDirectory);

            // key will be written to this stream
            MemoryStream keyStream = new MemoryStream();

            // encrypt the files in the directory
            using (VolumeCipher vc = new VolumeCipher())
            {
                keyStream = vc.CreateKey(CipherDescription.AES256CTR, paths.Length);
                vc.Initialize(keyStream);
                vc.Encrypt(paths);
            }

            // decrypt the files
            using (VolumeCipher vc = new VolumeCipher())
            {
                vc.Initialize(keyStream);
                vc.Decrypt(paths);
            }

            // manual inspection of files..
        }

        // example helper functions
        private static bool IsVolumeFile(string TargetFile)
        {
            using (FileStream fs = new FileStream(TargetFile, FileMode.Open, FileAccess.Read))
            {
                int len = VolumeHeader.DistributionCode.Length;
                byte[] id = new byte[len];
                fs.Seek(fs.Length - VolumeHeader.GetHeaderSize, SeekOrigin.Begin);
                fs.Read(id, 0, len);
                return Evaluate.AreEqual(VolumeHeader.DistributionCode, id);
            }
        }

        private static bool IsMatchingVolumeKey(string TargetFile, string KeyPath)
        {
            using (FileStream fs = new FileStream(TargetFile, FileMode.Open, FileAccess.Read))
            {
                using (FileStream ks = new FileStream(KeyPath, FileMode.Open, FileAccess.Read))
                {
                    fs.Seek(fs.Length - VolumeHeader.GetHeaderSize, SeekOrigin.Begin);
                    VolumeHeader vh = new VolumeHeader(fs);
                    VolumeKey vk = new VolumeKey(ks);

                    return Evaluate.AreEqual(vk.Tag, vh.KeyId);
                }
            }
        }
    }
}
