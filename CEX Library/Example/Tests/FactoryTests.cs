using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Factory;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.Tools;

namespace VTDev.Projects.CEX.Tests
{
    /// <summary>
    /// Tests Creation and Extraction methods from the KeyFactory, PackageFactory, and VolumeFactory classes
    /// </summary>
    static class FactoryTests
    {
        /// <summary>
        /// Creates a temporary CipherKey on disk, extracts and compares the copy
        /// <para>Throws an Exception on failure</</para>
        /// </summary>
        public static void KeyFactoryTest()
        {
            string path = GetTempPath();
            KeyParams key1;
            KeyParams key2;
            CipherKey cikey;
            CipherDescription desc;
            MemoryStream ks = new MemoryStream();

            using (KeyFactory factory = new KeyFactory(ks))
            {
                // create a key/iv
                key1 = new KeyGenerator().GetKeyParams(32, 16, 64);

                // alt: manual creation
                /*kf.Create(
                    kp, 
                    Engines.RHX, 
                    32, 
                    IVSizes.V128, 
                    CipherModes.CTR, 
                    PaddingModes.X923, 
                    BlockSizes.B128, 
                    RoundCounts.R14, 
                    Digests.Keccak512, 
                    64, 
                    Digests.Keccak512);*/

                // cipher paramaters
                desc = new CipherDescription(
                    SymmetricEngines.RHX, 
                    32,
                    IVSizes.V128,
                    CipherModes.CTR,
                    PaddingModes.X923,
                    BlockSizes.B128,
                    RoundCounts.R14,
                    Digests.Keccak512,
                    64,
                    Digests.Keccak512);

                // create the key
                factory.Create(desc, key1);
                // extract
                factory.Extract(out cikey, out key2);
            }

            if (!cikey.Description.Equals(desc))
                throw new Exception();
            // compare key material
            if (!Evaluate.AreEqual(key1.IKM, key2.IKM))
                throw new Exception();
            if (!Evaluate.AreEqual(key1.IV, key2.IV))
                throw new Exception();
            if (!Evaluate.AreEqual(key1.Key, key2.Key))
                throw new Exception();
        }

        /// <summary>
        /// Creates a temporary PackageKey on disk, extracts and compares the copy
        /// <para>Throws an Exception on failure</</para>
        /// </summary>
        public static void PackageFactoryTest()
        {
            string path = GetTempPath();
            KeyGenerator kgen = new KeyGenerator();
            // populate a KeyAuthority structure
            KeyAuthority authority = new KeyAuthority(kgen.GetBytes(16), kgen.GetBytes(16), kgen.GetBytes(16), kgen.GetBytes(32), 0);

            // cipher paramaters
            CipherDescription desc = new CipherDescription(
                SymmetricEngines.RHX, 32,
                IVSizes.V128,
                CipherModes.CTR,
                PaddingModes.X923,
                BlockSizes.B128,
                RoundCounts.R14,
                Digests.Keccak512,
                64,
                Digests.Keccak512);

            // create the package key
            PackageKey pkey = new PackageKey(authority, desc, 10);

            // write a key file
            using (PackageFactory pf = new PackageFactory(new FileStream(path, FileMode.Open, FileAccess.ReadWrite), authority))
                pf.Create(pkey);

            for (int i = 0; i < pkey.SubKeyCount; i++)
            {
                CipherDescription desc2;
                KeyParams kp1;
                KeyParams kp2;
                byte[] ext;
                byte[] id = pkey.SubKeyID[i];

                // get at index
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read))
                    kp2 = PackageKey.AtIndex(stream, i);

                // read the package from id
                using (PackageFactory pf = new PackageFactory(new FileStream(path, FileMode.Open, FileAccess.ReadWrite), authority))
                    pf.Extract(id, out desc2, out kp1, out ext);

                // compare key material
                if (!Evaluate.AreEqual(kp1.Key, kp2.Key))
                    throw new Exception();
                if (!Evaluate.AreEqual(kp1.IV, kp2.IV))
                    throw new Exception();
                if (!Evaluate.AreEqual(pkey.ExtensionKey, ext))
                    throw new Exception();
                if (!desc.Equals(desc2))
                    throw new Exception();
            }
            if (File.Exists(path))
                File.Delete(path);
        }

        /// <summary>
        /// Creates a temporary VolumeKey on disk, extracts and compares the copy
        /// <para>Throws an Exception on failure</</para>
        /// </summary>
        public static void VolumeFactoryTest()
        {
            // cipher paramaters
            CipherDescription desc = new CipherDescription(
                SymmetricEngines.RHX, 
                32,
                IVSizes.V128,
                CipherModes.CTR,
                PaddingModes.X923,
                BlockSizes.B128,
                RoundCounts.R14,
                Digests.Keccak512,
                64,
                Digests.Keccak512);

            // create the package key
            VolumeKey vkey = new VolumeKey(desc, 10);
            // add id's
            for (int i = 0; i < vkey.FileId.Length; i++)
                vkey.FileId[i] = i;

            MemoryStream keyStream;
            // create a volume key stream
            using (VolumeFactory vf = new VolumeFactory())
                keyStream = vf.Create(vkey);

            for (int i = 0; i < vkey.Count; i++)
            {
                CipherDescription desc2;
                KeyParams kp1;
                KeyParams kp2;

                kp1 = VolumeKey.AtIndex(keyStream, i);
                int id = vkey.FileId[i];

                // read the key
                using (VolumeFactory vf = new VolumeFactory())
                    vf.Extract(keyStream, id, out desc2, out kp2);

                // compare key material
                if (!Evaluate.AreEqual(kp1.Key, kp2.Key))
                    throw new Exception();
                if (!Evaluate.AreEqual(kp1.IV, kp2.IV))
                    throw new Exception();
                if (!desc.Equals(desc2))
                    throw new Exception();
            }
        }

        private static string GetTempPath()
        {
            string path = Path.GetTempFileName();
            if (File.Exists(path))
                File.Delete(path);
            return path;
        }
    }
}
