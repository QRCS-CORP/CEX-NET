#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Processing;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.MacTest
{
    /// <summary>
    /// Compares the normal mode of MacStream with the Concurrent mode for equality
    /// </summary>
    public class MacStreamTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Compares MacStream with standard classes for equality.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All MacStream tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// Tests initialization methods and correctness of parallel processing mode in the MacStream implementation
        /// by comparing mac output between both modes performed on random streams
        /// </summary>
        /// 
        /// <returns>Status</returns>
        public string Run()
        {
            try
            {
                FromDescriptionTest();
                OnProgress(new TestEventArgs("Passed MacDescription serialization tests.."));
                CmacDescriptionTest();
                OnProgress(new TestEventArgs("Passed MacStream CMAC test.."));
                HmacDescriptionTest();
                OnProgress(new TestEventArgs("Passed MacStream HMAC tests.."));
                VmacDescriptionTest();
                OnProgress(new TestEventArgs("Passed MacStream VMAC tests.."));
                MacTests();
                OnProgress(new TestEventArgs("Passed MacStream integrity tests.."));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Tests
        private string CreateTempFile(int Size)
        {
            string path = Path.GetTempFileName();
            byte[] data = new CSPPrng().GetBytes(Size);

            File.WriteAllBytes(path, data);

            return path;
        }

        private void FromDescriptionTest()
        {
            MacDescription mds = new MacDescription(64, Digests.SHA256);
            MacDescription mds2 = new MacDescription(mds.ToBytes());
            MacDescription mds3 = new MacDescription(mds2.ToStream());
            if (!mds.Equals(mds2) || !mds.Equals(mds3))
                throw new Exception("MacStreamTest: Description serialization has failed!");
            mds = new MacDescription(32, BlockCiphers.RHX, IVSizes.V128, BlockSizes.B128, RoundCounts.R14);
            mds2 = new MacDescription(mds.ToBytes());
            mds3 = new MacDescription(mds2.ToStream());
            if (!mds.Equals(mds2) || !mds.Equals(mds3))
                throw new Exception("MacStreamTest: Description serialization has failed!");
            mds = new MacDescription(32, 96);
            mds2 = new MacDescription(mds.ToBytes());
            mds3 = new MacDescription(mds2.ToStream());
            if (!mds.Equals(mds2) || !mds.Equals(mds3))
                throw new Exception("MacStreamTest: Description serialization has failed!");
        }

        private void CmacDescriptionTest()
        {
            CSPPrng rng = new CSPPrng();
            byte[] data = rng.GetBytes(rng.Next(100, 400));
            byte[] key = rng.GetBytes(32);
            byte[] iv = rng.GetBytes(16);
            CMAC mac = new CMAC(BlockCiphers.RHX);
            mac.Initialize(key, iv);
            byte[] c1 = mac.ComputeMac(data);
            MacDescription mds = new MacDescription(32, BlockCiphers.RHX, IVSizes.V128, BlockSizes.B128, RoundCounts.R14);
            MacStream mst = new MacStream(mds, new KeyParams(key, iv));
            mst.Initialize(new MemoryStream(data));
            byte[] c2 = mst.ComputeMac();

            if (!Evaluate.AreEqual(c1, c2))
                throw new Exception("MacStreamTest: CMAC code arrays are not equal!");
        }

        private void HmacDescriptionTest()
        {
            CSPPrng rng = new CSPPrng();
            byte[] data = rng.GetBytes(rng.Next(100, 400));
            byte[] key = rng.GetBytes(64);
            HMAC mac = new HMAC(Digests.SHA256);
            mac.Initialize(key);
            byte[] c1 = mac.ComputeMac(data);
            MacDescription mds = new MacDescription(64, Digests.SHA256);
            MacStream mst = new MacStream(mds, new KeyParams(key));
            mst.Initialize(new MemoryStream(data));
            byte[] c2 = mst.ComputeMac();

            if (!Evaluate.AreEqual(c1, c2))
                throw new Exception("MacStreamTest: HMAC code arrays are not equal!");
        }

        private void VmacDescriptionTest()
        {
            CSPPrng rng = new CSPPrng();
            byte[] data = rng.GetBytes(rng.Next(100, 400));
            byte[] key = rng.GetBytes(64);
            byte[] iv = rng.GetBytes(16);
            VMAC mac = new VMAC();
            mac.Initialize(key, iv);
            byte[] c1 = mac.ComputeMac(data);
            MacDescription mds = new MacDescription(64, 16);
            MacStream mst = new MacStream(mds, new KeyParams(key, iv));
            mst.Initialize(new MemoryStream(data));
            byte[] c2 = mst.ComputeMac();

            if (!Evaluate.AreEqual(c1, c2))
                throw new Exception("MacStreamTest: Mac code arrays are not equal!");
        }

        private void MacTests()
        {
            string path = CreateTempFile(117674);
            byte[] Ikm = new CSPPrng().GetBytes(32);
            byte[] x1 = MacTest1(path, Ikm);
            byte[] y1 = MacTest2(path, Ikm);

            if (File.Exists(path))
                File.Delete(path);

            if ((Evaluate.AreEqual(x1, y1) == false))
                throw new Exception("Failed! Mac outputs are not equal");

            OnProgress(new TestEventArgs("Passed round 1 comparisons.."));

            path = CreateTempFile(69041);
            x1 = MacTest1(path, Ikm);
            y1 = MacTest2(path, Ikm);

            if (File.Exists(path))
                File.Delete(path);

            if ((Evaluate.AreEqual(x1, y1) == false))
                throw new Exception("Failed! Mac outputs are not equal");

            OnProgress(new TestEventArgs("Passed round 2 comparisons.."));

            path = CreateTempFile(65536);
            x1 = MacTest1(path, Ikm);
            y1 = MacTest2(path, Ikm);

            if (File.Exists(path))
                File.Delete(path);

            if ((Evaluate.AreEqual(x1, y1) == false))
                throw new Exception("Failed! Mac outputs are not equal");

            OnProgress(new TestEventArgs("Passed round 3 comparisons.."));

            if (!MacTest3(Ikm))
                throw new Exception("Failed! Mac outputs are not equal");

            OnProgress(new TestEventArgs("Passed round 4 comparisons.."));
        }

        private byte[] MacTest1(string FileName, byte[] IKm)
        {
            using (FileStream inStream = new FileStream(FileName, FileMode.Open))
            {
                using (MacStream mac = new MacStream(new HMAC(new SHA512(),IKm)))
                {
                    mac.Initialize(inStream);
                    mac.IsConcurrent = true;
                    return mac.ComputeMac();
                }
            }
        }

        private byte[] MacTest2(string FileName, byte[] IKm)
        {
            using (FileStream inStream = new FileStream(FileName, FileMode.Open))
            {
                using (MacStream mac = new MacStream(new HMAC(new SHA512(), IKm)))
                {
                    mac.Initialize(inStream);
                    mac.IsConcurrent = false;
                    return mac.ComputeMac();
                }
            }
        }

        private bool MacTest3(byte[] IKm)
        {
            byte[] data = new CSPPrng().GetBytes(33033);
            byte[] hash1;
            byte[] hash2;

            using (MacStream mac1 = new MacStream(new HMAC(new SHA512(), IKm)))
            {
                mac1.Initialize(new MemoryStream(data));
                mac1.IsConcurrent = false;
                hash1 =  mac1.ComputeMac();
            }

            using (HMAC mac2 = new HMAC(new SHA512(), IKm))
                hash2 = mac2.ComputeMac(data);

            return Evaluate.AreEqual(hash1, hash2);
        }
        #endregion
    }
}
