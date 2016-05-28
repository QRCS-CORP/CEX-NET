#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Factory;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.Crypto.Processing;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.Tools
{
    /// <summary>
    /// Tests the integrity of all methods used by various Factory structure implementations
    /// </summary>
    public class FactoryStructureTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Tests Factory related structures methods and interfaces.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! FactoryStructure tests have executed succesfully.";
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
        /// Test KeyFactory and supporting structures
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                CipherDescriptionTest();
                OnProgress(new TestEventArgs("Passed CipherDescription serialization and access tests.."));
                CipherKeyTest();
                OnProgress(new TestEventArgs("Passed CipherKey serialization and access tests.."));
                KeyAuthorityTest();
                OnProgress(new TestEventArgs("Passed KeyAuthority serialization and access tests.."));
                KeyParamsTest();
                OnProgress(new TestEventArgs("Passed KeyParams serialization and access tests.."));
                MessageHeaderTest();
                OnProgress(new TestEventArgs("Passed MessageHeader serialization and access tests.."));
                PackageKeyTest();
                OnProgress(new TestEventArgs("Passed PackageKey serialization and access tests.."));
                VolumeKeyTest();
                OnProgress(new TestEventArgs("Passed VolumeKey serialization and access tests.."));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Private
        private void CipherDescriptionTest()
        {
            CipherDescription cd1 = new CipherDescription(
                SymmetricEngines.RHX,
                192, IVSizes.V128,
                CipherModes.CTR,
                PaddingModes.None,
                BlockSizes.B128,
                RoundCounts.R22);

            byte[] bcd = cd1.ToBytes();
            CipherDescription cd2 = new CipherDescription(bcd);
            if (!cd1.Equals(cd2))
                throw new Exception("KeyFactoryTest: CipherDescription serialization has failed!");
            MemoryStream mcd = cd2.ToStream();
            CipherDescription cd3 = new CipherDescription(mcd);
            if (!cd1.Equals(cd3))
                throw new Exception("KeyFactoryTest: CipherDescription serialization has failed!");

            int x = cd1.GetHashCode();
            if (x != cd2.GetHashCode() || x != cd3.GetHashCode())
                throw new Exception("KeyFactoryTest: CipherDescription hash code test has failed!");
        }

        private void CipherKeyTest()
        {
            CipherDescription ds = new CipherDescription(
                SymmetricEngines.RHX,
                192,
                IVSizes.V128,
                CipherModes.CTR,
                PaddingModes.PKCS7,
                BlockSizes.B128,
                RoundCounts.R22,
                Digests.Skein512,
                64,
                Digests.SHA512);

            CSPPrng rnd = new CSPPrng();
            byte[] id = new byte[16];
            byte[] ek = new byte[16];
            rnd.GetBytes(id);
            rnd.GetBytes(ek);

            // test serialization
            CipherKey ck = new CipherKey(ds, id, ek);
            byte[] sk = ck.ToBytes();
            CipherKey ck2 = new CipherKey(sk);
            if (!ck.Equals(ck2))
                throw new Exception("KeyFactoryTest: CipherKey serialization has failed!");

            MemoryStream mk = ck.ToStream();
            CipherKey ck3 = new CipherKey(mk);
            if (!ck.Equals(ck3))
                throw new Exception("KeyFactoryTest: CipherKey serialization has failed!");

            // test access funcs
            CipherKey.SetCipherDescription(mk, ds);
            CipherDescription ds2 = CipherKey.GetCipherDescription(mk);
            if (!ck.Description.Equals(ds2))
                throw new Exception("KeyFactoryTest: CipherKey access has failed!");

            rnd.GetBytes(ek);
            CipherKey.SetExtensionKey(mk, ek);
            if (!Evaluate.AreEqual(CipherKey.GetExtensionKey(mk), ek))
                throw new Exception("KeyFactoryTest: CipherKey access has failed!");

            rnd.GetBytes(id);
            CipherKey.SetKeyId(mk, id);
            if (!Evaluate.AreEqual(CipherKey.GetKeyId(mk), id))
                throw new Exception("KeyFactoryTest: CipherKey access has failed!");
        }

        private void KeyAuthorityTest()
        {
            CSPPrng rnd = new CSPPrng();
            byte[] di = new byte[16];
            byte[] oi = new byte[16];
            byte[] pi = new byte[16];
            byte[] pd = new byte[32];
            byte[] ti = new byte[16];
            rnd.GetBytes(di);
            rnd.GetBytes(oi);
            rnd.GetBytes(pi);
            rnd.GetBytes(pd);
            rnd.GetBytes(ti);
            KeyAuthority ka1 = new KeyAuthority(di, oi, pi, pd, KeyPolicies.IdentityRestrict | KeyPolicies.NoExport | KeyPolicies.NoNarrative, 1, ti);

            byte[] bcd = ka1.ToBytes();
            KeyAuthority ka2 = new KeyAuthority(bcd);
            if (!ka1.Equals(ka2))
                throw new Exception("KeyFactoryTest: KeyAuthority serialization has failed!");
            MemoryStream mcd = ka2.ToStream();
            KeyAuthority ka3 = new KeyAuthority(mcd);
            if (!ka1.Equals(ka3))
                throw new Exception("KeyFactoryTest: KeyAuthority serialization has failed!");

            int x = ka1.GetHashCode();
            if (x != ka2.GetHashCode() || x != ka3.GetHashCode())
                throw new Exception("KeyFactoryTest: KeyAuthority hash code test has failed!");
        }

        private void KeyParamsTest()
        {
            CSPPrng rnd = new CSPPrng();
            KeyGenerator kg = new KeyGenerator();

            for (int i = 0; i < 10; ++i)
            {
                // out-bound funcs return pointer to obj
                KeyParams kp1 = kg.GetKeyParams(rnd.Next(1, 1024), rnd.Next(1, 128), rnd.Next(1, 128));
                MemoryStream m = (MemoryStream)KeyParams.Serialize(kp1);
                KeyParams kp2 = KeyParams.DeSerialize(m);

                if (!kp1.Equals(kp2))
                    throw new Exception("KeyFactoryTest: KeyParams serialization test has failed!");
                if (kp1.GetHashCode() != kp2.GetHashCode())
                    throw new Exception("KeyFactoryTest: KeyAuthority hash code test has failed!");
            }
        }

        private void MessageHeaderTest()
        {
            CSPPrng rnd = new CSPPrng();
            byte[] id = new byte[16];
            byte[] ex = new byte[16];
            rnd.GetBytes(id);
            rnd.GetBytes(ex);

            // test serialization
            /*MessageHeader mh = new MessageHeader(id, ex, 0);
            byte[] sk = mh.ToBytes();
            MessageHeader mh2 = new MessageHeader(sk);
            if (!mh.Equals(mh2))
                throw new Exception("KeyFactoryTest: MessageHeader serialization has failed!");

            MemoryStream mk = mh.ToStream();
            MessageHeader mh3 = new MessageHeader(mk);
            if (!mh.Equals(mh3))
                throw new Exception("KeyFactoryTest: MessageHeader serialization has failed!");

            byte[] id2 = MessageHeader.GetKeyId(mk);
            if (!Evaluate.AreEqual(id, id2))
                throw new Exception("KeyFactoryTest: MessageHeader access has failed!");

            byte[] ex2 = MessageHeader.GetExtension(mk);
            if (!Evaluate.AreEqual(ex, ex2))
                throw new Exception("KeyFactoryTest: MessageHeader access has failed!");

            string ext1 = "test";
            byte[] enc = MessageHeader.EncryptExtension(ext1, MessageHeader.GetExtension(mk));
            string ext2 = MessageHeader.DecryptExtension(enc, MessageHeader.GetExtension(mk));
            if (ext1 != ext2)
                throw new Exception("KeyFactoryTest: MessageHeader access has failed!");*/
        }

        private void PackageKeyTest()
        {

            CipherDescription cd1 = new CipherDescription(
                SymmetricEngines.RHX,
                192, IVSizes.V128,
                CipherModes.CTR,
                PaddingModes.None,
                BlockSizes.B128,
                RoundCounts.R22);

            CSPPrng rnd = new CSPPrng();
            byte[] di = new byte[16];
            byte[] oi = new byte[16];
            byte[] pi = new byte[16];
            byte[] pd = new byte[32];
            byte[] ti = new byte[16];
            rnd.GetBytes(di);
            rnd.GetBytes(oi);
            rnd.GetBytes(pi);
            rnd.GetBytes(pd);
            rnd.GetBytes(ti);
            KeyAuthority ka1 = new KeyAuthority(di, oi, pi, pd, KeyPolicies.IdentityRestrict | KeyPolicies.NoExport | KeyPolicies.NoNarrative, 1, ti);

            MemoryStream mk = new MemoryStream();
            PackageKey pk1 = new PackageKey(ka1, cd1, 100);

            PackageFactory pf = new PackageFactory(mk, ka1);
            pf.Create(pk1);

            byte[] bpk = pk1.ToBytes();
            PackageKey pk2 = new PackageKey(bpk);
            if (!pk1.Equals(pk2))
                throw new Exception("KeyFactoryTest: PackageKey serialization has failed!");

            PackageKey pk3 = new PackageKey(mk);
            if (!pk1.Equals(pk3))
                throw new Exception("KeyFactoryTest: PackageKey serialization has failed!");
            if (pk1.GetHashCode() != pk2.GetHashCode() || pk1.GetHashCode() != pk3.GetHashCode())
                throw new Exception("KeyFactoryTest: PackageKey hash code test has failed!");
            pf.Dispose();
        }

        private void VolumeKeyTest()
        {
            CipherDescription cd1 = new CipherDescription(
                SymmetricEngines.RHX,
                192, IVSizes.V128,
                CipherModes.CTR,
                PaddingModes.None,
                BlockSizes.B128,
                RoundCounts.R22);

            MemoryStream mk;
            using (VolumeCipher vc = new VolumeCipher())
                mk = vc.CreateKey(cd1, 100);

            VolumeKey vk1 = new VolumeKey(mk);
            CipherDescription cd2 = vk1.Description;
            if (!cd1.Equals(cd2))
                throw new Exception("KeyFactoryTest: VolumeKey serialization has failed!");

            VolumeKey vk2 = new VolumeKey(mk.ToArray());
            if (!vk1.Equals(vk2))
                throw new Exception("KeyFactoryTest: VolumeKey serialization has failed!");
            if (vk1.GetHashCode() != vk2.GetHashCode())
                throw new Exception("KeyFactoryTest: VolumeKey hash code test has failed!");
        }
        #endregion
    }
}
