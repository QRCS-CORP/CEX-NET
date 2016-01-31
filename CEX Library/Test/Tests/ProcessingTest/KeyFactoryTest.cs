#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Factory;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.Tools
{
    /// <summary>
    /// Tests the KeyFactory implementation
    /// </summary>
    public class KeyFactoryTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Tests KeyFactory methods and interfaces.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! KeyFactory tests have executed succesfully.";
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
                CipherKeyCreateExtractTest();
                OnProgress(new TestEventArgs("Passed KeyFactory creation and extraction tests.."));

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
        private void CipherKeyCreateExtractTest()
        {
            KeyGenerator kg = new KeyGenerator();
            KeyParams kp = kg.GetKeyParams(192, 16, 64);

            CipherDescription ds = new CipherDescription (
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

            // in/out use a pointer
            MemoryStream m = new MemoryStream();
            KeyFactory kf =  new KeyFactory(m);
            kf.Create(ds, kp);
            // init new instance w/ populated stream
            m.Seek(0, SeekOrigin.Begin);
            KeyFactory kf2 = new KeyFactory(m);
            // extract key and desc from stream
            CipherKey ck;
            KeyParams kp2;
            kf2.Extract(out ck, out kp2);

            if (!ds.Equals(ck.Description))
                throw new Exception("KeyFactoryTest: Description extraction has failed!");
            if (!kp.Equals(kp2))
                throw new Exception("KeyFactoryTest: Key extraction has failed!");

            MemoryStream m2 = new MemoryStream();
            KeyFactory kf3 = new KeyFactory(m2);
            // test other create func
            kf3.Create(kp, SymmetricEngines.RHX, 192, IVSizes.V128, CipherModes.CTR, PaddingModes.PKCS7,
                BlockSizes.B128, RoundCounts.R22, Digests.Skein512, 64, Digests.SHA512);

            m2.Seek(0, SeekOrigin.Begin);
            KeyFactory kf4 = new KeyFactory(m2);
            kf4.Extract(out ck, out kp2);

            if (!ds.Equals(ck.Description))
                throw new Exception("KeyFactoryTest: Description extraction has failed!");
            if (!kp.Equals(kp2))
                throw new Exception("KeyFactoryTest: Key extraction has failed!");
        }
        #endregion
    }
}
