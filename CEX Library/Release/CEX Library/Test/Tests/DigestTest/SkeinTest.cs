#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.DigestTest
{
    /// <summary>
    /// Tests the 256, 512, and 1024 bit versions of Skein against known test vectors.
    /// </summary>
    public class SkeinTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of Skein.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All Skein tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Vectors
        private static readonly byte[] _expected256 = {
            0xDF, 0x28, 0xE9, 0x16, 0x63, 0x0D, 0x0B, 0x44, 
            0xC4, 0xA8, 0x49, 0xDC, 0x9A, 0x02, 0xF0, 0x7A,
            0x07, 0xCB, 0x30, 0xF7, 0x32, 0x31, 0x82, 0x56, 
            0xB1, 0x5D, 0x86, 0x5A, 0xC4, 0xAE, 0x16, 0x2F
        };

        private static readonly byte[] _expected512 = { 
            0x91 ,0xcc ,0xa5 ,0x10 ,0xc2 ,0x63 ,0xc4 ,0xdd ,0xd0 ,0x10 ,0x53 ,0x0a ,0x33 ,0x07 ,0x33 ,0x09,
            0x62 ,0x86 ,0x31 ,0xf3 ,0x08 ,0x74 ,0x7e ,0x1b ,0xcb ,0xaa ,0x90 ,0xe4 ,0x51 ,0xca ,0xb9 ,0x2e,
            0x51 ,0x88 ,0x08 ,0x7a ,0xf4 ,0x18 ,0x87 ,0x73 ,0xa3 ,0x32 ,0x30 ,0x3e ,0x66 ,0x67 ,0xa7 ,0xa2,
            0x10 ,0x85 ,0x6f ,0x74 ,0x21 ,0x39 ,0x00 ,0x00 ,0x71 ,0xf4 ,0x8e ,0x8b ,0xa2 ,0xa5 ,0xad ,0xb7
        };

        private static readonly byte[] _expected1024 = {
            0x1F, 0x3E, 0x02, 0xC4, 0x6F, 0xB8, 0x0A, 0x3F, 0xCD, 0x2D, 0xFB, 0xBC, 0x7C, 0x17, 0x38, 0x00,
            0xB4, 0x0C, 0x60, 0xC2, 0x35, 0x4A, 0xF5, 0x51, 0x18, 0x9E, 0xBF, 0x43, 0x3C, 0x3D, 0x85, 0xF9,
            0xFF, 0x18, 0x03, 0xE6, 0xD9, 0x20, 0x49, 0x31, 0x79, 0xED, 0x7A, 0xE7, 0xFC, 0xE6, 0x9C, 0x35,
            0x81, 0xA5, 0xA2, 0xF8, 0x2D, 0x3E, 0x0C, 0x7A, 0x29, 0x55, 0x74, 0xD0, 0xCD, 0x7D, 0x21, 0x7C,
            0x48, 0x4D, 0x2F, 0x63, 0x13, 0xD5, 0x9A, 0x77, 0x18, 0xEA, 0xD0, 0x7D, 0x07, 0x29, 0xC2, 0x48,
            0x51, 0xD7, 0xE7, 0xD2, 0x49, 0x1B, 0x90, 0x2D, 0x48, 0x91, 0x94, 0xE6, 0xB7, 0xD3, 0x69, 0xDB,
            0x0A, 0xB7, 0xAA, 0x10, 0x6F, 0x0E, 0xE0, 0xA3, 0x9A, 0x42, 0xEF, 0xC5, 0x4F, 0x18, 0xD9, 0x37,
            0x76, 0x08, 0x09, 0x85, 0xF9, 0x07, 0x57, 0x4F, 0x99, 0x5E, 0xC6, 0xA3, 0x71, 0x53, 0xA5, 0x78
        };
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// Tests the 256, 512, and 1024 bit versions of Skein against known test vectors.
        /// </summary>
        /// 
        /// <returns>Status</returns>
        public string Test()
        {
            try
            {
                DigestTest();

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Helpers
        private bool DigestTest()
        {
            byte[] hash;

            // Make test vector for 256-bit hash
            var testVector = new byte[64];
            for (int i = 0; i < testVector.Length; i++)
                testVector[i] = (byte)(255 - i);

            using (Skein256 skein256 = new Skein256())
            {
                hash = skein256.ComputeHash(testVector);
                hash = skein256.ComputeHash(testVector);
            }

            if (Compare.AreEqual(hash, _expected256) == false)
                throw new Exception("Skein256: Hash values are not equal! Expected: " + Hex.ToString(_expected256) + "Received: " + Hex.ToString(hash));
            OnProgress(new TestEventArgs("Passed Skein 256 bit digest vector tests.."));

            // test vector for the 512 and 1024-bit hash
            testVector = new byte[128];
            for (int i = 0; i < testVector.Length; i++)
                testVector[i] = (byte)(255 - i);

            using (Skein512 skein512 = new Skein512())
            {
                hash = skein512.ComputeHash(testVector);
                hash = skein512.ComputeHash(testVector);
            }

            if (Compare.AreEqual(hash, _expected512) == false)
                throw new Exception("Skein512: Hash values are not equal! Expected: " + Hex.ToString(_expected512) + "Received: " + Hex.ToString(hash));
            OnProgress(new TestEventArgs("Passed Skein 512 bit digest vector tests.."));

            using (Skein1024 skein1024 = new Skein1024())
            {
                hash = skein1024.ComputeHash(testVector);
                hash = skein1024.ComputeHash(testVector);
            }

            if (Compare.AreEqual(hash, _expected1024) == false)
                throw new Exception("Skein1024: Hash values are not equal! Expected: " + Hex.ToString(_expected1024) + "Received: " + Hex.ToString(hash));
            OnProgress(new TestEventArgs("Passed Skein 1024 bit digest vector tests.."));

            return true;
        }
        #endregion
    }
}
