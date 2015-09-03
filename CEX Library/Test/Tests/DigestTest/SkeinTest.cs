#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.DigestTest
{
    /// <summary>
    /// Tests the 256, 512, and 1024 bit versions of Skein against known test vectors from the skein 1.3 document, appendix C.
    /// http://www.skein-hash.info/sites/default/files/skein1.3.pdf
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
        private byte[] _msg256N1 = HexConverter.Decode("FF");
        private byte[] _msg256N2 = HexConverter.Decode("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0");
        private byte[] _msg256N3 = HexConverter.Decode("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0");

        private byte[] _msg512N1 = HexConverter.Decode("FF");
        private byte[] _msg512N2 = HexConverter.Decode("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0");
        private byte[] _msg512N3 = HexConverter.Decode("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180");

        private byte[] _msg1024N1 = HexConverter.Decode("FF");
        private byte[] _msg1024N2 = HexConverter.Decode("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180");
        private byte[] _msg1024N3 = HexConverter.Decode("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");

        private byte[] _exp256N1 = HexConverter.Decode("0B98DCD198EA0E50A7A244C444E25C23DA30C10FC9A1F270A6637F1F34E67ED2");
        private byte[] _exp256N2 = HexConverter.Decode("8D0FA4EF777FD759DFD4044E6F6A5AC3C774AEC943DCFC07927B723B5DBF408B");
        private byte[] _exp256N3 = HexConverter.Decode("DF28E916630D0B44C4A849DC9A02F07A07CB30F732318256B15D865AC4AE162F");

        private byte[] _exp512N1 = HexConverter.Decode("71B7BCE6FE6452227B9CED6014249E5BF9A9754C3AD618CCC4E0AAE16B316CC8CA698D864307ED3E80B6EF1570812AC5272DC409B5A012DF2A579102F340617A");
        private byte[] _exp512N2 = HexConverter.Decode("45863BA3BE0C4DFC27E75D358496F4AC9A736A505D9313B42B2F5EADA79FC17F63861E947AFB1D056AA199575AD3F8C9A3CC1780B5E5FA4CAE050E989876625B");
        private byte[] _exp512N3 = HexConverter.Decode("91CCA510C263C4DDD010530A33073309628631F308747E1BCBAA90E451CAB92E5188087AF4188773A332303E6667A7A210856F742139000071F48E8BA2A5ADB7");

        private byte[] _exp1024N1 = HexConverter.Decode("E62C05802EA0152407CDD8787FDA9E35703DE862A4FBC119CFF8590AFE79250BCCC8B3FAF1BD2422AB5C0D263FB2F8AFB3F796F048000381531B6F00D85161BC0FFF4BEF2486B1EBCD3773FABF50AD4AD5639AF9040E3F29C6C931301BF79832E9DA09857E831E82EF8B4691C235656515D437D2BDA33BCEC001C67FFDE15BA8");
        private byte[] _exp1024N2 = HexConverter.Decode("1F3E02C46FB80A3FCD2DFBBC7C173800B40C60C2354AF551189EBF433C3D85F9FF1803E6D920493179ED7AE7FCE69C3581A5A2F82D3E0C7A295574D0CD7D217C484D2F6313D59A7718EAD07D0729C24851D7E7D2491B902D489194E6B7D369DB0AB7AA106F0EE0A39A42EFC54F18D93776080985F907574F995EC6A37153A578");
        private byte[] _exp1024N3 = HexConverter.Decode("842A53C99C12B0CF80CF69491BE5E2F7515DE8733B6EA9422DFD676665B5FA42FFB3A9C48C217777950848CECDB48F640F81FB92BEF6F88F7A85C1F7CD1446C9161C0AFE8F25AE444F40D3680081C35AA43F640FD5FA3C3C030BCC06ABAC01D098BCC984EBD8322712921E00B1BA07D6D01F26907050255EF2C8E24F716C52A5");
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
                DigestTest(_msg256N1, _exp256N1);
                DigestTest(_msg256N2, _exp256N2);
                DigestTest(_msg256N3, _exp256N3);
                OnProgress(new TestEventArgs("Passed Skein 256 bit digest vector tests.."));

                DigestTest(_msg512N1, _exp512N1);
                DigestTest(_msg512N2, _exp512N2);
                DigestTest(_msg512N3, _exp512N3);
                OnProgress(new TestEventArgs("Passed Skein 512 bit digest vector tests.."));

                DigestTest(_msg1024N1, _exp1024N1);
                DigestTest(_msg1024N2, _exp1024N2);
                DigestTest(_msg1024N3, _exp1024N3);
                OnProgress(new TestEventArgs("Passed Skein 1024 bit digest vector tests.."));

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
        private void DigestTest(byte[] Data, byte[] Expected)
        {
            byte[] hash = new byte[0];
            // Make test vector for 256-bit hash
            if (Expected.Length == 32)
            {
                using (Skein256 skein256 = new Skein256())
                    hash = skein256.ComputeHash(Data);
            }
            else if (Expected.Length == 64)
            {
                using (Skein512 skein512 = new Skein512())
                    hash = skein512.ComputeHash(Data);
            }
            else
            {
                using (Skein1024 skein1024 = new Skein1024())
                    hash = skein1024.ComputeHash(Data);
            }

            if (Compare.AreEqual(hash, Expected) == false)
                throw new Exception("Skein256: Hash values are not equal! Expected: " + HexConverter.ToString(Expected) + " Received: " + HexConverter.ToString(hash));
        }
        #endregion
    }
}
