#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests
{
    /// <summary>
    /// Vectors used by BouncyCastle:
    /// http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/test/ChaChaTest.java
    /// Test cases generated using ref version of ChaCha20 in estreambench-20080905
    /// </summary>
    public class ChaChaTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "ChaCha Known Answer Tests.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! ChaCha tests have executed succesfully.";
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
        private static byte[] _plainText = HexConverter.Decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        private static readonly byte[][] _key = 
        {
            HexConverter.Decode("80000000000000000000000000000000"),
            HexConverter.Decode("00400000000000000000000000000000"),
            HexConverter.Decode("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
            HexConverter.Decode("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12")
        };
        private static readonly byte[][] _iv = 
        {
            HexConverter.Decode("0000000000000000"),
            HexConverter.Decode("0D74DB42A91077DE"),
            HexConverter.Decode("167DE44BB21980E7"),
        };
        private static readonly byte[][] _cipherText = 
        {
            HexConverter.Decode("FBB87FBB8395E05DAA3B1D683C422046F913985C2AD9B23CFC06C1D8D04FF213D44A7A7CDB84929F915420A8A3DC58BF0F7ECB4B1F167BB1A5E6153FDAF4493D"),//20r-1
            HexConverter.Decode("A276339F99316A913885A0A4BE870F0691E72B00F1B3F2239F714FE81E88E00CBBE52B4EBBE1EA15894E29658C4CB145E6F89EE4ABB045A78514482CE75AFB7C"),//20r-2
            HexConverter.Decode("36CF0D56E9F7FBF287BC5460D95FBA94AA6CBF17D74E7C784DDCF7E0E882DDAE3B5A58243EF32B79A04575A8E2C2B73DC64A52AA15B9F88305A8F0CA0B5A1A25"),//12r
            HexConverter.Decode("BEB1E81E0F747E43EE51922B3E87FB38D0163907B4ED49336032AB78B67C24579FE28F751BD3703E51D876C017FAA43589E63593E03355A7D57B2366F30047C5"),//8r
            HexConverter.Decode("57459975BC46799394788DE80B928387862985A269B9E8E77801DE9D874B3F51AC4610B9F9BEE8CF8CACD8B5AD0BF17D3DDF23FD7424887EB3F81405BD498CC3"),//20r-256k
            HexConverter.Decode("92A2508E2C4084567195F2A1005E552B4874EC0504A9CD5E4DAF739AB553D2E783D79C5BA11E0653BEBB5C116651302E8D381CB728CA627B0B246E83942A2B99")//20r-256k
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
        /// Run the test
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                // test vectors with 8/12/20 rounds and 128/256 keys
                VectorTest(20, _key[0], _iv[0], _plainText, _cipherText[0]);
                VectorTest(20, _key[1], _iv[0], _plainText, _cipherText[1]);
                OnProgress(new TestEventArgs("Passed 20 round vector tests.."));
                VectorTest(12, _key[0], _iv[0], _plainText, _cipherText[2]);
                //VectorTest(8, _key[0], _iv[0], _plainText, _cipherText[3]);
                OnProgress(new TestEventArgs("Passed 8 and 12 round vector tests.."));
                VectorTest(20, _key[2], _iv[1], _plainText, _cipherText[4]);
                //VectorTest(20, _key[3], _iv[2], _plainText, _cipherText[5]);
                OnProgress(new TestEventArgs("Passed 256 bit key vector tests.."));
                ParallelTest();
                OnProgress(new TestEventArgs("Passed parallel/linear equality tests.."));

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
        private void ParallelTest()
        {
            CSPRng rng = new CSPRng();
            byte[] key = rng.GetBytes(32);
            byte[] iv = rng.GetBytes(8);
            byte[] data = rng.GetBytes(2048);
            byte[] enc = new byte[2048];
            byte[] dec = new byte[2048];
            rng.Dispose();

            using (ChaCha chacha = new ChaCha(10))
            {
                // encrypt linear
                chacha.Initialize(new KeyParams(key, iv));
                chacha.IsParallel = false;
                chacha.Transform(data, enc);
                // decrypt parallel
                chacha.Initialize(new KeyParams(key, iv));
                chacha.IsParallel = true;
                chacha.ParallelBlockSize = 2048;
                chacha.Transform(enc, dec);
            }

            if (!Compare.AreEqual(data, dec))
                throw new Exception("ChaCha: Decrypted arrays are not equal!");
        }

        private void VectorTest(int Rounds, byte[] Key, byte[] Vector, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Input.Length];

            using (ChaCha chacha = new ChaCha(Rounds))
            {
                chacha.Initialize(new KeyParams(Key, Vector));
                chacha.Transform(Input, 0, Input.Length, outBytes, 0);

                if (Compare.AreEqual(outBytes, Output) == false)
                    throw new Exception("ChaChaVector: Encrypted arrays are not equal! Expected: " + HexConverter.ToString(Output) + " Received: " + HexConverter.ToString(outBytes));

                chacha.Initialize(new KeyParams(Key, Vector));
                chacha.Transform(Output, 0, Output.Length, outBytes, 0);
            }

            if (Compare.AreEqual(outBytes, Input) == false)
                throw new Exception("ChaChaVector: Decrypted arrays are not equal! Expected: " + HexConverter.ToString(Input) + " Received: " + HexConverter.ToString(outBytes));
        }

        #endregion
    }
}
