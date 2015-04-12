#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Utility;
using VTDev.Projects.CEX.Test.Helper;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.CipherTest
{
    /// <summary>
    /// Vectors used by BouncyCastle:
    /// http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/test/Salsa20Test.java
    /// </summary>
    public class SalsaTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Salsa20 Known Answer Tests.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Salsa20 tests have executed succesfully.";
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
        private static byte[] _plainText = Hex.Decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        private static readonly byte[][] _key = 
        {
            Hex.Decode("80000000000000000000000000000000"),//20-1
            Hex.Decode("00400000000000000000000000000000"),//20-2
            Hex.Decode("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
            Hex.Decode("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12")
        };
        private static readonly byte[][] _iv = 
        {
            Hex.Decode("0000000000000000"),
            Hex.Decode("0D74DB42A91077DE"),
            Hex.Decode("167DE44BB21980E7"),
        };
        private static readonly byte[][] _cipherText = 
        {
            Hex.Decode("4DFA5E481DA23EA09A31022050859936DA52FCEE218005164F267CB65F5CFD7F2B4F97E0FF16924A52DF269515110A07F9E460BC65EF95DA58F740B7D1DBB0AA"), //20r-1
            Hex.Decode("0471076057830FB99202291177FBFE5D38C888944DF8917CAB82788B91B53D1CFB06D07A304B18BB763F888A61BB6B755CD58BEC9C4CFB7569CB91862E79C459"), //20r-2
            Hex.Decode("FC207DBFC76C5E1774961E7A5AAD09069B2225AC1CE0FE7A0CE77003E7E5BDF8B31AF821000813E6C56B8C1771D6EE7039B2FBD0A68E8AD70A3944B677937897"), //12r
            Hex.Decode("A9C9F888AB552A2D1BBFF9F36BEBEB337A8B4B107C75B63BAE26CB9A235BBA9D784F38BEFC3ADF4CD3E266687EA7B9F09BA650AE81EAC6063AE31FF12218DDC5"), //8r
            Hex.Decode("F5FAD53F79F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EAF24CE493A86263F677B46ACE1924773D2BB25571E1AA8593758FC382B1280B71"), //20r-256k
            Hex.Decode("3944F6DC9F85B128083879FDF190F7DEE4053A07BC09896D51D0690BD4DA4AC1062F1E47D3D0716F80A9B4D85E6D6085EE06947601C85F1A27A2F76E45A6AA87")  //20r-256k
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
                VectorTest(8, _key[0], _iv[0], _plainText, _cipherText[3]);
                OnProgress(new TestEventArgs("Passed 8 and 12 round vector tests.."));
                VectorTest(20, _key[2], _iv[1], _plainText, _cipherText[4]);
                VectorTest(20, _key[3], _iv[2], _plainText, _cipherText[5]);
                OnProgress(new TestEventArgs("Passed 256 bit key vector tests.."));

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
        private void VectorTest(int Rounds, byte[] Key, byte[] Vector, byte[] Input, byte[] Output)
        {
            byte[] outBytes = new byte[Input.Length];

            using (Salsa20 salsa = new Salsa20(Rounds))
            {
                salsa.Initialize(new KeyParams(Key, Vector));
                salsa.Transform(Input, 0, Input.Length, outBytes, 0);

                if (Compare.AreEqual(outBytes, Output) == false)
                    throw new Exception("Salsa20: Encrypted arrays are not equal! Expected: " + Hex.ToString(Output) + "Received: " + Hex.ToString(outBytes));

                salsa.Initialize(new KeyParams(Key, Vector));
                salsa.Transform(Output, 0, Output.Length, outBytes, 0);

                if (Compare.AreEqual(outBytes, Input) == false)
                    throw new Exception("Salsa20: Decrypted arrays are not equal! Expected: " + Hex.ToString(Input) + "Received: " + Hex.ToString(outBytes));
            }
        }
        #endregion
    }
}
