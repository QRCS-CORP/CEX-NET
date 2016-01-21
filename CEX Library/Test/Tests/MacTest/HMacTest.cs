#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.MacTest
{
    /// <summary>
    /// SHA-2 Test vectors for 256 and 512 bit Kats.
    /// RFC 4321: Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512.
    /// http://tools.ietf.org/html/rfc4231
    /// </summary>
    public class HMacTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "RFC 4321 Test Vectors for HMAC SHA224, SHA256, SHA384, and SHA512.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! All HMAC tests have executed succesfully.";
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
        private static readonly byte[][] _keys =
		{
            // test case 1
			HexConverter.Decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            // test case 2
			HexConverter.Decode("4a656665"),
            // test case 3
			HexConverter.Decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            // test case 4
            HexConverter.Decode("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            // test case 5
			HexConverter.Decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
            // test case 6
            HexConverter.Decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + 
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + 
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            // test case 7
            HexConverter.Decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + 
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + 
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		};

        private static readonly byte[][] _plainText =
		{
			HexConverter.Decode("4869205468657265"),
			HexConverter.Decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),
			HexConverter.Decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
            HexConverter.Decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
			HexConverter.Decode("546573742057697468205472756e636174696f6e"),
            HexConverter.Decode("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"),
			HexConverter.Decode("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074" + 
            "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365" + 
            "642062792074686520484d414320616c676f726974686d2e")
		};

        private static readonly byte[][] _hashValue =
		{
            // 256 answer
			HexConverter.Decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            // 512 answer
			HexConverter.Decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),

			HexConverter.Decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            HexConverter.Decode("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),

			HexConverter.Decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            HexConverter.Decode("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"),

			HexConverter.Decode("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            HexConverter.Decode("b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"),

			HexConverter.Decode("a3b6167473100ee06e0c796c2955552b"), //truncated
			HexConverter.Decode("415fad6271580a531d4179bc891d87a6"),

            HexConverter.Decode("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
            HexConverter.Decode("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"),

            HexConverter.Decode("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
            HexConverter.Decode("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")
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
        /// Full set of test vectors from RFC 4321.
        /// Tests HMAC interface, SHA-2, and combined SHA-2/HMAC implementations.
        /// Throws exception on all failures.
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                for (int i = 0, j = 0; i < _plainText.Length; i++, j += 2)
                    MacTest(_keys[i], _plainText[i], _hashValue[j], _hashValue[j + 1]);
                OnProgress(new TestEventArgs("Passed 14 HMAC vector tests.."));
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
        private void MacTest(byte[] Key, byte[] Input, byte[] Out256, byte[] Out512)
        {
            byte[] hash = new byte[32];
            byte[] trnHash;

            // test 1: HMAC interface
            HMAC hmac1 = new HMAC(new SHA256());
            hmac1.Initialize(Key);
            hash = hmac1.ComputeMac(Input);

            // truncated output, test case #5
            if (Out256.Length != 32) 
            {
                trnHash = new byte[Out256.Length];
                Buffer.BlockCopy(hash, 0, trnHash, 0, Out256.Length);

                if (!Evaluate.AreEqual(Out256, trnHash))
                    throw new Exception("HMAC is not equal! Expected: " + HexConverter.ToString(Out256) + " Received: " + HexConverter.ToString(trnHash));
            }
            else
            {
                if (!Evaluate.AreEqual(Out256, hash))
                    throw new Exception("HMAC is not equal! Expected: " + HexConverter.ToString(Out256) + " Received: " + HexConverter.ToString(hash));
            }

            // test 2: 256 hmac
            using (HMAC hmac2 = new HMAC(new SHA256()))
            {
                hmac2.Initialize(Key);
                hash = hmac2.ComputeMac(Input);
            }

            if (Out256.Length != 32)
            {
                trnHash = new byte[Out256.Length];
                Buffer.BlockCopy(hash, 0, trnHash, 0, Out256.Length);

                if (!Evaluate.AreEqual(Out256, trnHash))
                    throw new Exception("HMAC is not equal! Expected: " + HexConverter.ToString(Out256) + " Received: " + HexConverter.ToString(trnHash));
            }
            else
            {
                if (!Evaluate.AreEqual(Out256, hash))
                    throw new Exception("HMAC is not equal! Expected: " + HexConverter.ToString(Out256) + " Received: " + HexConverter.ToString(hash));
            }

            hash = new byte[32];

            // test 3: HMAC interface
            hmac1 = new HMAC(new SHA512());
            hmac1.Initialize(Key);
            hash = hmac1.ComputeMac(Input);

            if (Out512.Length != 64)
            {
                trnHash = new byte[Out512.Length];
                Buffer.BlockCopy(hash, 0, trnHash, 0, Out512.Length);

                if (!Evaluate.AreEqual(Out512, trnHash))
                    throw new Exception("HMAC is not equal! Expected: " + HexConverter.ToString(Out512) + " Received: " + HexConverter.ToString(trnHash));
            }
            else
            {
                if (!Evaluate.AreEqual(Out512, hash))
                    throw new Exception("HMAC is not equal! Expected: " + HexConverter.ToString(Out512) + " Received: " + HexConverter.ToString(hash));
            }

            // test 4: 512 hmac
            using (HMAC hmac3 = new HMAC(new SHA512()))
            {
                hmac3.Initialize(Key);
                hash = hmac3.ComputeMac(Input);
            }

            if (Out512.Length != 64)
            {
                trnHash = new byte[Out512.Length];
                Buffer.BlockCopy(hash, 0, trnHash, 0, Out512.Length);

                if (!Evaluate.AreEqual(Out512, trnHash))
                    throw new Exception("HMAC is not equal! Expected: " + HexConverter.ToString(Out512) + " Received: " + HexConverter.ToString(trnHash));
            }
            else
            {
                if (!Evaluate.AreEqual(Out512, hash))
                    throw new Exception("HMAC is not equal! Expected: " + HexConverter.ToString(Out512) + " Received: " + HexConverter.ToString(hash));
            }
        }
        #endregion
    }
}
