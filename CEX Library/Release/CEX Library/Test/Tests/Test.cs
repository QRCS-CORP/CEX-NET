using System;
using System.Collections.Generic;
using VTDev.Projects.CEX.Test.Tests.DigestTest;
using VTDev.Projects.CEX.Test.Tests.MacTest;
using VTDev.Projects.CEX.Test.Tests.PrngTest;
using VTDev.Projects.CEX.Test.Tests.SpeedTest;
using VTDev.Libraries.CEXEngine.Crypto;

namespace VTDev.Projects.CEX.Test.Tests
{
    /// <summary>
    /// Wrapper class for various vector, equality, speed and IO tests
    /// </summary>
    static class Test
    {
        #region Enums
        /// <summary>
        /// The available range of Test types.
        /// Used to set the Test 'ParametersKey' property.
        /// </summary>
        internal enum Tests
        {
            /// <summary>
            /// AES specification tests: ascending key and text
            /// </summary>
            AesAvs,
            /// <summary>
            /// FIPS 197 and Gladman AES Monte Carlo tests
            /// </summary>
            AesMonteCarlo,
            /// <summary>
            /// Compares using ChaCha KAT Vectors used by BouncyCastle
            /// </summary>
            ChaChaVector,
            /// <summary>
            /// KAT vectors from RFC 5869
            /// </summary>
            HKDFVector,
            /// <summary>
            /// Compares HMAC Known answer tests from RFC 4321
            /// </summary>
            HmacVector,
            /// <summary>
            /// Compares PSC mode transform input/output vectors against CTR output
            /// </summary>
            ModePSCEquality,
            /// <summary>
            /// Tests mode vectors from NIST SP 800-38A
            /// </summary>
            ModeVectors,
            /// <summary>
            /// Tests transform output vectors, and basic I/O operations
            /// </summary>
            RijndaelIO,
            /// <summary>
            /// Tests Rijndael input/output vectors
            /// </summary>
            RijndaelVector,
            /// <summary>
            /// Compares using Salsa20 KAT Vectors used by BouncyCastle
            /// </summary>
            SalsaVector,
            /// <summary>
            /// Compares routine used in RSX key scheduler to Bouncy Castle key scheduler
            /// </summary>
            SerpentKey,
            /// <summary>
            /// Compares using Nessie Serpent Vectors
            /// </summary>
            SerpentVector,
            /// <summary>
            /// Compares SHA-2 output with NIST vectors
            /// </summary>
            Sha2Vector,
            /// <summary>
            /// Compares SHA-3 output with NIST vectors
            /// </summary>
            Sha3Vector,
            /// <summary>
            /// Compares using official Twofish Vectors
            /// </summary>
            TwofishVector
        }
        #endregion

        #region Constructor
        static Test()
        {
            // set default tests (all)
            ParametersKey = TestParams;
        }
        #endregion
        
        #region Fields
        /// <summary>
        /// List of available test names
        /// </summary>
        public readonly static string[] TestNames = new string[] { 
            "AesAvs", 
            "AesMonteCarlo", 
            "ChaChaVector",
            "HKDFVector",
            "HmacVector",
            "ModePSCEquality", 
            "ModeVectors", 
            "RijndaelIO", 
            "RijndaelVector", 
            "SalsaVector",
            "SerpentKey",
            "SerpentVector",
            "Sha2Vector",
            "Sha3Vector",
            "TwofishVector"
            };
        
        /// <summary>
        /// Default state for the Run() method. Use the Parameters property to add or remove tests
        /// </summary>
        private static readonly Dictionary<Tests, bool> TestParams = new Dictionary<Tests, bool>() {  
            {Tests.AesAvs, true},
            {Tests.AesMonteCarlo, true},
            {Tests.ChaChaVector, true},
            {Tests.HKDFVector, true},
            {Tests.HmacVector, true},
            {Tests.ModePSCEquality, true},
            {Tests.ModeVectors, true},
            {Tests.RijndaelIO, true},
            {Tests.RijndaelVector, true},
            {Tests.SalsaVector, true},
            {Tests.SerpentKey, true},
            {Tests.SerpentVector, true},
            {Tests.Sha2Vector, true},
            {Tests.Sha3Vector, true},
            {Tests.TwofishVector, true}
        };
        
        /// <summary>
        /// Test descriptions
        /// </summary>
        private static readonly Dictionary<Tests, string> TestDescription = new Dictionary<Tests, string>() {  
            {Tests.AesAvs, "NIST AESAVS incrementing key and text 128/192/256 (960 vectors)"},
            {Tests.AesMonteCarlo, "AES: FIPS 197 KAT and Gladman Monte Carlo vectors"},
            {Tests.ChaChaVector, "ChaCha Known answer tests"},
            {Tests.HKDFVector, "HKDF KAT vectors from RFC 5869"},
            {Tests.HmacVector, "Compares HMAC Known answer tests from RFC 4321"},
            {Tests.ModePSCEquality, "PSC mode output compared to SIC"},
            {Tests.ModeVectors, "CBC/CTR/ECB vectors from NIST SP 800-38A"},
            {Tests.RijndaelIO, "Test output vectors and I/O operations"},
            {Tests.RijndaelVector, "Tests Rijndael input/output vectors"},
            {Tests.SalsaVector, "Tests Salsa20 input/output vectors"},
            {Tests.SerpentKey, "Compare Serpent and RSX key scheduler outputs"},
            {Tests.SerpentVector, "Nessie Serpent KAT and Monte Carlo vectors"},
            {Tests.Sha2Vector, "SHA-2 256/512 Known Answer Tests"},
            {Tests.Sha3Vector, "Tests SHA-3 224/256/384/512 and HMACs"},
            {Tests.TwofishVector, "Tests Twofish 128/192/256 KAT vectors"}
        };
        #endregion

        #region Properties
        /// <summary>
        /// Select or deselect a test with this property: true/false. The key value is a member of 'Tests'.
        /// Usage: ParametersKey[Tests.ApproximateEntropy] = false;
        /// </summary>
        public static Dictionary<Tests, bool> ParametersKey { get; set; }
        #endregion

        #region Progress
        public static event Action<int, string> ProgressChanged;
        private static void OnProgressChanged(int value, string message)
        {
            var progress = ProgressChanged;
            if (progress != null)
                progress(value, message);
        }

        internal static int ProgressMax()
        {
            // get the number of tests
            int testCount = 0;

            foreach (var test in TestParams)
                testCount += test.Value == true ? 1 : 0;

            return testCount;
        }
        #endregion

        #region Public
        /// <summary>
        /// Get test results from various tests
        /// </summary>
        /// <returns>Results dictionary [key: Tests.(testname) : value]</returns>
        internal static Dictionary<string, string> Run()
        {
            bool state = false;
            
            // create the results dictionary
            Dictionary<string, string> testResults = new Dictionary<string, string>();

            // run the tests..
            if (ParametersKey[Tests.AesAvs])
            {
                state = AesAvsTest();
                testResults.Add("AesAvs", TestDescription[Tests.AesAvs] + "," + State(state));
                OnProgressChanged(1, "AesAvs Completed..");
            }
            if (ParametersKey[Tests.AesMonteCarlo])
            {
                state = AesMonteCarloTest();
                testResults.Add("AesMonteCarlo", TestDescription[Tests.AesMonteCarlo] + "," + State(state));
                OnProgressChanged(1, "AesMonteCarlo Completed..");
            }
            if (ParametersKey[Tests.ChaChaVector])
            {
                state = ChaChaVectorTest();
                testResults.Add("ChaChaVector", TestDescription[Tests.ChaChaVector] + "," + State(state));
                OnProgressChanged(1, "ChaChaVector Completed..");
            }
            if (ParametersKey[Tests.HKDFVector])
            {
                state = HKDFVectorTest();
                testResults.Add("HKDFVector", TestDescription[Tests.HKDFVector] + "," + State(state));
                OnProgressChanged(1, "HKDFVector Completed..");
            }
            if (ParametersKey[Tests.HmacVector])
            {
                state = HmacVectorTest();
                testResults.Add("HmacVector", TestDescription[Tests.HmacVector] + "," + State(state));
                OnProgressChanged(1, "HmacVector Completed..");
            }
            if (ParametersKey[Tests.ModePSCEquality])
            {
                state = ModePSCEqualityTest();
                testResults.Add("ModePSCEquality", TestDescription[Tests.ModePSCEquality] + "," + State(state));
                OnProgressChanged(1, "ModePSCEquality Completed..");
            }
            if (ParametersKey[Tests.ModeVectors])
            {
                state = ModeVectorTest();
                testResults.Add("ModeVector", TestDescription[Tests.ModeVectors] + "," + State(state));
                OnProgressChanged(1, "ModeVector Completed..");
            }
            if (ParametersKey[Tests.RijndaelIO])
            {
                state = RijndaelIOTest();
                testResults.Add("RijndaelIO", TestDescription[Tests.RijndaelIO] + "," + State(state));
                OnProgressChanged(1, "RijndaelIO Completed..");
            }
            if (ParametersKey[Tests.RijndaelVector])
            {
                state = RijndaelVectorTest();
                testResults.Add("RijndaelVector", TestDescription[Tests.RijndaelVector] + "," + State(state));
                OnProgressChanged(1, "RijndaelVector Completed..");
            }
            if (ParametersKey[Tests.SalsaVector])
            {
                state = SalsaVectorTest();
                testResults.Add("SalsaVector", TestDescription[Tests.SalsaVector] + "," + State(state));
                OnProgressChanged(1, "SalsaVector Completed..");
            }
            if (ParametersKey[Tests.SerpentKey])
            {
                state = SerpentKeyTest();
                testResults.Add("SerpentKey", TestDescription[Tests.SerpentKey] + "," + State(state));
                OnProgressChanged(1, "Serpent Key Completed..");
            }
            if (ParametersKey[Tests.SerpentVector])
            {
                state = SerpentVectorTest();
                testResults.Add("SerpentVector", TestDescription[Tests.SerpentVector] + "," + State(state));
                OnProgressChanged(1, "Serpent Vector Completed..");
            }
            if (ParametersKey[Tests.Sha2Vector])
            {
                state = Sha2VectorTest();
                testResults.Add("SHA2Vector", TestDescription[Tests.Sha2Vector] + "," + State(state));
                OnProgressChanged(1, "SHA2 Vector Completed..");
            }
            if (ParametersKey[Tests.Sha3Vector])
            {
                state = Sha3VectorTest();
                testResults.Add("SHA3Vector", TestDescription[Tests.Sha3Vector] + "," + State(state));
                OnProgressChanged(1, "SHA3 Vector Completed..");
            }
            if (ParametersKey[Tests.TwofishVector])
            {
                state = TwofishVectorTest();
                testResults.Add("TwofishVector", TestDescription[Tests.TwofishVector] + "," + State(state));
                OnProgressChanged(1, "Twofish Vector Completed..");
            }
            return testResults;
        }
        #endregion

        #region Private
        /// <summary>
        /// NIST Advanced Encryption Standard Algorithm Validation Suite (AESAVS), 960 tests total.
        /// AESAVS certification vectors: http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf
        /// </summary>
        private static bool AesAvsTest()
        {
            return (new AesAvsTest().Test());
        }

        /// <summary>
        /// KAT vectors from the NIST standard tests contained in the AES specification document FIPS 197:
        /// <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"></a>
        /// Monte Carlo AES tests from the Brian Gladman's vector set:
        /// <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/"></a>
        /// </summary>
        /// <returns>Number of Tests passed (12 total)</returns>
        private static bool AesMonteCarloTest()
        {
            return new AesFipsTest().Test();
        }

        /// <summary>
        /// KAT Vectors used by BouncyCastle:
        /// http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/test/ChaChaTest.java
        /// Test cases generated using ref version of ChaCha20 in estreambench-20080905
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool ChaChaVectorTest()
        {
            return new ChaChaTest().Test();
        }

        /// <summary>
        /// KAT vectors from RFC 5869: 'HMAC-based Extract-and-Expand Key Derivation Function (HKDF)':
        /// http://tools.ietf.org/html/rfc5869
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool HKDFVectorTest()
        {
            return new HkdfTest().Test();
        }

        /// <summary>
        /// KAT vectors from RFC 4321: 'Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512':
        /// http://tools.ietf.org/html/rfc4231
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool HmacVectorTest()
        {
            return new HmacTest().Test();
        }

        /// <summary>
        /// KAT vectors from NIST Special Publication 800-38A:
        /// http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool ModeVectorTest()
        {
            return new CipherModeTest().Test();
        }

        /// <summary>
        /// Compares PSC mode transform input/output vectors against CTR output
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool ModePSCEqualityTest()
        {
            return new ParallelModeTest().Test();
        }

        /// <summary>
        /// Tests transform output vectors, and basic I/O operations
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool RijndaelIOTest()
        {
            return new IOTest().Test();
        }

        /// <summary>
        /// Test vectors derived from Bouncy Castle RijndaelTest.cs and the Nessie unverified vectors:
        /// <a href="https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/Rijndael-256-256.unverified.test-vectors"></a>
        /// Tests support block sizes of 16 and 32 bytes.
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool RijndaelVectorTest()
        {
            return new RijndaelTest().Test();
        }

        /// <summary>
        /// Tests Salsa20 input/output vectors
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool SalsaVectorTest()
        {
            return new SalsaTest().Test();
        }

        /// <summary>
        /// Compares Serpents Key scheduler output to RSX
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool SerpentKeyTest()
        {
            return new SerpentKeyTest().Test();
        }

        /// <summary>
        /// The full Nessie verified vector tests, (2865 tests in total).
        /// Throws on all failures.
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool SerpentVectorTest()
        {
            return new SerpentTest().Test();
        }

        /// <summary>
        /// NIST SHA-2 KAT vectors:
        /// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
        /// standard: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool Sha2VectorTest()
        {
            return new Sha2Test().Test();
        }

        /// <summary>
        /// A range of Vector KATs; tests SHA-3 224/256/384/512 and HMACs.
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool Sha3VectorTest()
        {
            return new KeccakTest().Test();
        }

        /// <summary>
        /// The full set of Twofish ECB key vector tests.
        /// https://www.schneier.com/twofish.html
        /// Throws on all failures.
        /// </summary>
        /// <returns>Success [bool]</returns>
        private static bool TwofishVectorTest()
        {
            return new TwofishTest().Test();
        }
        #endregion

        #region Helpers
        private static string State(bool Value)
        {
            return Value == true ? "PASS" : "FAIL";
        }
        #endregion
    }
}