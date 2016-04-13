#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Processing;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Projects.CEX.Test.Tests.ProcessingTest
{
    /// <summary>
    /// Tests the SecureRandom and Prng access methods and return ranges
    /// </summary>
    public class CipherStreamTest : ITest
    {
        #region Constants
        private string DESCRIPTION = "PRNG Test: Tests I/O, access methods, and expected return ranges.";
        private string FAILURE = "FAILURE! ";
        private string SUCCESS = "SUCCESS! All PRNG tests have executed succesfully.";
        private int MIN_ALLOC = 512;
		private int MAX_ALLOC = 4096;
        #endregion

        #region Fields
        private byte[] _cmpText = new byte[0];
        private byte[] _decText = new byte[0];
        private byte[] _encText = new byte[0];
        private byte[] _iv = new byte[16];
        private byte[] _key = new byte[32];
        private byte[] _plnText = new byte[0];
        private int _processorCount = 0;
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

        #region Constructor
        public CipherStreamTest()
        {
            _processorCount = VTDev.Libraries.CEXEngine.Utility.ParallelUtils.ProcessorCount;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Tests the SecureRandom access methods and return ranges
        /// </summary>
        /// <returns>Status</returns>
        public string Run()
        {
            try
            {
                CbcModeTest();
				OnProgress(new TestEventArgs("Passed CBC Mode tests.."));
				CfbModeTest();
				OnProgress(new TestEventArgs("Passed CFB Mode tests.."));
				CtrModeTest();
				OnProgress(new TestEventArgs("Passed CTR Mode tests.."));
				OfbModeTest();
				OnProgress(new TestEventArgs("Passed OFB Mode tests.."));
				StreamTest();
                OnProgress(new TestEventArgs("Passed Stream Cipher tests"));

				SerializeStructTest();
				OnProgress(new TestEventArgs("Passed CipherDescription serialization test.."));
				OnProgress(new TestEventArgs(""));

				OnProgress(new TestEventArgs("***Testing Cipher Parameters***.. "));
				ParametersTest();
				OnProgress(new TestEventArgs("Passed Cipher Parameters test.."));

				RHX eng = new RHX();
				OnProgress(new TestEventArgs("***Testing Padding Modes***.."));
				StreamModesTest(new CBC(eng, false), new X923());
				OnProgress(new TestEventArgs("Passed CBC/X923 CipherStream test.."));
				StreamModesTest(new CBC(eng, false), new PKCS7());
				OnProgress(new TestEventArgs("Passed CBC/PKCS7 CipherStream test.."));
                StreamModesTest(new CBC(eng, false), new TBC());
				OnProgress(new TestEventArgs("Passed CBC/TBC CipherStream test.."));
				StreamModesTest(new CBC(eng, false), new ISO7816());
				OnProgress(new TestEventArgs("Passed CBC/ISO7816 CipherStream test.."));
				OnProgress(new TestEventArgs(""));

				OnProgress(new TestEventArgs("***Testing Cipher Modes***.."));
				StreamModesTest(new CTR(eng, false), new ISO7816());
				OnProgress(new TestEventArgs("Passed CTR CipherStream test.."));
				StreamModesTest(new CFB(eng, 128, false), new ISO7816());
				OnProgress(new TestEventArgs("Passed CFB CipherStream test.."));
				StreamModesTest(new OFB(eng, false), new ISO7816());
				OnProgress(new TestEventArgs("Passed OFB CipherStream test.."));
				OnProgress(new TestEventArgs(""));
				eng.Dispose();

				OnProgress(new TestEventArgs("***Testing Stream Ciphers***.."));
				StreamingTest(new ChaCha());
				OnProgress(new TestEventArgs("Passed ChaCha CipherStream test.."));
				StreamingTest(new Salsa20());
				OnProgress(new TestEventArgs("Passed Salsa20 CipherStream test.."));
				OnProgress(new TestEventArgs(""));

				OnProgress(new TestEventArgs("***Testing Cipher Description Initialization***.."));
				CipherDescription cd = new CipherDescription(
					SymmetricEngines.RHX,		// cipher engine
					32,							// key size in bytes
					IVSizes.V128,				// cipher iv size
					CipherModes.CTR,			// cipher mode
					PaddingModes.ISO7816,		// cipher padding
					BlockSizes.B128,			// cipher block size
					RoundCounts.R14,			// number of transformation rounds
					Digests.None,			    // optional key schedule engine (HX ciphers)
					0,							// optional HMAC size
					Digests.None);		        // optional HMAC engine

				DescriptionTest(cd);
				OnProgress(new TestEventArgs("Passed CipherDescription stream test.."));
				OnProgress(new TestEventArgs(""));

				OnProgress(new TestEventArgs("***Testing Block Ciphers***.. "));
				THX tfx = new THX();
				StreamModesTest(new CBC(tfx, false), new ISO7816());
				tfx.Dispose();
				OnProgress(new TestEventArgs("Passed THX CipherStream test.."));
				SHX spx = new SHX();
				StreamModesTest(new CBC(spx, false), new ISO7816());
                spx.Dispose();
				OnProgress(new TestEventArgs("Passed SHX CipherStream test.."));

				Array.Resize(ref _key, 192);
				for (int i = 0; i < 192; i++)
					_key[i] = (byte)i;

				// test extended ciphers
				RHX rhx = new RHX();
				StreamModesTest(new CBC(rhx, false), new ISO7816());
                rhx.Dispose();
				OnProgress(new TestEventArgs("Passed RHX CipherStream test.."));
				SHX shx = new SHX();
				StreamModesTest(new CBC(shx, false), new ISO7816());
                shx.Dispose();
				OnProgress(new TestEventArgs("Passed SHX CipherStream test.."));
				THX thx = new THX();
				StreamModesTest(new CBC(thx, false), new ISO7816());
                thx.Dispose();
				OnProgress(new TestEventArgs("Passed THX CipherStream test.."));
				OnProgress(new TestEventArgs(""));

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
		private void CbcModeTest()
		{
			AllocateRandom(ref _iv, 16);
			AllocateRandom(ref _key, 32);

			KeyParams kp =  new KeyParams(_key, _iv);
			RHX eng = new RHX();
			CBC cipher = new CBC(eng);
			CBC cipher2 = new CBC(eng);
			ISO7816 padding = new ISO7816();
			cipher.IsParallel = false;
			CipherStream cs =  new CipherStream(cipher2, padding);

			for (int i = 0; i < 10; i++)
			{
                int sze = AllocateRandom(ref _plnText, 0, eng.BlockSize);
				int prlBlock = sze - (sze % (cipher.BlockSize * _processorCount));
				_cmpText = new byte[sze];
				_decText = new byte[sze];
				_encText = new byte[sze];

				cipher.ParallelBlockSize = prlBlock;
				cipher2.ParallelBlockSize = prlBlock;
				MemoryStream mIn = new MemoryStream(_plnText);
				MemoryStream mOut = new MemoryStream();
				MemoryStream mRes = new MemoryStream();
					
				// *** Compare encryption output *** //

				// local processor
				cipher.Initialize(true, kp);
                BlockEncrypt(cipher, padding, _plnText, 0, ref _encText, 0);

				// streamcipher linear mode
				cs.IsParallel = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(mIn, mOut);

				if (!Evaluate.AreEqual(mOut.ToArray(), _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher.Initialize(false, kp);
                BlockDecrypt(cipher, padding, _encText, 0, ref _decText, 0);

				if (!Evaluate.AreEqual(_plnText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cs.IsParallel = false;
				mOut.Seek(0, SeekOrigin.Begin);
				cs.Initialize(false, kp);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
                cs.Write(_encText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt parallel mode
				cs.IsParallel = true;
				mOut.Seek(0, SeekOrigin.Begin);
				mRes.Seek(0, SeekOrigin.Begin);
				cs.Initialize(false, kp);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
                Array.Resize(ref _cmpText, _encText.Length);
                cs.Write(_encText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _decText))
                    throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");
			}

			eng.Dispose();
		}

        private void CfbModeTest()
		{
			AllocateRandom(ref _iv, 16);
			AllocateRandom(ref _key, 32);

			KeyParams kp = new KeyParams(_key, _iv);
			RHX eng = new RHX();
			CFB cipher = new CFB(eng);
			CFB cipher2 = new CFB(eng);
			ISO7816 padding = new ISO7816();
			cipher.IsParallel = false;
			CipherStream cs = new CipherStream(cipher2, padding);

			for (int i = 0; i < 10; i++)
			{
                int sze = AllocateRandom(ref _plnText, 0, eng.BlockSize);
				int prlBlock = sze - (sze % (cipher.BlockSize * _processorCount));
				_cmpText = new byte[sze];
				_decText = new byte[sze];
				_encText = new byte[sze];

				cipher.ParallelBlockSize = prlBlock;
				cipher2.ParallelBlockSize = prlBlock;
				MemoryStream mIn = new MemoryStream(_plnText);
				MemoryStream mOut = new MemoryStream();
				MemoryStream mRes = new MemoryStream();

				// *** Compare encryption output *** //

				// local processor
				cipher.Initialize(true, kp);
                BlockEncrypt(cipher, padding, _plnText, 0, ref _encText, 0);

				// streamcipher linear mode
				cs.IsParallel = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(mIn, mOut);

				if (!Evaluate.AreEqual(mOut.ToArray(), _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
                cs.Write(_plnText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher.Initialize(false, kp);
                BlockDecrypt(cipher, padding, _encText, 0, ref _decText, 0);

				if (!Evaluate.AreEqual(_plnText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cs.IsParallel = false;
				mOut.Seek(0, SeekOrigin.Begin);
				cs.Initialize(false, kp);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
                cs.Write(_encText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt parallel mode
				cs.IsParallel = true;
				mOut.Seek(0, SeekOrigin.Begin);
				mRes.Seek(0, SeekOrigin.Begin);
				cs.Initialize(false, kp);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
                Array.Resize(ref _cmpText, _encText.Length);
                cs.Write(_encText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _decText))
                    throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");
			}

			eng.Dispose();
		}

        private void CtrModeTest()
		{
			AllocateRandom(ref _iv, 16);
			AllocateRandom(ref _key, 32);

			KeyParams kp = new KeyParams(_key, _iv);
			RHX eng = new RHX();
			CTR cipher = new CTR(eng);
			CTR cipher2 = new CTR(eng);
			CipherStream cs = new CipherStream(cipher2);
			cipher.IsParallel = false;

			// ctr test
			for (int i = 0; i < 10; i++)
			{
				int sze = AllocateRandom(ref _plnText);
				int prlBlock = sze - (sze % (cipher.BlockSize * _processorCount));
				_encText = new byte[sze];
				_cmpText = new byte[sze];
				_decText = new byte[sze];

				cipher.ParallelBlockSize = prlBlock;
				cipher2.ParallelBlockSize = prlBlock;
				MemoryStream mIn = new MemoryStream(_plnText);
				MemoryStream mOut = new MemoryStream();
				MemoryStream mRes = new MemoryStream();

				// *** Compare encryption output *** //

				// local processor
				cipher.Initialize(true, kp);
				BlockCTR(cipher, _plnText, 0, _encText, 0);

				// streamcipher linear mode
				cs.IsParallel = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(mIn, mOut);

				if (!Evaluate.AreEqual(mOut.ToArray(), _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
                cs.Write(_plnText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				mIn.Seek(0, SeekOrigin.Begin);
				mOut.Seek(0, SeekOrigin.Begin);

				cs.IsParallel = true;
				cs.Initialize(true, kp);
				cs.Write(mIn, mOut);

				if (!Evaluate.AreEqual(mOut.ToArray(), _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
                cs.Write(_plnText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher.Initialize(false, kp);
				BlockCTR(cipher, _encText, 0, _decText, 0);

				if (!Evaluate.AreEqual(_plnText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cs.IsParallel = false;
				mOut.Seek(0, SeekOrigin.Begin);
				cs.Initialize(false, kp);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
                cs.Write(_encText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt parallel mode
				cs.IsParallel = true;
				mOut.Seek(0, SeekOrigin.Begin);
				mRes.Seek(0, SeekOrigin.Begin);
				cs.Initialize(false, kp);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
                cs.Write(_encText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _decText))
                    throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");
			}

			eng.Dispose();
		}

        private void DescriptionTest(CipherDescription Description)
		{
			AllocateRandom(ref _iv, 16);
			AllocateRandom(ref _key, 32);
			AllocateRandom(ref _plnText);

			KeyParams kp = new KeyParams(_key, _iv);
			MemoryStream mIn = new MemoryStream(_plnText);
			MemoryStream mOut = new MemoryStream();
			MemoryStream mRes = new MemoryStream();

			CipherStream cs = new CipherStream(Description);
			cs.Initialize(true, kp);
			cs.Write(mIn, mOut);

			mOut.Seek(0, SeekOrigin.Begin);

			cs.Initialize(false, kp);
			cs.Write(mOut, mRes);

			if (!Evaluate.AreEqual(mRes.ToArray(), _plnText))
                throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");
		}
        
		private void OfbModeTest()
		{
			AllocateRandom(ref _iv, 16);
			AllocateRandom(ref _key, 32);

			KeyParams kp = new KeyParams(_key, _iv);
			RHX eng = new RHX();
			OFB cipher = new OFB(eng);
			OFB cipher2 = new OFB(eng);
			ISO7816 padding = new ISO7816();
			cipher.IsParallel = false;
            CipherStream cs = new CipherStream(cipher2, padding);

			for (int i = 0; i < 10; i++)
			{
                int sze = AllocateRandom(ref _plnText, 0, eng.BlockSize);
				int prlBlock = sze - (sze % (cipher.BlockSize * _processorCount));
				_cmpText = new byte[sze];
				_decText = new byte[sze];
				_encText = new byte[sze];

				cipher.ParallelBlockSize = prlBlock;
				cipher2.ParallelBlockSize = prlBlock;
				MemoryStream mIn = new MemoryStream(_plnText);
				MemoryStream mOut = new MemoryStream();
				MemoryStream mRes = new MemoryStream();

				// *** Compare encryption output *** //

				// local processor
				cipher.Initialize(true, kp);
                BlockEncrypt(cipher, padding, _plnText, 0, ref _encText, 0);

				// streamcipher linear mode
				cs.IsParallel = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(mIn, mOut);

				if (!Evaluate.AreEqual(mOut.ToArray(),_encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
                cs.Write(_plnText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher.Initialize(false, kp);
                BlockDecrypt(cipher, padding, _encText, 0, ref _decText, 0);

				if (!Evaluate.AreEqual(_plnText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cipher2.IsParallel = false;
				mOut.Seek(0, SeekOrigin.Begin);
				cs.Initialize(false, kp);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
                Array.Resize(ref _cmpText, _encText.Length);
                cs.Write(_encText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");
			}

			eng.Dispose();
		}

        private void ParametersTest()
		{
			AllocateRandom(ref _iv, 16);
			AllocateRandom(ref _key, 32);
			AllocateRandom(ref _plnText, 1);

			KeyParams kp = new KeyParams(_key, _iv);
			_cmpText = new byte[1];
			_decText = new byte[1];
			_encText = new byte[1];

			RHX engine = new RHX();
			
			// 1 byte w/ byte arrays
			{
				CTR cipher = new CTR(engine, false);
				CipherStream cs = new CipherStream(cipher);

				cs.Initialize(true, kp);
                cs.Write(_plnText, 0, ref _encText, 0);

				cs.Initialize(false, kp);
                cs.Write(_encText, 0, ref _decText, 0);

				if (!Evaluate.AreEqual(_decText, _plnText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				cipher.Dispose();
			}
			// 1 byte w/ stream
			{
				CTR cipher = new CTR(engine, false);
				CipherStream cs = new CipherStream(cipher);
				cs.Initialize(true, kp);
				AllocateRandom(ref _plnText, 1);
				MemoryStream mIn = new MemoryStream(_plnText);
				MemoryStream mOut = new MemoryStream();
				cs.Write(mIn, mOut);

				cs.Initialize(false, kp);
				MemoryStream mRes = new MemoryStream();
				mOut.Seek(0, SeekOrigin.Begin);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _plnText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				cipher.Dispose();
			}

			// partial block w/ byte arrays
			{
				CTR cipher = new CTR(engine, false);
				CipherStream cs = new CipherStream(cipher);
				AllocateRandom(ref _plnText, 15);
				Array.Resize(ref _decText, 15);
				Array.Resize(ref _encText, 15);

				cs.Initialize(true, kp);
                cs.Write(_plnText, 0, ref _encText, 0);

				cs.Initialize(false, kp);
                cs.Write(_encText, 0, ref _decText, 0);

				if (!Evaluate.AreEqual(_decText, _plnText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				cipher.Dispose();
			}
			// partial block w/ stream
			{
				CTR cipher = new CTR(engine, false);
				CipherStream cs = new CipherStream(cipher);
				AllocateRandom(ref _plnText, 15);
				Array.Resize(ref _decText, 15);
				Array.Resize(ref _encText, 15);

				cs.Initialize(true, kp);
				MemoryStream mIn = new MemoryStream(_plnText);
				MemoryStream mOut = new MemoryStream();
				cs.Write(mIn, mOut);

				cs.Initialize(false, kp);
				MemoryStream mRes = new MemoryStream();
				mOut.Seek(0, SeekOrigin.Begin);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _plnText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				cipher.Dispose();
			}

			// random block sizes w/ byte arrays
			{
				for (int i = 0; i < 100; i++)
				{
					CTR cipher = new CTR(engine, false);

					int sze = AllocateRandom(ref _plnText);
					_decText = new byte[sze];
					_encText = new byte[sze];

					CipherStream cs = new CipherStream(cipher);
					cs.Initialize(true, kp);
                    cs.Write(_plnText, 0, ref _encText, 0);

					cs.Initialize(false, kp);
                    cs.Write(_encText, 0, ref _decText, 0);

					if (!Evaluate.AreEqual(_decText, _plnText))
						throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

					cipher.Dispose();
				}
			}
			// random block sizes w/ stream
			{
				for (int i = 0; i < 100; i++)
				{
					CTR cipher = new CTR(engine, false);
					int sze = AllocateRandom(ref _plnText);
					_decText = new byte[sze];
					_encText = new byte[sze];

					CipherStream cs = new CipherStream(cipher);
					cs.Initialize(true, kp);
					MemoryStream mIn = new MemoryStream(_plnText);
					MemoryStream mOut = new MemoryStream();
					cs.Write(mIn, mOut);

					cs.Initialize(false, kp);
					MemoryStream mRes = new MemoryStream();
					mOut.Seek(0, SeekOrigin.Begin);
					cs.Write(mOut, mRes);

					if (!Evaluate.AreEqual(mRes.ToArray(), _plnText))
						throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

					cipher.Dispose();
				}
			}

			engine.Dispose();
		}

        void SerializeStructTest()
		{
			CipherDescription cd = new CipherDescription(
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

            CipherDescription cy = new CipherDescription(cd.ToStream());

			if (!cy.Equals(cd))
                throw new Exception("CipherStreamTest: CipherDescriptions are not equal!");

			cy.KeySize = 0;
			if (cy.Equals(cd))
                throw new Exception("CipherStreamTest: CipherDescriptionsare not equal!");
		}

        void StreamTest()
		{
			AllocateRandom(ref _iv, 8);
			AllocateRandom(ref _key, 32);

			KeyParams kp = new KeyParams(_key, _iv);
			Salsa20 cipher = new Salsa20();
			Salsa20 cipher2 = new Salsa20();
            CipherStream cs = new CipherStream(cipher2);
			cipher.IsParallel = false;

			// ctr test
			for (int i = 0; i < 10; i++)
			{
				int sze = AllocateRandom(ref _plnText);
				int prlBlock = sze - (sze % (cipher.BlockSize * _processorCount));
                _cmpText = new byte[sze];
				_decText = new byte[sze];
				_encText = new byte[sze];

				cipher.ParallelBlockSize = prlBlock;
				cs.ParallelBlockSize = prlBlock;
				MemoryStream mIn = new MemoryStream(_plnText);
				MemoryStream mOut = new MemoryStream();
				MemoryStream mRes = new MemoryStream();

				// *** Compare encryption output *** //

				// local processor
				cipher.Initialize(kp);
				ProcessStream(cipher, _plnText, 0, _encText, 0);

				// streamcipher linear mode
				cs.IsParallel = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(mIn, mOut);

				if (!Evaluate.AreEqual(mOut.ToArray(), _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
                cs.Write(_plnText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				mIn.Seek(0, SeekOrigin.Begin);
				mOut.Seek(0, SeekOrigin.Begin);

				// parallel test
				cs.IsParallel = true;
				cs.Initialize(true, kp);
				cs.Write(mIn, mOut);

				if (!Evaluate.AreEqual(mOut.ToArray(), _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
                cs.Write(_plnText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _encText))
					throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher.Initialize(kp);
				ProcessStream(cipher, _encText, 0, _decText, 0);

				if (!Evaluate.AreEqual(_plnText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cs.IsParallel = false;
				mOut.Seek(0, SeekOrigin.Begin);
				cs.Initialize(false, kp);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
                cs.Write(_encText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt parallel mode
				cs.IsParallel = true;
				mOut.Seek(0, SeekOrigin.Begin);
				mRes.Seek(0, SeekOrigin.Begin);
				cs.Initialize(false, kp);
				cs.Write(mOut, mRes);

				if (!Evaluate.AreEqual(mRes.ToArray(), _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
                cs.Write(_encText, 0, ref _cmpText, 0);

				if (!Evaluate.AreEqual(_cmpText, _decText))
					throw new Exception("CipherStreamTest: Decrypted arrays are not equal!");
			}

			cipher.Dispose();
            cipher2.Dispose();
		}

        void StreamModesTest(ICipherMode Cipher, IPadding Padding)
		{
			if (Cipher.Engine.LegalKeySizes[0] > 32)
				AllocateRandom(ref _key, 192);
			else
				AllocateRandom(ref _key, 32);

			AllocateRandom(ref _iv, 16);
            // we are testing padding modes, make sure input size is random, but -not- block aligned..
            AllocateRandom(ref _plnText, 0, Cipher.BlockSize);

			KeyParams kp = new KeyParams(_key, _iv);
			MemoryStream mIn = new MemoryStream(_plnText);
			MemoryStream mOut = new MemoryStream();
			MemoryStream mRes = new MemoryStream();

            CipherStream cs = new CipherStream(Cipher, Padding);
			cs.Initialize(true, kp);
			cs.Write(mIn, mOut);

			cs.Initialize(false, kp);
			mOut.Seek(0, SeekOrigin.Begin);
			cs.Write(mOut, mRes);

            int pos = (int)mRes.Position;
            byte[] res = new byte[_plnText.Length];
            Buffer.BlockCopy(mRes.ToArray(), 0, res, 0, pos);

            if (!Evaluate.AreEqual(res, _plnText))
                throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");

			Cipher.Dispose();
		}

        void StreamingTest(IStreamCipher Cipher)
		{
			AllocateRandom(ref _plnText);
			AllocateRandom(ref _iv, 8);
			AllocateRandom(ref _key, 32);

			KeyParams kp = new KeyParams(_key, _iv);
			MemoryStream mIn = new MemoryStream(_plnText);
			MemoryStream mOut = new MemoryStream();
			MemoryStream mRes = new MemoryStream();

            CipherStream cs = new CipherStream(Cipher);
			cs.Initialize(true, kp);
			cs.Write(mIn, mOut);

			mOut.Seek(0, SeekOrigin.Begin);

			cs.Initialize(false, kp);
			cs.Write(mOut, mRes);
			Cipher.Dispose();

			if (!Evaluate.AreEqual(mRes.ToArray(), _plnText))
				throw new Exception("CipherStreamTest: Encrypted arrays are not equal!");
		}
        #endregion

        #region Crypto
        private int AllocateRandom(ref byte[] Data, int Size = 0, int NonAlign = 0)
        {
            CSPPrng rng = new CSPPrng();

            if (Size != 0)
            {
                Data = new byte[Size];
            }
            else
            {
                int sze = 0;
                if (NonAlign != 0)
                {
                    while ((sze = rng.Next(MIN_ALLOC, MAX_ALLOC)) % NonAlign == 0) ;
                }
                else
                {
                    sze = rng.Next(MIN_ALLOC, MAX_ALLOC);
                }

                Data = new byte[sze];
            }

            rng.GetBytes(Data);
            return Data.Length;
        }

        private void BlockCTR(ICipherMode Cipher, byte[] Input, int InOffset, byte[] Output, int OutOffset)
		{
			int blkSize = Cipher.BlockSize;
			long inpSize = (Input.Length - InOffset);
			long alnSize = inpSize - (inpSize % blkSize);
			long count = 0;

			Cipher.IsParallel = false;

			while (count != alnSize)
			{
				Cipher.Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			// partial
			if (alnSize != inpSize)
			{
				int cnkSize = (int)(inpSize - alnSize);
				byte[] inpBuffer = new byte[blkSize];
                Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, cnkSize);
				byte[] outBuffer = new byte[blkSize];
				Cipher.Transform(inpBuffer, 0, outBuffer, 0);
                Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, cnkSize);
				count += cnkSize;
			}
		}

        private void BlockDecrypt(ICipherMode Cipher, IPadding Padding, byte[] Input, int InOffset, ref byte[] Output, int OutOffset)
		{
			int blkSize = Cipher.BlockSize;
			long inpSize = (Input.Length - InOffset);
			long alnSize = inpSize - blkSize;
			long count = 0;

			Cipher.IsParallel = false;

			while (count != alnSize)
			{
				Cipher.Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			// last block
			byte[] inpBuffer = new byte[blkSize];
            Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, blkSize);
			byte[] outBuffer = new byte[blkSize];
			Cipher.Transform(inpBuffer, 0, outBuffer, 0);
			int fnlSize = blkSize - Padding.GetPaddingLength(outBuffer, 0);
            Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, fnlSize);
			OutOffset += fnlSize;

			if (Output.Length != OutOffset)
				Array.Resize(ref Output, OutOffset);
		}

        private void BlockEncrypt(ICipherMode Cipher, IPadding Padding, byte[] Input, int InOffset, ref byte[] Output, int OutOffset)
		{
			int blkSize = Cipher.BlockSize;
			long inpSize = (Input.Length - InOffset);
			long alnSize = inpSize - (inpSize % blkSize);
			long count = 0;

			Cipher.IsParallel = false;

			while (count != alnSize)
			{
				Cipher.Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			// partial
			if (alnSize != inpSize)
			{
				int fnlSize = (int)(inpSize - alnSize);
				byte[] inpBuffer = new byte[blkSize];
                Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, fnlSize);
				Padding.AddPadding(inpBuffer, fnlSize);
				byte[] outBuffer = new byte[blkSize];
				Cipher.Transform(inpBuffer, 0, outBuffer, 0);
				if (Output.Length != OutOffset + blkSize)
					Array.Resize(ref Output, OutOffset + blkSize);
                Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, blkSize);
				count += blkSize;
			}
		}

        private void ParallelCTR(ICipherMode Cipher, byte[] Input, int InOffset, byte[] Output, int OutOffset)
		{
			int blkSize = Cipher.ParallelBlockSize;
			long inpSize = (Input.Length - InOffset);
			long alnSize = (inpSize / blkSize) * blkSize;
			long count = 0;

			Cipher.IsParallel = true;
			Cipher.ParallelBlockSize = blkSize;

			// parallel blocks
			while (count != alnSize)
			{
				Cipher.Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			if (alnSize != inpSize)
			{
				int cnkSize = (int)(inpSize - alnSize);
				byte[] inpBuffer = new byte[cnkSize];
                Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, cnkSize);
				byte[] outBuffer = new byte[cnkSize];
				Cipher.Transform(inpBuffer, outBuffer);
                Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, cnkSize);
				count += cnkSize;
			}
		}

        private void ParallelDecrypt(ICipherMode Cipher, IPadding Padding, byte[] Input, int InOffset, byte[] Output, int OutOffset)
		{
			int blkSize = Cipher.ParallelBlockSize;
			long inpSize = (Input.Length - InOffset);
			long alnSize = (inpSize / blkSize) * blkSize;
			long count = 0;

			Cipher.IsParallel = true;
			Cipher.ParallelBlockSize = blkSize;

			// parallel
			while (count != alnSize)
			{
				Cipher.Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			if (alnSize != inpSize)
			{
				int cnkSize = (int)(inpSize - alnSize);
                BlockDecrypt(Cipher, Padding, Input, InOffset, ref Output, OutOffset);
			}
		}

        private void ParallelStream(IStreamCipher Cipher, byte[] Input, int InOffset, byte[] Output, int OutOffset)
		{
			int blkSize = Cipher.ParallelBlockSize;
			long inpSize = (Input.Length - InOffset);
			long alnSize = (inpSize / blkSize) * blkSize;
			long count = 0;

			Cipher.IsParallel = true;
			Cipher.ParallelBlockSize = blkSize;

			// parallel blocks
			while (count != alnSize)
			{
				Cipher.Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			if (alnSize != inpSize)
			{
				int cnkSize = (int)(inpSize - alnSize);
				byte[] inpBuffer = new byte[cnkSize];
				Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, cnkSize);
				byte[] outBuffer = new byte[cnkSize];
				Cipher.Transform(inpBuffer, outBuffer);
				Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, cnkSize);
				count += cnkSize;
			}
		}

        private void ProcessStream(IStreamCipher Cipher, byte[] Input, int InOffset, byte[] Output, int OutOffset)
		{
			int blkSize = Cipher.BlockSize;
			long inpSize = (Input.Length - InOffset);
			long alnSize = (inpSize / blkSize) * blkSize;
			long count = 0;

			Cipher.IsParallel = false;

			while (count != alnSize)
			{
				Cipher.Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			// partial
			if (alnSize != inpSize)
			{
				int cnkSize = (int)(inpSize - alnSize);
				byte[] inpBuffer = new byte[cnkSize];
				Buffer.BlockCopy(Input, InOffset, inpBuffer, 0, cnkSize);
				byte[] outBuffer = new byte[cnkSize];
				Cipher.Transform(inpBuffer, outBuffer);
				Buffer.BlockCopy(outBuffer, 0, Output, OutOffset, cnkSize);
				count += cnkSize;
			}
		}
        #endregion
    }
}
