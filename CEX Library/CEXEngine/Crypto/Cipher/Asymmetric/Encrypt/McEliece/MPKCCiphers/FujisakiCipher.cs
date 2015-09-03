#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
using VTDev.Libraries.CEXEngine.CryptoException;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers
{
    /// <summary>
    /// This class implements the Fujisaki/Okamoto conversion of the McEliecePKCS
    /// </summary>
    /// <remarks>
    /// <para>Fujisaki and Okamoto propose hybrid encryption that merges a symmetric encryption scheme which is secure in the find-guess model with 
    /// an asymmetric one-way encryption scheme which is sufficiently probabilistic to obtain a public key cryptosystem which is CCA2-secure. 
    /// For details, see D. Engelbert, R. Overbeck, A. Schmidt, "A summary of the development of the McEliece Cryptosystem", technical report.</para>
    /// </remarks>
    internal class FujisakiCipher : IMPKCCiphers, IDisposable
    {
        #region Constants
        /// <summary>
        /// The OID of the algorithm
        /// </summary>
        public static readonly byte[] OID = System.Text.Encoding.ASCII.GetBytes("1.3.6.1.4.1.8301.3.1.3.4.2.1");
        #endregion

        #region Fields
        private IAsymmetricKey _asmKey;
        private MPKCParameters _cprParams;
        private IDigest _dgtEngine;
        private bool _isDisposed = false;
        private bool _isEncryption;
        private int _maxPlainText;
        private IRandom _rndEngine;
        private int _K;
        private int _N;
        private int _T;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        public int MaxPlainText
        {
            get { return _maxPlainText; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Paramaters">The cipher parameters</param>
        public FujisakiCipher(MPKCParameters Paramaters)
        {
            _cprParams = Paramaters;
            _dgtEngine = GetDigest(Paramaters.Digest);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~FujisakiCipher()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a cipher text
        /// </summary>
        /// 
        /// <param name="Input">The cipher text</param>
        /// 
        /// <returns>The plain text</returns>
        public byte[] Decrypt(byte[] Input)
        {
            if (_isEncryption)
                throw new CryptoAsymmetricSignException("FujisakiCipher:Decrypt", "The cipher is not initialized for decryption!", new ArgumentException());

            int c1Len = (_N + 7) >> 3;
            int c2Len = Input.Length - c1Len;

            // split ciphertext (c1||c2)
            byte[][] c1c2 = ByteUtils.Split(Input, c1Len);
            byte[] c1 = c1c2[0];
            byte[] c2 = c1c2[1];

            // decrypt c1 ...
            GF2Vector hrmVec = GF2Vector.OS2VP(_N, c1);
            GF2Vector[] decC1 = CCA2Primitives.Decrypt((MPKCPrivateKey)_asmKey, hrmVec);
            byte[] rBytes = decC1[0].GetEncoded();
            // ... and obtain error vector z
            GF2Vector z = decC1[1];

            byte[] mBytes;
            // get PRNG object..
            using (KDF2Drbg sr0 = new KDF2Drbg(GetDigest(_cprParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(rBytes);
                // generate random sequence
                mBytes = new byte[c2Len];
                sr0.Generate(mBytes);
            }

            // XOR with c2 to obtain m
            for (int i = 0; i < c2Len; i++)
                mBytes[i] ^= c2[i];

            // compute H(r||m)
            byte[] rmBytes = ByteUtils.Concatenate(rBytes, mBytes);
            byte[] hrm = new byte[_dgtEngine.DigestSize];
            _dgtEngine.BlockUpdate(rmBytes, 0, rmBytes.Length);
            _dgtEngine.DoFinal(hrm, 0);
            // compute Conv(H(r||m))
            hrmVec = CCA2Conversions.Encode(_N, _T, hrm);

            // check that Conv(H(m||r)) = z
            if (!hrmVec.Equals(z))
                throw new CryptoAsymmetricSignException("FujisakiCipher:Decrypt", "Bad Padding: invalid ciphertext!", new InvalidDataException());

            // return plaintext m
            return mBytes;
        }

        /// <summary>
        /// Encrypt a plain text message
        /// </summary>
        /// 
        /// <param name="Input">The plain text</param>
        /// 
        /// <returns>The cipher text</returns>
        public byte[] Encrypt(byte[] Input)
        {
            if (!_isEncryption)
                throw new CryptoAsymmetricSignException("FujisakiCipher:Encrypt", "The cipher is not initialized for encryption!", new ArgumentException());

            // generate random vector r of length k bits
            GF2Vector r = new GF2Vector(_K, _rndEngine);
            // convert r to byte array
            byte[] rBytes = r.GetEncoded();
            // compute (r||input)
            byte[] rm = ByteUtils.Concatenate(rBytes, Input);

            // compute H(r||input)
            _dgtEngine.BlockUpdate(rm, 0, rm.Length);
            byte[] hrm = new byte[_dgtEngine.DigestSize];
            _dgtEngine.DoFinal(hrm, 0);
            // convert H(r||input) to error vector z
            GF2Vector z = CCA2Conversions.Encode(_N, _T, hrm);

            // compute c1 = E(r, z)
            byte[] c1 = CCA2Primitives.Encrypt((MPKCPublicKey)_asmKey, r, z).GetEncoded();
            byte[] c2;

            // get PRNG object
            using (KDF2Drbg sr0 = new KDF2Drbg(GetDigest(_cprParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(rBytes);
                // generate random c2
                c2 = new byte[Input.Length];
                sr0.Generate(c2);
            }

            // XOR with input
            for (int i = 0; i < Input.Length; i++)
                c2[i] ^= Input[i];

            // return (c1||c2)
            return ByteUtils.Concatenate(c1, c2);
        }

        /// <summary>
        /// Return the key size of the working key
        /// </summary>
        /// 
        /// <returns>The size of the key</returns>
        public int GetKeySize(IAsymmetricKey AsmKey)
        {
            if (AsmKey is MPKCPublicKey)
                return ((MPKCPublicKey)AsmKey).N;
            if (AsmKey is MPKCPrivateKey)
                return ((MPKCPrivateKey)AsmKey).N;

            throw new CryptoAsymmetricSignException("FujisakiCipher:Encrypt", "Unsupported Key type!", new ArgumentException());
        }

        /// <summary>
        /// Initialize the cipher.
        /// <para>Requires a <see cref="MPKCPublicKey"/> for encryption, or a <see cref="MPKCPrivateKey"/> for decryption</para>
        /// </summary>
        /// 
        /// <param name="AsmKey">The <see cref="IAsymmetricKey"/> containing the McEliece public or private key</param>
        public void Initialize(IAsymmetricKey AsmKey)
        {
            if (!(AsmKey is MPKCPublicKey) && !(AsmKey is MPKCPrivateKey))
                throw new CryptoAsymmetricSignException("FujisakiCipher:Initialize", "The key is not a valid McEliece key!", new InvalidDataException());

            _isEncryption = (AsmKey is MPKCPublicKey);

            _asmKey = AsmKey;

            if (_isEncryption)
            {
                _rndEngine = GetPrng(_cprParams.RandomEngine);
                _N = ((MPKCPublicKey)AsmKey).N;
                _K = ((MPKCPublicKey)AsmKey).K;
                _T = ((MPKCPublicKey)AsmKey).T;
                _maxPlainText = (((MPKCPublicKey)AsmKey).K >> 3);
            }
            else
            {
                _N = ((MPKCPrivateKey)AsmKey).N;
                _K = ((MPKCPrivateKey)AsmKey).K;
                _T = ((MPKCPrivateKey)AsmKey).T;
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="Digest">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests Digest)
        {
            switch (Digest)
            {
                case Digests.Blake256:
                    return new Blake256();
                case Digests.Blake512:
                    return new Blake512();
                case Digests.Keccak256:
                    return new Keccak256();
                case Digests.Keccak512:
                    return new Keccak512();
                case Digests.Keccak1024:
                    return new Keccak1024();
                case Digests.SHA256:
                    return new SHA256();
                case Digests.SHA512:
                    return new SHA512();
                case Digests.Skein256:
                    return new Skein256();
                case Digests.Skein512:
                    return new Skein512();
                case Digests.Skein1024:
                    return new Skein1024();
                default:
                    throw new CryptoAsymmetricSignException("FujisakiCipher:GetDigest", "The digest type is not supported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="Prng">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        private IRandom GetPrng(Prngs Prng)
        {
            switch (Prng)
            {
                case Prngs.CTRPrng:
                    return new CTRPrng();
                case Prngs.DGCPrng:
                    return new DGCPrng();
                case Prngs.CSPRng:
                    return new CSPRng();
                case Prngs.BBSG:
                    return new BBSG();
                case Prngs.CCG:
                    return new CCG();
                case Prngs.MODEXPG:
                    return new MODEXPG();
                case Prngs.QCG1:
                    return new QCG1();
                case Prngs.QCG2:
                    return new QCG2();
                default:
                    throw new CryptoAsymmetricSignException("FujisakiCipher:GetPrng", "The Prng type is not supported!", new ArgumentException());
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_dgtEngine != null)
                    {
                        _dgtEngine.Dispose();
                        _dgtEngine = null;
                    }
                    if (_rndEngine != null)
                    {
                        _rndEngine.Dispose();
                        _rndEngine = null;
                    }
                    _K = 0;
                    _N = 0;
                    _T = 0;
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
