#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// This class implements the key pair generation of the McEliece Public Key Crypto System (McEliece PKCS) using CCA2 Secure variants
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of creating a keypair:</description>
    /// <code>
    /// MPKCParameters encParams = MPKCParamSets.MPKCFM11T40S256;
    /// MPKCKeyGenerator keyGen = new MPKCKeyGenerator(encParams);
    /// IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.AsymmetricEngines">VTDev.Libraries.CEXEngine.Crypto AsymmetricEngines Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCPublicKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece MPKCPublicKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCPrivateKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece MPKCPrivateKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKeyPair Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKey Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <description>The algorithm is given the parameters m and t or the key size n as input. Then, the following matrices are generated:</description> 
    /// <list type="table">
    /// <item><description>The public key is <c>(n, t, G)</c>. The private key is <c>(m, k, field polynomial, Goppa polynomial, H, S, P, setJ)</c>.</description></item>
    /// <item><description><c>G</c> is a k x n generator matrix of a binary irreducible (n,k) Goppa code GC which can correct up to t errors where n = 2^m and k is chosen maximal, i.e. k &lt;= n - mt.</description></item>
    /// <item><description><c>H</c> is an mt x n check matrix of the Goppa code GC.</description></item>
    /// <item><description><c>S</c> is a k x k random binary non-singular matrix.</description></item>
    /// <item><description><c>P</c> is an n x n random permutation matrix.</description></item>
    /// <item><description>Then, the algorithm computes the k x n matrix <c>G = SG'P.</c>.</description></item>
    /// </list> 
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>McEliece Handbook of Applied Cryptography: Chapter 8<see href="http://cacr.uwaterloo.ca/hac/about/chap8.pdf"/>.</description></item>
    /// <item><description>Selecting Parameters for Secure McEliece-based Cryptosystems: <see href="https://eprint.iacr.org/2010/271.pdf"/></item>
    /// <item><description>Weak keys in the McEliece public-key cryptosystem: <see href="http://perso.univ-rennes1.fr/pierre.loidreau/articles/ieee-it/Cles_Faibles.pdf"/>.</description></item>
    /// <item><description>McBits: fast constant-time code-based cryptography: <see href="http://binary.cr.yp.to/mcbits-20130616.pdf"/>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class MPKCKeyGenerator : IAsymmetricGenerator
    {
        #region Constants
        private const string ALG_NAME = "MPKCKeyGenerator";
        #endregion

        #region Fields
        private bool _isDisposed;
        private MPKCParameters _mpkcParams;
        private int _M;
        private int _N;
        private int _T;
        private int _fieldPoly;
        private IRandom _rndEngine;
        private bool _frcLinear = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Generator name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CipherParams">The MPKCParameters instance containing thecipher settings</param>
        /// <param name="Parallel">Use parallel processing when generating a key; set to false if using a passphrase type generator (default is true)</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if a Prng that requires pre-initialization is specified; (wrong constructor)</exception>
        public MPKCKeyGenerator(MPKCParameters CipherParams, bool Parallel = true)
        {
            if (CipherParams.RandomEngine == Prngs.PBPrng)
                throw new CryptoAsymmetricException("MPKCKeyGenerator:Ctor", "Passphrase based digest and CTR generators must be pre-initialized, use the other constructor!", new ArgumentException());

            _frcLinear = ParallelUtils.ForceLinear;
            ParallelUtils.ForceLinear = !Parallel;
            _mpkcParams = (MPKCParameters)CipherParams;
            // set source of randomness
            _rndEngine = GetPrng(_mpkcParams.RandomEngine);
            _M = _mpkcParams.M;
            _N = _mpkcParams.N;
            _T = _mpkcParams.T;
            _fieldPoly = _mpkcParams.FieldPolynomial;
        }

        /// <summary>
        /// Use an initialized prng to generate the key; use this constructor with an Rng that requires pre-initialization, i.e. PBPrng
        /// </summary>
        /// 
        /// <param name="CipherParams">The RLWEParameters instance containing the cipher settings</param>
        /// <param name="RngEngine">An initialized Prng instance</param>
        /// <param name="Parallel">Use parallel processing when generating a key; set to false if using a passphrase type generator (default is true)</param>
        public MPKCKeyGenerator(MPKCParameters CipherParams, IRandom RngEngine, bool Parallel = true)
        {
            _mpkcParams = (MPKCParameters)CipherParams;
            // set source of randomness
            _rndEngine = RngEngine;
            _M = _mpkcParams.M;
            _N = _mpkcParams.N;
            _T = _mpkcParams.T;
            _fieldPoly = _mpkcParams.FieldPolynomial;

            _frcLinear = ParallelUtils.ForceLinear;
            // passphrase gens must be linear processed
            if (RngEngine.GetType().Equals(typeof(PBPRng)))
                ParallelUtils.ForceLinear = true;
            else
                ParallelUtils.ForceLinear = !Parallel;
        }

        private MPKCKeyGenerator()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCKeyGenerator()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Generate an encryption Key pair
        /// </summary>
        /// 
        /// <returns>A McElieceKeyPair containing public and private keys</returns>
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            // finite field GF(2^m)
            GF2mField field = new GF2mField(_M, _fieldPoly); 
            // irreducible Goppa polynomial
            PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, _T, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, _rndEngine);
            PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);
            // matrix for computing square roots in (GF(2^m))^t
            PolynomialGF2mSmallM[] qInv = ring.SquareRootMatrix;
            // generate canonical check matrix
            GF2Matrix h = GoppaCode.CreateCanonicalCheckMatrix(field, gp);
            // compute short systematic form of check matrix
            GoppaCode.MaMaPe mmp = GoppaCode.ComputeSystematicForm(h, _rndEngine);
            GF2Matrix shortH = mmp.SecondMatrix;
            Permutation p = mmp.Permutation;
            // compute short systematic form of generator matrix
            GF2Matrix shortG = (GF2Matrix)shortH.ComputeTranspose();
            // obtain number of rows of G (= dimension of the code)
            int k = shortG.RowCount;
            // generate keys
            IAsymmetricKey pubKey = new MPKCPublicKey(_N, _T, shortG);
            IAsymmetricKey privKey = new MPKCPrivateKey(_N, k, field, gp, p, h, qInv);

            // return key pair
            return new MPKCKeyPair(pubKey, privKey);            
        }

        /// <summary>
        /// Generates an encryption key pair using a passphrase based prng.
        /// <para>Invoking this method with the same passphrase and salt will always return the same key pair.</para>
        /// </summary>
        /// 
        /// <param name="Passphrase">The passphrase</param>
        /// <param name="Salt">Salt for the passphrase; can be <c>null</c> but this is strongly discouraged</param>
        /// 
        /// <returns>A populated IAsymmetricKeyPair</returns>
        public IAsymmetricKeyPair GenerateKeyPair(byte[] Passphrase, byte[] Salt)
        {
            using (IDigest dgt = GetDigest(_mpkcParams.Digest))
            {
                using (IRandom rnd = new PBPRng(dgt, Passphrase, Salt, 10000, false))
                    return GenerateKeyPair();
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="DigestType">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests DigestType)
        {
            try
            {
                return DigestFromName.GetInstance(DigestType);
            }
            catch
            {
                throw new CryptoAsymmetricException("MPKCKeyGenerator:GetDigest", "The digest type is not supported!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="PrngType">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the prng type is unknown or unsupported</exception>
        private IRandom GetPrng(Prngs PrngType)
        {
            try
            {
                return PrngFromName.GetInstance(PrngType);
            }
            catch
            {
                throw new CryptoAsymmetricException("MPKCKeyGenerator:GetPrng", "The Prng type is not supported!", new ArgumentException());
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            ParallelUtils.ForceLinear = _frcLinear;
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_rndEngine != null)
                    {
                        _rndEngine.Dispose();
                        _rndEngine = null;
                    }
                    _M = 0;
                    _N = 0;
                    _T = 0;
                    _fieldPoly = 0;
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
