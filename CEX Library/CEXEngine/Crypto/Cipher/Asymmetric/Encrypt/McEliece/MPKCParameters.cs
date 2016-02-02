#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCCiphers;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// Creates, reads and writes parameter settings for MPKCEncrypt.
    /// <para>Predefined parameter sets are available and new ones can be created as well.
    /// These predefined settings are accessable through the <see cref="MPKCParamSets"/> class</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create a parameter set and write to stream:</description>
    /// <code>
    /// MemoryStream ks = new MemoryStream();
    /// using (MPKCParameters mp = new MPKCParameters(new byte[] { 1, 1, 11, 1 }, 11, 40, McElieceCiphers.Fujisaki, Digests.SHA256))
    ///    mp.WriteTo(ks);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.0.1.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.MPKCEncrypt">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece MPKCEncrypt Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.McElieceCiphers Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>MPKC Parameter Description:</h4></description>
    /// <list type="table">
    /// <item><description><c>OId</c> - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</description></item>
    /// <item><description><c>M</c> - The degree of the finite field GF(2^m).</description></item>
    /// <item><description><c>T</c> - The error correction capability of the code.</description></item>
    /// <item><description><c>Engine</c> - The McEliece CCA2 cipher engine.</description></item>
    /// <item><description><c>Digest</c> - The digest used by the cipher engine.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>McEliece Handbook of Applied Cryptography: Chapter 8<see href="http://cacr.uwaterloo.ca/hac/about/chap8.pdf"/>.</description></item>
    /// <item><description>Selecting Parameters for Secure McEliece-based Cryptosystems: <see href="https://eprint.iacr.org/2010/271.pdf"/></item>
    /// <item><description>Weak keys in the McEliece public-key cryptosystem: <see href="http://perso.univ-rennes1.fr/pierre.loidreau/articles/ieee-it/Cles_Faibles.pdf"/>.</description></item>
    /// <item><description>McBits: fast constant-time code-based cryptography: <see href="http://binary.cr.yp.to/mcbits-20130616.pdf"/>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> versions McEliece implementation.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MPKCParameters : IAsymmetricParameters
    {
        #region Constants
        // The default extension degree
        private const int DEFAULT_M = 11;
        // The default error correcting capability
        private const int DEFAULT_T = 50;
        private const int OID_SIZE = 4;
        private const string ALG_NAME = "MPKCParameters";
        #endregion

        #region Fields
        private int _M;
        private int _T;
        private int _N;
        private byte[] _oId = new byte[OID_SIZE];
        private int _fieldPoly;
        private bool _isDisposed = false;
        private Digests _dgtEngineType = Digests.SHA256;
        private Prngs _rndEngineType = Prngs.CTRPrng;
        private CCA2Ciphers _cca2Engine = CCA2Ciphers.Pointcheval;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Parameters name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// The cipher engine used for encryption
        /// </summary>
        public CCA2Ciphers CCA2Engine
        {
            get { return _cca2Engine; }
            private set { _cca2Engine = value; }
        }

        /// <summary>
        /// The digest engine used to power CCA2 variants
        /// </summary>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid digest is specified</exception>
        public Digests Digest
        {
            get { return _dgtEngineType; }
            private set
            {
                if (value == Digests.Skein1024)
                    throw new CryptoAsymmetricException("MPKCParameters:Digest", "Only 512 and 256 bit Digests are supported!", new ArgumentException());

                _dgtEngineType = value;
            }
        }

        /// <summary>
        /// Returns the field polynomial
        /// </summary>
        public int FieldPolynomial
        {
            get { return _fieldPoly; }
        }

        /// <summary>
        /// Returns the extension degree of the finite field GF(2^m)
        /// </summary>
        public int M
        {
            get { return _M; }
        }

        /// <summary>
        /// Returns the length of the code _maxPlainText = (((MPKCPublicKey)AsmKey).K >> 3);
        /// </summary>
        public int N
        {
            get { return _N; }
        }

        /// <summary>
        /// Get: Three bytes that uniquely identify the parameter set
        /// </summary>
        public byte[] OId
        {
            get { return _oId; }
            private set { _oId = value; }
        }

        /// <summary>
        /// The cipher Prng
        /// </summary>
        public Prngs RandomEngine
        {
            get { return _rndEngineType; }
            private set { _rndEngineType = value; }
        }

        /// <summary>
        /// Return the error correction capability of the code
        /// </summary>
        public int T
        {
            get { return _T; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Set the default parameters: extension degree
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The prng used by the cipher engine</param>
        public MPKCParameters(byte[] OId, CCA2Ciphers CCA2Engine = CCA2Ciphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng) :
            this(OId, DEFAULT_M, DEFAULT_T)
        {
            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="Keysize">The length of a Goppa code</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The Prng used by the cipher</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the OId is invalid, or <c>keysize &lt; 1</c></exception>
        public MPKCParameters(byte[] OId, int Keysize, CCA2Ciphers CCA2Engine = CCA2Ciphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng)
        {
            if (Keysize < 1)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "The key size must be positive!", new ArgumentException());
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.McEliece)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.McEliece, new ArgumentException()));

            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;
            Array.Copy(OId, this.OId, Math.Min(OId.Length, OID_SIZE));
            _M = 0;
            _N = 1;

            while (_N < Keysize)
            {
                _N <<= 1;
                _M++;
            }
            _T = _N >> 1;
            _T /= _M;

            _fieldPoly = PolynomialRingGF2.GetIrreduciblePolynomial(_M);
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="M">The degree of the finite field GF(2^m)</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The Prng used by the cipher</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the OId is invalid or; <c>m &lt; 1</c>, <c>m &gt; 32</c>, <c>t &lt; 0</c> or <c>t &gt; n</c></exception>
        public MPKCParameters(byte[] OId, int M, int T, CCA2Ciphers CCA2Engine = CCA2Ciphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng)
        {
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.McEliece)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.McEliece, new ArgumentException()));
            if (M < 1)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "M must be positive!", new ArgumentException());
            if (M > 32)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "M is too large!", new ArgumentOutOfRangeException());

            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;

            Array.Copy(OId, this.OId, Math.Min(OId.Length, OID_SIZE));
            _M = M;
            _N = 1 << M;

            if (T < 0)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "T must be positive!", new ArgumentException());
            if (T > N)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "T must be less than n = 2^m!", new ArgumentOutOfRangeException());

            _T = T;
            _fieldPoly = PolynomialRingGF2.GetIrreduciblePolynomial(M);
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The McEliece family must be <c>1</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="M">The degree of the finite field GF(2^m)</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="FieldPoly">The field polynomial</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The Prng used by the cipher</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the OId is invalid or; <c>t &lt; 0</c>, <c>t &gt; n</c>, or <c>poly</c> is not an irreducible field polynomial</exception>
        public MPKCParameters(byte[] OId, int M, int T, int FieldPoly, CCA2Ciphers CCA2Engine = CCA2Ciphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng)
        {
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.McEliece)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.McEliece, new ArgumentException()));
            if (M < 1)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "M must be positive!", new ArgumentException());
            if (M > 32)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "M is too large!", new ArgumentOutOfRangeException());

            _M = M;
            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;

            Array.Copy(OId, this.OId, Math.Min(OId.Length, OID_SIZE));
            _N = 1 << M;
            _T = T;

            if (T < 0)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "T must be positive!", new ArgumentException());
            if (T > N)
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "T must be less than n = 2^m!", new ArgumentOutOfRangeException());

            if ((PolynomialRingGF2.Degree(FieldPoly) == M) && (PolynomialRingGF2.IsIrreducible(FieldPoly)))
                _fieldPoly = FieldPoly;
            else
                throw new CryptoAsymmetricException("MPKCParameters:Ctor", "Polynomial is not a field polynomial for GF(2^m)", new InvalidDataException());
        }
        
        /// <summary>
        /// Builds a parameter set from an encoded input stream
        /// </summary>
        /// 
        /// <param name="ParamStream">Stream containing a parameter set</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Stream is unreadable</exception>
        public MPKCParameters(Stream ParamStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(ParamStream);
                _oId = reader.ReadBytes(OID_SIZE);
                _cca2Engine = (CCA2Ciphers)reader.ReadInt32();
                _dgtEngineType = (Digests)reader.ReadInt32();
                _rndEngineType = (Prngs)reader.ReadInt32();
                _M = reader.ReadInt32();
                _T = reader.ReadInt32();
                _fieldPoly = reader.ReadInt32();
                _N = 1 << M;
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("MPKCParameters:CTor", "The stream could not be read!", ex);
            }
        }

        /// <summary>
        /// Builds a parameter set from an encoded byte array
        /// </summary>
        /// 
        /// <param name="ParamArray">Byte array containing a parameter set</param>
        public MPKCParameters(byte[] ParamArray) :
            this(new MemoryStream(ParamArray))
        {
        }

        private MPKCParameters()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCParameters()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read an encoded Parameter set from a byte array
        /// </summary>
        /// 
        /// <param name="ParamArray">The byte array containing the parameters</param>
        /// 
        /// <returns>An initialized MPKCParameters class</returns>
        public static MPKCParameters From(byte[] ParamArray)
        {
            return new MPKCParameters(ParamArray);
        }

        /// <summary>
        /// Read an encoded Parameters set from a Stream
        /// </summary>
        /// 
        /// <param name="ParamStream">The Stream containing the encoded Parameter set</param>
        /// 
        /// <returns>An initialized MPKCParameters class</returns>
        public static MPKCParameters From(Stream ParamStream)
        {
            return new MPKCParameters(ParamStream);
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded byte array
        /// </summary>
        /// 
        /// <returns>McElieceParameters as a byte array</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded Stream
        /// </summary>
        /// 
        /// <returns>McElieceParameters as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(OId);
            writer.Write((int)CCA2Engine);
            writer.Write((int)Digest);
            writer.Write((int)RandomEngine);
            writer.Write(M);
            writer.Write(T);
            writer.Write(FieldPolynomial);
            writer.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes the MPKCParameters to a byte array
        /// </summary>
        /// 
        /// <param name="Output">Output array receiving the encoded Parameters</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the MPKCParameters to a byte array
        /// </summary>
        /// 
        /// <param name="Output">Output array receiving the encoded Parameters</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if The output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("MPKCParameters:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the MPKCParameters to a Stream
        /// </summary>
        /// 
        /// <param name="Output">The Output stream receiving the encoded Parameters</param>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (IOException e)
            {
                throw new CryptoAsymmetricException(e.Message);
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int hash = 31 * (int)Digest;
            hash += 31 * (int)CCA2Engine;
            hash += 31 * (int)RandomEngine;
            hash += 31 * M;
            hash += 31 * N;
            hash += 31 * T;
            hash += 31 * FieldPolynomial;

            return hash;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (this == Obj)
                return true;
            if (Obj == null && this != null)
                return false;

            MPKCParameters other = (MPKCParameters)Obj;
            if (Digest != other.Digest)
                return false;
            if (CCA2Engine != other.CCA2Engine)
                return false;
            if (RandomEngine != other.RandomEngine)
                return false;
            if (M != other.M)
                return false;
            if (N != other.N)
                return false;
            if (T != other.T)
                return false;
            if (FieldPolynomial != other.FieldPolynomial)
                return false;

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this McElieceParameters instance
        /// </summary>
        /// 
        /// <returns>The McElieceParameters copy</returns>
        public object Clone()
        {
            return new MPKCParameters(_oId, M, T, FieldPolynomial, _cca2Engine, _dgtEngineType, _rndEngineType);
        }

        /// <summary>
        /// Create a deep copy of this MPKCParameters instance
        /// </summary>
        /// 
        /// <returns>The MPKCParameters copy</returns>
        public object DeepCopy()
        {
            return new MPKCParameters(ToStream());
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
                    if (_oId != null)
                    {
                        Array.Clear(_oId, 0, _oId.Length);
                        _oId = null;
                    }
                    _N = 0;
                    _M = 0;
                    _T = 0;
                    _fieldPoly = 0;
                    _cca2Engine = CCA2Ciphers.Fujisaki;
                    _dgtEngineType = Digests.SHA256;
                    _rndEngineType = Prngs.CTRPrng;
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
