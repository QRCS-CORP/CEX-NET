#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.CryptoException;
using System.Runtime.Serialization.Formatters.Binary;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// A McEliece Private Key
    /// </summary>
    public sealed class MPKCPrivateKey : IAsymmetricKey
    {
        #region Constants
        private const int GF_LENGTH = 4;
        private const string ALG_NAME = "MPKCPrivateKey";
        #endregion

        #region Fields
        private GF2mField _gField;
        private PolynomialGF2mSmallM _goppaPoly;
        private bool _isDisposed = false;
        private GF2Matrix _H;
        private int _K;
        private int _N;
        private Permutation _P1;
        private PolynomialGF2mSmallM[] _qInv;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Private key name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Returns the finite field <c>GF(2^m)</c>
        /// </summary>
        internal GF2mField GF
        {
            get { return _gField; }
        }

        /// <summary>
        /// Get: Returns the irreducible Goppa polynomial
        /// </summary>
        internal PolynomialGF2mSmallM GP
        {
            get { return _goppaPoly; }
        }

        /// <summary>
        /// Get: Returns the canonical check matrix H
        /// </summary>
        internal GF2Matrix H
        {
            get { return _H; }
        }

        /// <summary>
        /// Get: Returns the dimension of the code
        /// </summary>
        public int K
        {
            get { return _K; }
        }

        /// <summary>
        /// Get: Returns the length of the code
        /// </summary>
        public int N
        {
            get { return _N; }
        }

        /// <summary>
        /// Get: Returns the permutation used to generate the systematic check matrix
        /// </summary>
        internal Permutation P1
        {
            get { return _P1; }
        }

        /// <summary>
        /// Get: Returns the matrix used to compute square roots in <c>(GF(2^m))^t</c>
        /// </summary>
        internal PolynomialGF2mSmallM[] QInv
        {
            get { return _qInv; }
        }

        /// <summary>
        /// Get: Returns the degree of the Goppa polynomial (error correcting capability)
        /// </summary>
        public int T
        {
            get { return _goppaPoly.Degree; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class for CCA2 MPKCS
        /// </summary>
        /// 
        /// <param name="N">Length of the code</param>
        /// <param name="K">The dimension of the code</param>
        /// <param name="Gf">The finite field <c>GF(2^m)</c></param>
        /// <param name="Gp">The irreducible Goppa polynomial</param>
        /// <param name="P">The permutation</param>
        /// <param name="H">The canonical check matrix</param>
        /// <param name="QInv">The matrix used to compute square roots in <c>(GF(2^m))^t</c></param>
        internal MPKCPrivateKey(int N, int K, GF2mField Gf, PolynomialGF2mSmallM Gp, Permutation P, GF2Matrix H, PolynomialGF2mSmallM[] QInv)
        {
            _N = N;
            _K = K;
            _gField = Gf;
            _goppaPoly = Gp;
            _P1 = P;
            _H = H;
            _qInv = QInv;
        }
        
        /// <summary>
        /// Initialize this class CCA2 MPKCS using encoded byte arrays
        /// </summary>
        /// 
        /// <param name="N">Length of the code</param>
        /// <param name="K">The dimension of the code</param>
        /// <param name="Gf">Encoded field polynomial defining the finite field <c>GF(2^m)</c></param>
        /// <param name="Gp">Encoded irreducible Goppa polynomial</param>
        /// <param name="P">The encoded permutation</param>
        /// <param name="H">Encoded canonical check matrix</param>
        /// <param name="QInv">The encoded matrix used to compute square roots in <c>(GF(2^m))^t</c></param>
        public MPKCPrivateKey(int N, int K, byte[] Gf, byte[] Gp, byte[] P, byte[] H, byte[][] QInv)
        {
            _N = N;
            _K = K;
            _gField = new GF2mField(Gf);
            _goppaPoly = new PolynomialGF2mSmallM(_gField, Gp);
            _P1 = new Permutation(P);
            _H = new GF2Matrix(H);
            _qInv = new PolynomialGF2mSmallM[QInv.Length];

            for (int i = 0; i < QInv.Length; i++)
                _qInv[i] = new PolynomialGF2mSmallM(_gField, QInv[i]);
        }

        /// <summary>
        /// Reads a Private Key from a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be loaded</exception>
        public MPKCPrivateKey(Stream KeyStream)
        {
            try
            {
                int len;
                BinaryReader reader = new BinaryReader(KeyStream);

                // length
                _N = reader.ReadInt32();
                // dimension
                _K = reader.ReadInt32();

                // gf
                byte[] gf = reader.ReadBytes(GF_LENGTH);
                _gField = new GF2mField(gf);

                // gp
                len = reader.ReadInt32();
                byte[] gp = reader.ReadBytes(len);
                _goppaPoly = new PolynomialGF2mSmallM(_gField, gp);

                // p1
                len = reader.ReadInt32();
                byte[] p1 = reader.ReadBytes(len);
                _P1 = new Permutation(p1);

                // check matrix
                len = reader.ReadInt32();
                byte[] h = reader.ReadBytes(len);
                _H = new GF2Matrix(h);

                // length of first dimension
                len = reader.ReadInt32();
                byte[][] qi = new byte[len][];

                // get the qinv encoded array
                for (int i = 0; i < qi.Length; i++)
                {
                    len = reader.ReadInt32();
                    qi[i] = reader.ReadBytes(len);
                }

                // assign qinv
                _qInv = new PolynomialGF2mSmallM[qi.Length];

                for (int i = 0; i < QInv.Length; i++)
                    _qInv[i] = new PolynomialGF2mSmallM(_gField, qi[i]);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("MPKCPrivateKey:CTor", "The Private key could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Reads a Private Key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The encoded key array</param>
        public MPKCPrivateKey(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private MPKCPrivateKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCPrivateKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a Private key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the encoded key</param>
        /// 
        /// <returns>An initialized MPKCPrivateKey class</returns>
        public static MPKCPrivateKey From(byte[] KeyArray)
        {
            return new MPKCPrivateKey(KeyArray);
        }

        /// <summary>
        /// Read a Private key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized MPKCPrivateKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static MPKCPrivateKey From(Stream KeyStream)
        {
            return new MPKCPrivateKey(KeyStream);
        }

        /// <summary>
        /// Converts the Private key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded MPKCPrivateKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the MPKCPrivateKey to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Private Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            // length
            writer.Write(_N);
            // dimension
            writer.Write(_K);
            // gf
            writer.Write(_gField.GetEncoded());
            // gp
            byte[] gp = _goppaPoly.GetEncoded();
            writer.Write(gp.Length);
            writer.Write(gp);
            // p1
            byte[] p = _P1.GetEncoded();
            writer.Write(p.Length);
            writer.Write(p);

            // check matrix
            byte[] h = _H.GetEncoded();
            writer.Write(h.Length);
            writer.Write(h);

            // length of first dimension
            writer.Write(_qInv.Length);
            for (int i = 0; i < _qInv.Length; i++)
            {
                // roots
                byte[] qi = _qInv[i].GetEncoded();
                writer.Write(qi.Length);
                writer.Write(qi);
            }
            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes encoded the MPKCPrivateKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Private Key encoded as a byte array</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the encoded MPKCPrivateKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Private Key encoded to a byte array</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("MPKCPrivateKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded MPKCPrivateKey to an output stream
        /// </summary>
        /// 
        /// <param name="Output">The Output Stream receiving the encoded Private Key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be written</exception>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("MPKCPrivateKey:WriteTo", "The key could not be written!", ex);
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Decides whether the given object <c>other</c> is the same as this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns <c>(this == other)</c></returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is MPKCPrivateKey))
                return false;

            MPKCPrivateKey key = (MPKCPrivateKey)Obj;


            if (!N.Equals(key.N))
                return false;
            if (!K.Equals(key.K))
                return false;
            if (!GF.Equals(key.GF))
                return false;
            if (!GP.Equals(key.GP))
                return false;
            if (!P1.Equals(key.P1))
                return false;
            if (!H.Equals(key.H))
                return false;
            if (QInv.Length != key.QInv.Length)
                return false;

            for (int i = 0; i < QInv.Length; i++)
            {
                if (!QInv[i].Equals(key.QInv[i]))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int hash = N * 31;
            hash += K * 31;
            hash += GF.GetHashCode() * 31;
            hash += GP.GetHashCode() * 31;
            hash += P1.GetHashCode() * 31;

            return hash;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this MPKCPublicKey instance
        /// </summary>
        /// 
        /// <returns>The MPKCPublicKey copy</returns>
        public object Clone()
        {
            return new MPKCPrivateKey(_N, _K, _gField, _goppaPoly, _P1, _H, _qInv);
        }

        /// <summary>
        /// Create a deep copy of this MPKCPublicKey instance
        /// </summary>
        /// 
        /// <returns>The MPKCPublicKey copy</returns>
        public object DeepCopy()
        {
            return new MPKCPrivateKey(ToStream());
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
                    if (_gField != null)
                    {
                        _gField.Clear();
                        _gField = null;
                    }
                    if (_goppaPoly != null)
                    {
                        _goppaPoly.Clear();
                        _goppaPoly = null;
                    }
                    if (_H != null)
                    {
                        _H.Clear();
                        _H = null;
                    }
                    if (_P1 != null)
                    {
                        _P1.Clear();
                        _P1 = null;
                    }
                    if (_qInv != null)
                    {
                        for (int i = 0; i < _qInv.Length; i++)
                        {
                            _qInv[i].Clear();
                            _qInv[i] = null;
                        }
                        _qInv = null;
                    }
                    _K = 0;
                    _N = 0;
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
