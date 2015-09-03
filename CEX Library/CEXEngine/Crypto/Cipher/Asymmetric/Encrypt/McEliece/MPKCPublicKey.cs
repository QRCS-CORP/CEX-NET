#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.CryptoException;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// A McEliece Public Key
    /// </summary>
    public sealed class MPKCPublicKey : IAsymmetricKey
    {
        #region Constants
        private const string ALG_NAME = "MPKCPublicKey";
        #endregion

        #region Fields
        private bool _isDisposed = false;
        // the length of the code
        private int _N;
        // the error correction capability of the code
        private int _T;
        // the generator matrix
        private GF2Matrix _G;
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
        /// Get: Returns the length of the code
        /// </summary>
        public int N
        {
            get { return _N; }
        }

        /// <summary>
        /// Get: Returns the error correction capability of the code
        /// </summary>
        public int T
        {
            get { return _T; }
        }

        /// <summary>
        /// Get: Returns the generator matrix
        /// </summary>
        internal GF2Matrix G
        {
            get { return _G; }
        }

        /// <summary>
        /// Get: Returns the dimension of the code
        /// </summary>
        public int K
        {
            get { return _G.RowCount; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="N">The length of the code</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="G">The generator matrix</param>
        internal MPKCPublicKey(int N, int T, GF2Matrix G)
        {
            _N = N;
            _T = T;
            _G = new GF2Matrix(G);
        }

        /// <summary>
        /// Constructor used by McElieceKeyFactory
        /// </summary>
        /// 
        /// <param name="N">The length of the code</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="G">The encoded generator matrix</param>
        public MPKCPublicKey(int N, int T, byte[] G)
        {
            _N = N;
            _T = T;
            _G = new GF2Matrix(G);
        }

        /// <summary>
        /// Read a Public Key from a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be loaded</exception>
        public MPKCPublicKey(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                _N = reader.ReadInt32();
                _T = reader.ReadInt32();
                int len = reader.ReadInt32();
                _G = new GF2Matrix(reader.ReadBytes(len));
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("MPKCPublicKey:CTor", "The Public key could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Read a Public Key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The encoded key array</param>
        public MPKCPublicKey(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private MPKCPublicKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCPublicKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a Public key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the encoded key</param>
        /// 
        /// <returns>An initialized MPKCPublicKey class</returns>
        public static MPKCPublicKey From(byte[] KeyArray)
        {
            return new MPKCPublicKey(KeyArray);
        }

        /// <summary>
        /// Read a Public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized MPKCPublicKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static MPKCPublicKey From(Stream KeyStream)
        {
            return new MPKCPublicKey(KeyStream);
        }

        /// <summary>
        /// Converts the Public key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded MPKCPublicKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the Public key to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Public Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(N);
            writer.Write(T);
            // add the encoded matrix
            byte[] encoded = G.GetEncoded();
            writer.Write(encoded.Length);
            writer.Write(encoded);

            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;            
        }

        /// <summary>
        /// Writes encoded the MPKCPublicKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Public Key encoded as a byte array</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the encoded MPKCPublicKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Public Key encoded to a byte array</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("MPKCPublicKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded MPKCPublicKey to an output stream
        /// </summary>
        /// 
        /// <param name="Output">The Output Stream receiving the encoded Public Key</param>
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
                throw new CryptoAsymmetricException("MPKCPublicKey:WriteTo", "The Public key could not be written!", ex);
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
            if (Obj == null || !(Obj is MPKCPublicKey))
                return false;
            MPKCPublicKey key = (MPKCPublicKey)Obj;

            if (N != key.N)
                return false;
            if (T != key.T)
                return false;
            if (!G.Equals(key.G))
                return false;

            return true;
        }

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int code = 0;
            code += N * 31;
            code += T * 31;
            code += G.GetHashCode();

            return code;
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
            return new MPKCPublicKey(_N, _T, _G);
        }

        /// <summary>
        /// Create a deep copy of this MPKCPublicKey instance
        /// </summary>
        /// 
        /// <returns>The MPKCPublicKey copy</returns>
        public object DeepCopy()
        {
            return new MPKCPublicKey(ToStream());
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
                    if (_G != null)
                    {
                        _G.Clear();
                        _G = null;
                    }
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
