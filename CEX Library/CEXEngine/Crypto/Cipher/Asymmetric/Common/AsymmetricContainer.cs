/*! \mainpage A programmers guide to the CEX .NET Cryptographic library

\section intro_sec Welcome
Welcome to the CEX Cryptographic Library, version 1.5.0.6.
\brief 
CEX is a library built for both speed and maximum security. 
This help package contains details on the cryptographic primitives used in the library, their uses, and code examples.


\details   This class is used to demonstrate a number of section commands.
\author    John Underhill
\version   1.5.0.6
\date      February 10, 2016
\copyright MIT public license


\section intro_link Links
Get the latest version from the CEX Home page: http://www.vtdev.com/cexhome.html

The CEX++ Help pages: http://www.vtdev.com/CEX-Plus/Help/html/index.html

CEX++ on Github: https://github.com/Steppenwolfe65/CEX

CEX .NET on Github: https://github.com/Steppenwolfe65/CEX-NET

The Code Project article on CEX .NET: http://www.codeproject.com/Articles/828477/Cipher-EX-V
*/

// end doxygen header //

#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using System.IO;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Common
{
    /// <summary>
    /// A class that can store an asymmetric key or key-pair, a parameters set, and an optional tag value.
    /// </summary>
    /// 
    /// <remarks>
    /// <para>Use this class to store a ciphers keys and settings.
    /// The optional Tag value can be any length, is stored at the start of a serialized structure 
    /// (int: tag size, byte[]: tag value), and can be used to uniquely identify a container.
    /// Use the ToBytes() or ToStream() methods to serialize a container, and the 
    /// corresponding constructors to deserialize a stream or byte array.</para>
    /// </remarks>
    public sealed class AsymmetricContainer : IDisposable
    {
        #region Fields
        private AsymmetricEngines _asmEngine;
        private IAsymmetricParameters _asmParameters;
        private byte[] _idTag;
        private bool _isDisposed = false;
        private IAsymmetricKey _privateKey;
        private IAsymmetricKey _publicKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the asymmetric cipher family
        /// </summary>
        public AsymmetricEngines EngineType
        {
            get { return _asmEngine; }
        }

        /// <summary>
        /// Get: Returns the parameters
        /// </summary>
        public IAsymmetricParameters Parameters
        {
            get { return _asmParameters; }
        }

        /// <summary>
        /// Get: Returns the public key
        /// </summary>
        public IAsymmetricKey PublicKey
        {
            get { return _publicKey; }
        }

        /// <summary>
        /// Get: Returns the private key
        /// </summary>
        public IAsymmetricKey PrivateKey
        {
            get { return _privateKey; }
        }

        /// <summary>
        /// Get: Returns the identity tag
        /// </summary>
        public byte[] Tag
        {
            get { return _idTag; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher Parameters</param>
        /// <param name="AsmKey">The Public or Private asymmetric key</param>
        /// <param name="Tag">An identity field</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key is used</exception>
        public AsymmetricContainer(IAsymmetricParameters Parameters, IAsymmetricKey AsmKey, byte[] Tag = null)
        {
            _asmParameters = Parameters;
            _idTag = Tag;

            if (AsymmetricUtils.IsPublicKey(AsmKey))
                _publicKey = AsmKey;
            else
                _privateKey = AsmKey;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher Parameters</param>
        /// <param name="KeyPair">The public or private key</param>
        /// <param name="Tag">An identity field</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key is used</exception>
        public AsymmetricContainer(IAsymmetricParameters Parameters, IAsymmetricKeyPair KeyPair, byte[] Tag = null)
        {
            if (!(KeyPair is IAsymmetricKeyPair))
                throw new CryptoAsymmetricException("KeyContainer:Ctor", "Not a valid key-pair!", new InvalidDataException());

            _publicKey = KeyPair.PublicKey;
            _privateKey = KeyPair.PrivateKey;
            _asmParameters = Parameters;
            _idTag = Tag;
        }
        
        /// <summary>
        /// Reads the key container from an input stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key container</param>
        public AsymmetricContainer(MemoryStream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            byte[] data;
            int len;

            _idTag = null;
            _publicKey = null;
            _publicKey = null;

            // tag
            len = reader.ReadInt32();
            if (len > 0)
                _idTag = reader.ReadBytes(len);

            // family
            _asmEngine = (AsymmetricEngines)reader.ReadByte();

            // parameters
            len = reader.ReadInt32();
            data = reader.ReadBytes(len);
            _asmParameters = ParamsFromBytes(data);

            // public key
            len = reader.ReadInt32();
            if (len > 0)
            {
                data = reader.ReadBytes(len);
                _publicKey = PublicKeyFromBytes(data);
            }

            // private key
            len = reader.ReadInt32();
            if (len > 0)
            {
                data = reader.ReadBytes(len);
                _privateKey = PrivateKeyFromBytes(data);
            }
        }

        /// <summary>
        /// Reads the key container from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">An byte array containing an encoded key container</param>
        public AsymmetricContainer(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private AsymmetricContainer()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~AsymmetricContainer()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Converts the Public key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded RLWEPublicKey</returns>
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
            byte[] data;

            // tag
            if (_idTag == null)
            {
                writer.Write((int)0);
            }
            else
            {
                writer.Write(_idTag.Length);
                writer.Write(_idTag.Length);
            }

            // family
            writer.Write((byte)_asmEngine);

            // parameters
            data = _publicKey.ToBytes();
            writer.Write(data.Length);
            writer.Write(data.Length);

            // public key
            if (_publicKey == null)
            {
                writer.Write((int)0);
            }
            else
            {
                data = _publicKey.ToBytes();
                writer.Write(data.Length);
                writer.Write(data.Length);
            }

            // private key
            if (_privateKey == null)
            {
                writer.Write((int)0);
            }
            else
            {
                data = _privateKey.ToBytes();
                writer.Write(data.Length);
                writer.Write(data.Length);
            }
            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }
        #endregion

        #region Private Methods
        private IAsymmetricParameters ParamsFromBytes(byte[] ParameterArray)
        {
            if (_asmEngine == AsymmetricEngines.GMSS)
                return new GMSSParameters(ParameterArray);
            else if (_asmEngine == AsymmetricEngines.McEliece)
                return new MPKCParameters(ParameterArray);
            else if (_asmEngine == AsymmetricEngines.NTRU)
                return new NTRUParameters(ParameterArray);
            else if (_asmEngine == AsymmetricEngines.Rainbow)
                return new RNBWParameters(ParameterArray);
            else
                return new RLWEParameters(ParameterArray);
        }

        private IAsymmetricKey PublicKeyFromBytes(byte[] KeyArray)
        {
            if (_asmEngine == AsymmetricEngines.GMSS)
                return new GMSSPublicKey(KeyArray);
            else if (_asmEngine == AsymmetricEngines.McEliece)
                return new MPKCPublicKey(KeyArray);
            else if (_asmEngine == AsymmetricEngines.NTRU)
                return new NTRUPublicKey(KeyArray);
            else if (_asmEngine == AsymmetricEngines.Rainbow)
                return new RNBWPublicKey(KeyArray);
            else
                return new RLWEPublicKey(KeyArray);
        }

        private IAsymmetricKey PrivateKeyFromBytes(byte[] KeyArray)
        {
            if (_asmEngine == AsymmetricEngines.GMSS)
                return new GMSSPrivateKey(KeyArray);
            else if (_asmEngine == AsymmetricEngines.McEliece)
                return new MPKCPrivateKey(KeyArray);
            else if (_asmEngine == AsymmetricEngines.NTRU)
                return new NTRUPrivateKey(KeyArray);
            else if (_asmEngine == AsymmetricEngines.Rainbow)
                return new RNBWPrivateKey(KeyArray);
            else
                return new RLWEPrivateKey(KeyArray);
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
                    if (_asmParameters != null)
                    {
                        _asmParameters.Dispose();
                        _asmParameters = null;
                    }
                    if (_publicKey != null)
                    {
                        _publicKey.Dispose();
                        _publicKey = null;
                    }
                    if (_privateKey != null)
                    {
                        _privateKey.Dispose();
                        _privateKey = null;
                    }
                    if (_idTag != null)
                    {
                        Array.Clear(_idTag, 0, _idTag.Length);
                        _idTag = null;
                    }
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
