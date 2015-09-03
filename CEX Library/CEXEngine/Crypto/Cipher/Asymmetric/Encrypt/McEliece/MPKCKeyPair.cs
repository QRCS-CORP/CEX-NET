#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.CryptoException;
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// An McEliece Key-Pair container
    /// </summary>
    public sealed class MPKCKeyPair : IAsymmetricKeyPair
    {
        #region Constants
        private const string ALG_NAME = "MPKCKeyPair";
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private IAsymmetricKey _publicKey;
        private IAsymmetricKey _privateKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: KeyPair name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Returns the public key parameters
        /// </summary>
        public IAsymmetricKey PublicKey
        {
            get { return _publicKey; }
        }

        /// <summary>
        /// Get: Returns the private key parameters
        /// </summary>
        public IAsymmetricKey PrivateKey
        {
            get { return _privateKey; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="PublicKey">The public key</param>
        /// <param name="PrivateKey">The corresponding private key</param>
        public MPKCKeyPair(IAsymmetricKey PublicKey, IAsymmetricKey PrivateKey)
        {
            _publicKey = PublicKey;
            _privateKey = PrivateKey;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Key">The public or private key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key is used</exception>
        public MPKCKeyPair(IAsymmetricKey Key)
        {
            if (Key is MPKCPublicKey)
                _publicKey = (MPKCPublicKey)Key;
            else if (Key is MPKCPrivateKey)
                _privateKey = (MPKCPrivateKey)Key;
            else
                throw new CryptoAsymmetricException("MPKCKeyPair:Ctor", "Not a valid McEliece key!", new ArgumentException());
        }
        
        /// <summary>
        /// Reads a key pair from an input stream.
        /// <para>Note: both keys must be present in the stream; ordered Public, Private.</para>
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key pair</param>
        public MPKCKeyPair(MemoryStream KeyStream)
        {
            _publicKey = new MPKCPublicKey(KeyStream);
            _privateKey = new MPKCPrivateKey(KeyStream);
        }

        /// <summary>
        /// Reads a key pair  from a byte array.
        /// <para>Note: both keys must be present in the stream; ordered Public, Private.</para>
        /// </summary>
        /// 
        /// <param name="KeyArray">An byte array containing an encoded key pair</param>
        public MPKCKeyPair(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private MPKCKeyPair()
        {
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a copy of this key pair instance
        /// </summary>
        /// 
        /// <returns>The IAsymmetricKeyPair copy</returns>
        public object Clone()
        {
            return new MPKCKeyPair((IAsymmetricKey)_publicKey.Clone(), (IAsymmetricKey)_privateKey.Clone());
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
                    if (_privateKey != null)
                        ((MPKCPrivateKey)_privateKey).Dispose();
                    if (_publicKey != null)
                        ((MPKCPublicKey)_publicKey).Dispose();
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
