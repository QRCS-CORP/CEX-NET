#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Common
{
    /// <summary>
    /// KeyParams: A Symmetric Cipher Key and Vector Container class.
    /// </summary>
    public class KeyParams : IDisposable, ICloneable
    {
        #region Fields
        private bool _isDisposed = false;
        private byte[] _Key = null;
        private byte[] _Iv = null;
        private byte[] _Ikm = null;
        private byte[] _ExtKey = null;
        #endregion

        #region Properties
        /// <summary>
        /// Input Key Material
        /// </summary>
        public byte[] IKM
        {
            get { return _Ikm == null ? null : (byte[])_Ikm.Clone(); }
            set { _Ikm = value; }
        }

        /// <summary>
        /// Cipher Key
        /// </summary>
        public byte[] Key 
        {
            get { return _Key == null ? null : (byte[])_Key.Clone(); } 
            set { _Key = value; } 
        }

        /// <summary>
        /// Cipher Initialization Vector
        /// </summary>
        public byte[] IV 
        {
            get { return _Iv == null ? null : (byte[])_Iv.Clone(); }
            set { _Iv = value; } 
        }

        /// <summary>
        /// Extended key material
        /// </summary>
        public byte[] ExtKey
        {
            get { return _ExtKey == null ? null : (byte[])_ExtKey.Clone(); }
            set { _ExtKey = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize an empty container
        /// </summary>
        public KeyParams()
        {
        }

        /// <summary>
        /// Initialize the class with a Cipher Key
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        public KeyParams(byte[] Key)
        {
            if (Key != null)
            {
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, _Key.Length);
            }
        }

        /// <summary>
        /// Initialize the class with a Cipher Key and IV.
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        /// <param name="IV">Cipher IV</param>
        public KeyParams(byte[] Key, byte[] IV)
        {
            if (Key != null)
            {
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, _Key.Length);
            }
            if (IV != null)
            {
                _Iv = new byte[IV.Length];
                Buffer.BlockCopy(IV, 0, _Iv, 0, _Iv.Length);
            }
        }

        /// <summary>
        /// Initialize the class with a Cipher Key, IV, and IKM.
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        /// <param name="IV">Cipher IV</param>
        /// <param name="IKM">IKM value</param>
        public KeyParams(byte[] Key, byte[] IV, byte[] IKM)
        {
            if (Key != null)
            {
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, _Key.Length);
            }
            if (IV != null)
            {
                _Iv = new byte[IV.Length];
                Buffer.BlockCopy(IV, 0, _Iv, 0, _Iv.Length);
            }
            if (IKM != null)
            {
                _Ikm = new byte[IKM.Length];
                Buffer.BlockCopy(IKM, 0, _Ikm, 0, _Ikm.Length);
            }
        }

        /// <summary>
        /// Initialize the class with a Cipher Key, IV, IKM, and ExtKey
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        /// <param name="IV">Cipher IV</param>
        /// <param name="IKM">IKM value</param>
        /// <param name="ExtKey">ExtKey value</param>
        public KeyParams(byte[] Key, byte[] IV, byte[] IKM, byte[] ExtKey)
        {
            if (Key != null)
            {
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, _Key.Length);
            }
            if (IV != null)
            {
                _Iv = new byte[IV.Length];
                Buffer.BlockCopy(IV, 0, _Iv, 0, _Iv.Length);
            }
            if (IKM != null)
            {
                _Ikm = new byte[IKM.Length];
                Buffer.BlockCopy(IKM, 0, _Ikm, 0, _Ikm.Length);
            }
            if (ExtKey != null)
            {
                _ExtKey = new byte[ExtKey.Length];
                Buffer.BlockCopy(ExtKey, 0, _ExtKey, 0, _ExtKey.Length);
            }
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~KeyParams()
        {
            Dispose(false);
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Deserialize a KeyParams class
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing the KeyParams data</param>
        /// 
        /// <returns>A populated KeyParams class</returns>
        public static KeyParams DeSerialize(Stream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            short keyLen = reader.ReadInt16();
            short ivLen = reader.ReadInt16();
            short ikmLen = reader.ReadInt16();
            short extLen = reader.ReadInt16();

            byte[] key = null;
            byte[] iv = null;
            byte[] ikm = null;
            byte[] ext = null;

            if (keyLen > 0)
                key = reader.ReadBytes(keyLen);
            if (ivLen > 0)
                iv = reader.ReadBytes(ivLen);
            if (ikmLen > 0)
                ikm = reader.ReadBytes(ikmLen);
            if (extLen > 0)
                ext = reader.ReadBytes(extLen);

            return new KeyParams(key, iv, ikm, ext);
        }

        /// <summary>
        /// Serialize a KeyParams class
        /// </summary>
        /// 
        /// <param name="KeyObj">A KeyParams class</param>
        /// 
        /// <returns>A stream containing the KeyParams data</returns>
        public static Stream Serialize(KeyParams KeyObj)
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(KeyObj.Key != null ? (short)KeyObj.Key.Length : (short)0);
            writer.Write(KeyObj.IV != null ? (short)KeyObj.IV.Length : (short)0);
            writer.Write(KeyObj.IKM != null ? (short)KeyObj.IKM.Length : (short)0);
            writer.Write(KeyObj.ExtKey != null ? (short)KeyObj.ExtKey.Length : (short)0);

            if (KeyObj.Key != null)
                writer.Write(KeyObj.Key);
            if (KeyObj.IV != null)
                writer.Write(KeyObj.IV);
            if (KeyObj.IKM != null)
                writer.Write(KeyObj.IKM);
            if (KeyObj.ExtKey != null)
                writer.Write(KeyObj.ExtKey);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }

        /// <summary>
        /// Convert the Key parameters to a MemoryStream
        /// </summary>
        /// 
        /// <returns>The MemoryStream containing the keying material</returns>
        public MemoryStream ToStream()
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(_Key != null ? (short)_Key.Length : (short)0);
            writer.Write(_Iv != null ? (short)_Iv.Length : (short)0);
            writer.Write(_Ikm != null ? (short)_Ikm.Length : (short)0);
            writer.Write(_ExtKey != null ? (short)_ExtKey.Length : (short)0);

            if (_Key != null)
                writer.Write(_Key);
            if (_Iv != null)
                writer.Write(_Iv);
            if (_Ikm != null)
                writer.Write(_Ikm);
            if (_ExtKey != null)
                writer.Write(_ExtKey);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region ICloneable
        /// <summary>
        /// Create a shallow copy of this KeyParams instance
        /// </summary>
        /// 
        /// <returns>The KeyParams copy</returns>
        public object Clone()
        {
            return new KeyParams(_Key, _Iv, _Ikm, _ExtKey);
        }

        /// <summary>
        /// Create a deep copy of this KeyParams instance
        /// </summary>
        /// 
        /// <returns>The KeyParams copy</returns>
        public object DeepCopy()
        {
            return DeSerialize(Serialize(this));
        }
        #endregion

        #region Equals
        /// <summary>
        /// Compare this KeyParams instance with another
        /// </summary>
        /// 
        /// <param name="Obj">KeyParams to compare</param>
        /// 
        /// <returns>Returns true if equal</returns>
        public bool Equals(KeyParams Obj)
        {
            if (!Compare.IsEqual(Obj.Key, _Key))
                return false;
            if (!Compare.IsEqual(Obj.IV, _Iv))
                return false;
            if (!Compare.IsEqual(Obj.IKM, _Ikm))
                return false;
            if (!Compare.IsEqual(Obj.ExtKey, _ExtKey))
                return false;

            return true;
        }

        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int hash =  Utility.ArrayUtils.GetHashCode(_Key);
            hash += Utility.ArrayUtils.GetHashCode(_Iv);
            hash += Utility.ArrayUtils.GetHashCode(_Ikm);
            hash += Utility.ArrayUtils.GetHashCode(_ExtKey);

            return hash;
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
                    if (_Key != null)
                    {
                        Array.Clear(_Key, 0, _Key.Length);
                        _Key = null;
                    }

                    if (_Iv != null)
                    {
                        Array.Clear(_Iv, 0, _Iv.Length);
                        _Iv = null;
                    }
                    if (_Ikm != null)
                    {
                        Array.Clear(_Ikm, 0, _Ikm.Length);
                        _Ikm = null;
                    }
                    if (_ExtKey != null)
                    {
                        Array.Clear(_ExtKey, 0, _ExtKey.Length);
                        _ExtKey = null;
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
