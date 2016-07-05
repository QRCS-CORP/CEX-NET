#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Common
{
    /// <summary>
    /// MacParams: A MAC Key, Salt, and Info Container class.
    /// </summary>
    public sealed class MacParams
    {
        #region Fields
        bool _isDisposed;
        byte[] _Key;
        byte[] _Info;
        byte[] _Salt;
        #endregion

        #region Properties
        /// <summary>
        /// Get/Set: The MAC Key
        /// </summary>
        public byte[] Key
        {
            get { return _Key == null ? null : (byte[])_Key.Clone(); }
            set { _Key = value; }
        }

        /// <summary>
        /// Get/Set: MAC Personalization info
        /// </summary>
        public byte[] Info
        {
            get { return _Info == null ? null : (byte[])_Info.Clone(); }
            set { _Info = value; }
        }

        /// <summary>
        /// Get/Set: MAC Salt value
        /// </summary>
        public byte[] Salt
        {
            get { return _Salt == null ? null : (byte[])_Salt.Clone(); }
            set { _Salt = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public MacParams()
        {
            _isDisposed = false;
        }

        /// <summary>
        /// Initialize this class with a MAC Key
        /// </summary>
        ///
        /// <param name="Key">MAC Key</param>
        public MacParams(byte[] Key)
        {
            if (Key != null)
            {
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, _Key.Length);
            }
        }

        /// <summary>
        /// Initialize this class with a MAC Key, and Salt
        /// </summary>
        ///
        /// <param name="Key">MAC Key</param>
        /// <param name="Salt">MAC Salt</param>
        public MacParams(byte[] Key, byte[] Salt)
        {
            if (Key != null)
            {
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, _Key.Length);
            }
            if (Salt != null)
            {
                _Salt = new byte[Salt.Length];
                Buffer.BlockCopy(Salt, 0, _Salt, 0, Salt.Length);
            }
        }

        /// <summary>
        /// Initialize this class with a Cipher Key, Salt, and Info
        /// </summary>
        ///
        /// <param name="Key">MAC Key</param>
        /// <param name="Salt">MAC Salt</param>
        /// <param name="Info">MAC Info</param>
        public MacParams(byte[] Key, byte[] Salt, byte[] Info)
        {
            if (Key != null)
            {
                _Key = new byte[Key.Length];
                Buffer.BlockCopy(Key, 0, _Key, 0, _Key.Length);
            }
            if (Salt != null)
            {
                _Salt = new byte[Salt.Length];
                Buffer.BlockCopy(Salt, 0, _Salt, 0, Salt.Length);
            }
            if (Info != null)
            {
                _Info = new byte[Info.Length];
                Buffer.BlockCopy(Info, 0, _Info, 0, Info.Length);
            }
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MacParams()
        {
            Dispose();
        }
        #endregion

        #region Serialization
        /// <summary>
        /// Deserialize a MacParams class
        /// </summary>
        /// 
        /// <param name="KeyStream">Stream containing the MacParams data</param>
        /// 
        /// <returns>A populated MacParams class</returns>
        public static MacParams DeSerialize(Stream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            short keyLen = reader.ReadInt16();
            short saltLen = reader.ReadInt16();
            short infoLen = reader.ReadInt16();

            byte[] key = null;
            byte[] salt = null;
            byte[] info = null;

            if (keyLen > 0)
                key = reader.ReadBytes(keyLen);
            if (saltLen > 0)
                salt = reader.ReadBytes(saltLen);
            if (infoLen > 0)
                info = reader.ReadBytes(infoLen);

            return new MacParams(key, salt, info);
        }

        /// <summary>
        /// Serialize a MacParams class
        /// </summary>
        /// 
        /// <param name="MacObj">A MacParams class</param>
        /// 
        /// <returns>A stream containing the MacParams data</returns>
        public static Stream Serialize(MacParams MacObj)
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(MacObj.Key != null ? (short)MacObj.Key.Length : (short)0);
            writer.Write(MacObj.Salt != null ? (short)MacObj.Salt.Length : (short)0);
            writer.Write(MacObj.Info != null ? (short)MacObj.Info.Length : (short)0);

            if (MacObj.Key != null)
                writer.Write(MacObj.Key);
            if (MacObj.Salt != null)
                writer.Write(MacObj.Salt);
            if (MacObj.Info != null)
                writer.Write(MacObj.Info);

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
            writer.Write(_Salt != null ? (short)_Salt.Length : (short)0);
            writer.Write(_Info != null ? (short)_Info.Length : (short)0);

            if (_Key != null)
                writer.Write(_Key);
            if (_Salt != null)
                writer.Write(_Salt);
            if (_Info != null)
                writer.Write(_Info);

            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion

        #region ICloneable
        /// <summary>
        /// Create a shallow copy of this MacParams instance
        /// </summary>
        /// 
        /// <returns>The MacParams copy</returns>
        public object Clone()
        {
            return new MacParams(_Key, _Salt, _Info);
        }

        /// <summary>
        /// Create a deep copy of this MacParams instance
        /// </summary>
        /// 
        /// <returns>The MacParams copy</returns>
        public object DeepCopy()
        {
            return DeSerialize(Serialize(this));
        }
        #endregion

        #region Equals
        /// <summary>
        /// Compare this MacParams instance with another
        /// </summary>
        /// 
        /// <param name="Obj">MacParams to compare</param>
        /// 
        /// <returns>Returns true if equal</returns>
        public bool Equals(MacParams Obj)
        {
            if (!Compare.IsEqual(Obj.Key, _Key))
                return false;
            if (!Compare.IsEqual(Obj.Salt, _Salt))
                return false;
            if (!Compare.IsEqual(Obj.Info, _Info))
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
            int hash = Utility.ArrayUtils.GetHashCode(_Key);
            hash += Utility.ArrayUtils.GetHashCode(_Salt);
            hash += Utility.ArrayUtils.GetHashCode(_Info);

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

                    if (_Salt != null)
                    {
                        Array.Clear(_Salt, 0, _Salt.Length);
                        _Salt = null;
                    }
                    if (_Info != null)
                    {
                        Array.Clear(_Info, 0, _Info.Length);
                        _Info = null;
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    };
}
