namespace VTDev.Libraries.CEXEngine.Crypto
{
    /// <summary>
    /// A Key and Vector Container class
    /// </summary>
    public class KeyParams
    {
        #region Fields
        private byte[] _Key = null;
        private byte[] _IV = null;
        #endregion

        #region Properties
        /// <summary>
        /// Cipher Key
        /// </summary>
        public byte[] Key 
        { 
            get { return _Key; } 
            private set { _Key = value; } 
        }

        /// <summary>
        /// Cipher IV
        /// </summary>
        public byte[] IV 
        { 
            get { return _IV; }
            private set { _IV = value; } 
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        public KeyParams(byte[] Key)
        {
            this.Key = Key;
        }

        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Key">Cipher Key</param>
        /// <param name="IV">Cipher IV</param>
        public KeyParams(byte[] Key, byte[] IV)
        {
            this.Key = Key;
            this.IV = IV;
        }
        #endregion
    }
}
