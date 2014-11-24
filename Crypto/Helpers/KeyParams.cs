namespace VTDev.Projects.CEX.Crypto
{
    public class KeyParams
    {
        #region Fields
        private byte[] _Key = null;
        private byte[] _IV = null;
        #endregion

        #region Properties
        public byte[] Key 
        { 
            get { return _Key; } 
            private set { _Key = value; } 
        }

        public byte[] IV 
        { 
            get { return _IV; }
            private set { _IV = value; } 
        }
        #endregion

        #region Constructor
        public KeyParams(byte[] Key)
        {
            this.Key = Key;
        }

        public KeyParams(byte[] Key, byte[] IV)
        {
            this.Key = Key;
            this.IV = IV;
        }
        #endregion
    }
}
