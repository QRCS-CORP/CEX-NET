namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages
{
    /// <summary>
    /// This enum represents the DTM KEX exchange state flags
    /// </summary>
    public enum DtmExchangeFlags : short
    {
        /// <summary>
        /// Public id fields exchange
        /// </summary>
        Connect = 31,
        /// <summary>
        /// Exchange full Public Identity
        /// </summary>
        Init = 32,
        /// <summary>
        /// Exchange Asymmetric Public keys
        /// </summary>
        PreAuth = 33,
        /// <summary>
        /// Exchange Symmetric KeyParams
        /// </summary>
        AuthEx = 34,
        /// <summary>
        /// Exchange Private Id's
        /// </summary>
        Auth = 35,
        /// <summary>
        /// Exchange Primary Asymmetric parameter OId's
        /// </summary>
        Sync = 36,
        /// <summary>
        /// Exchange Primary Public Keys
        /// </summary>
        PrimeEx = 37,
        /// <summary>
        /// Exchange Primary Symmetric keys
        /// </summary>
        Primary = 38,
        /// <summary>
        /// The VPN is established
        /// </summary>
        Established = 39,
        /// <summary>
        /// Negotiate the minimum security requirements
        /// </summary>
        Negotiate = 40
    }
}
