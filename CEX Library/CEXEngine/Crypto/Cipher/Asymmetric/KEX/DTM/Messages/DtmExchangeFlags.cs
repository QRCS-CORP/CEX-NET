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
        Connect = 1,
        /// <summary>
        /// Exchange full Public Identity
        /// </summary>
        Init = 2,
        /// <summary>
        /// Exchange Asymmetric Public keys
        /// </summary>
        PreAuth = 3,
        /// <summary>
        /// Exchange Symmetric KeyParams
        /// </summary>
        AuthEx = 4,
        /// <summary>
        /// Exchange Private Id's
        /// </summary>
        Auth = 5,
        /// <summary>
        /// Exchange Primary Asymmetric parameter OId's
        /// </summary>
        Sync = 6,
        /// <summary>
        /// Exchange Primary Public Keys
        /// </summary>
        PrimeEx = 7,
        /// <summary>
        /// Exchange Primary Symmetric keys
        /// </summary>
        Primary = 8,
        /// <summary>
        /// The VPN is established
        /// </summary>
        Established = 9,
        /// <summary>
        /// Negotiate the minimum security requirements
        /// </summary>
        Negotiate = 10
    }
}
