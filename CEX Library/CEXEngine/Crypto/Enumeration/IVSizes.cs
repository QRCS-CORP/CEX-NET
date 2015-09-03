﻿namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// <para>IV Sizes in bits. Can be cast as IV byte size integers, 
    /// i.e. (int sz = IVSizes.V128) is equal to 16.</para>
    /// </summary>
    public enum IVSizes : int
    {
        /// <summary>
        /// 64 bit IV
        /// </summary>
        V64 = 8,
        /// <summary>
        /// 128 bit IV
        /// </summary>
        V128 = 16,
        /// <summary>
        /// 256 bit IV
        /// </summary>
        V256 = 32
    }
}
