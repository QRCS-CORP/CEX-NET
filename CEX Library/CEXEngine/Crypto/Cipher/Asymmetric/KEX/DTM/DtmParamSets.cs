#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The GPL Version 3 License
// 
// Copyright (C) 2015 John Underhill
// This file is part of the CEX Cryptographic library.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 
// Written by John Underhill, August 21, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM
{
    /// <summary>
    /// A set of pre-defined DTM parameter sets.
    /// <para>Both hosts in a key exchange must use a parameter set with the same Security Classification.
    /// This is negotiated during the Connect phase of the DTM Key Exchange protocol. See the <see cref="DtmKex"/> class for a description of the exchange.</para>
    /// <para>Set id prefix is defined as: Security Classification <c>X1</c> (maximum security), <c>X2</c> (high security), <c>X3</c> (security and speed), and <c>X4</c> (speed optimized).
    /// The next 2 characters are the first letter of both asymmetric parameter ids. 
    /// This is followed by both symmetric cipher enumeration values and their Kdf engine type (Digests enum member or 0 for none).</para>
    /// </summary>
    /// 
    /// <remarks>
    /// <description><h4>The 16 byte Parameter OId configuration:</h4></description>
    /// <list type="bullet">
    /// <item><description>The bytes <c>0</c> through <c>3</c> are the Auth-Stage asymmetric parameters OId.</description></item>
    /// <item><description>The bytes <c>4</c> through <c>7</c> are the Primary-Stage asymmetric parameters OId.</description></item>
    /// <item><description>Bytes <c>8</c> and <c>9</c> identify the Auth-Stage DtmSession symmetric cipher parameters.</description></item>
    /// <item><description>Bytes <c>10</c> and <c>11</c> identify the Primary-Stage DtmSession symmetric cipher parameters.</description></item>
    /// <item><description>The third byte: <c>SubSet</c>, defines the PolyType; simple <c>1</c> or product form <c>2</c>.</description></item>
    /// <item><description>The last <c>4</c> bytes are used to uniquely identify the parameter set.</description></item>
    /// </list>
    /// </remarks>
    public static class DtmParamSets
    {
        #region Enums
        /// <summary>
        /// Set id prefix is defined as: Security Classification <c>X1</c> (maximum security), <c>X2</c> (high security), <c>X3</c> (security and speed), and <c>X4</c> (speed optimized).
        /// <para>The next 2 characters are the first letter of both asymmetric parameter ids. 
        /// This is followed by both symmetric cipher enumeration values and their Kdf engine type (Digests enum member or 0 for none).</para>
        /// </summary>
        public enum DtmParamNames : int
        {
            /// <summary>
            /// Class 1, X1.1 Configuration: Optimized for maximum security; (this is the recommended X1 parameter set).
            /// <para>Authentication Stage: Ring-LWE and 40 rounds of Serpent.
            /// Primary Stage: NTRU and 22 rounds of RHX with the Keccak512 Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X11RNS1R2 = 1,
            /// <summary>
            /// Class 1, X1.2 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: Ring-LWE and 20 rounds of TwoFish.
            /// Primary Stage: NTRU and 40 rounds of SHX with the Keccak512 Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X12RNT1S2,
            /// <summary>
            /// Class 2, X2.1 Configuration: Optimized for maximum security.
            /// <para>Authentication Stage: McEliece and 22 rounds of RHX.
            /// Primary Stage: NTRU and 22 rounds of THX with the Skein512 Kdf.
            /// Random bytes appended and prepended to exchange entities and message packets.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X21MNR2T2,
            /// <summary>
            /// Class 2, X2.2 Configuration: Optimized for security and speed; (this is the recommended x2 parameter set).
            /// <para>Authentication Stage: McEliece and 40 rounds of SHX.
            /// Primary Stage: NTRU and 22 rounds of RHX with the Skein512 Kdf.
            /// Random bytes appended and prepended to exchange entities.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X22MNS2R2,
            /// <summary>
            /// Class 3, X3.1 Configuration: Optimized for security and speed.
            /// <para>Authentication Stage: McEliece and 20 rounds of Twofish.
            /// Primary Stage: NTRU and 22 rounds of RHX with the Skein512 Kdf.
            /// Random bytes appended and prepended to exchange entities.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X31RNT1R2,
            /// <summary>
            /// Class 3, X3.2 Configuration: Optimized for security and speed.
            /// <para>Authentication Stage: Ring-LWE and 40 rounds of Serpent.
            /// Primary Stage: NTRU and 20 rounds of THX with the Skein512 Kdf.
            /// Random bytes appended and prepended to exchange entities.
            /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
            /// </summary>
            X32RNS1T2,
            /// <summary>
            /// Class 4, X4.1 Configuration: Optimized for speed.
            /// <para>Authentication Stage: Ring-LWE and 16 rounds of Twofish.
            /// Primary Stage: NTRU and 14 rounds of Rijndael.</para>
            /// </summary>
            X41RNT1R1,
            /// <summary>
            /// Class 4, X4.2 Configuration: Optimized for speed.
            /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
            /// Primary Stage: NTRU and 22 rounds of Rijndael.</para>
            /// </summary>
            X42RNS1R1
        }

        /// <summary>
        /// Represents the security classification of a predefined parameter set
        /// </summary>
        public enum SecurityContexts : int
        {
            /// <summary>
            /// Maximum Security: Set was implemented for a maximum security context
            /// </summary>
            X1 = 1,
            /// <summary>
            /// High Security: Set was implemented for a high security context
            /// </summary>
            X2,
            /// <summary>
            /// Security and Speed: Set was balanced for security and speed
            /// </summary>
            X3,
            /// <summary>
            /// Speed Optimized: Set was optimized for speed
            /// </summary>
            X4
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Retrieve a DtmParameters by its identity code
        /// </summary>
        /// 
        /// <param name="OId">The 16 byte parameter set identity code</param>
        /// 
        /// <returns>A populated DtmParameters parameter set</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static DtmParameters FromId(byte[] OId)
        {
            if (OId == null)
                throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId can not be null!", new ArgumentException());
            if (OId.Length != 16)
                throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId must be at least 16 bytes in length!", new ArgumentException());
            if (OId[0] != 1 && OId[0] != 2 && OId[0] != 3)
                throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId is not a valid DtmParameters parameter id!", new ArgumentException());
            if (OId[4] != 1 && OId[4] != 2 && OId[4] != 3)
                throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId is not a valid DtmParameters parameter id!", new ArgumentException());

            if (Compare.AreEqual(OId, GetID(DtmParamNames.X11RNS1R2)))
                return (DtmParameters)DTMX11RNS1R2.DeepCopy();
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X12RNT1S2)))
                return (DtmParameters)DTMX12RNT1S2.DeepCopy();
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X21MNR2T2)))
                return (DtmParameters)DTMX21MNR2T2.DeepCopy();
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X22MNS2R2)))
                return (DtmParameters)DTMX22MNS2R2.DeepCopy();
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X31RNT1R2)))
                return (DtmParameters)DTMX31RNT1R2.DeepCopy();
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X32RNS1T2)))
                return (DtmParameters)DTMX32RNS1T2.DeepCopy();
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X41RNT1R1)))
                return (DtmParameters)DTMX41RNT1R1.DeepCopy();
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X42RNS1R1)))
                return (DtmParameters)DTMX42RNS1R1.DeepCopy();

            throw new CryptoAsymmetricException("DtmParamSets:FromId", "OId does not identify a valid param set!", new ArgumentException());
        }

        /// <summary>
        /// Retrieve a DtmParameters by its enumeration name
        /// </summary>
        /// 
        /// <param name="Name">The enumeration name</param>
        /// 
        /// <returns>A populated DtmParameters parameter set</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown parameter name is used.</exception>
        public static DtmParameters FromName(DtmParamNames Name)
        {
            switch (Name)
            {
                case DtmParamNames.X11RNS1R2:
                    return (DtmParameters)DTMX11RNS1R2.DeepCopy();
                case DtmParamNames.X12RNT1S2:
                    return (DtmParameters)DTMX12RNT1S2.DeepCopy();
                case DtmParamNames.X21MNR2T2:
                    return (DtmParameters)DTMX21MNR2T2.DeepCopy();
                case DtmParamNames.X22MNS2R2:
                    return (DtmParameters)DTMX22MNS2R2.DeepCopy();
                case DtmParamNames.X31RNT1R2:
                    return (DtmParameters)DTMX31RNT1R2.DeepCopy();
                case DtmParamNames.X32RNS1T2:
                    return (DtmParameters)DTMX32RNS1T2.DeepCopy();
                case DtmParamNames.X41RNT1R1:
                    return (DtmParameters)DTMX41RNT1R1.DeepCopy();
                case DtmParamNames.X42RNS1R1:
                    return (DtmParameters)DTMX42RNS1R1.DeepCopy();
                default:
                    throw new CryptoAsymmetricException("DtmParamSets:FromName", "The enumeration name is unknown!", new ArgumentException());
            }
        }

        /// <summary>
        /// Returns the security classification prefix
        /// </summary>
        /// 
        /// <param name="OId">A DtmParameters OId</param>
        /// 
        /// <returns>The security classification prefix</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown parameter name is used.</exception>
        public static SecurityContexts GetContext(byte[] OId)
        {
            if (Compare.AreEqual(OId, GetID(DtmParamNames.X11RNS1R2)) || Compare.AreEqual(OId, GetID(DtmParamNames.X12RNT1S2)))
                return SecurityContexts.X1;
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X21MNR2T2)) || Compare.AreEqual(OId, GetID(DtmParamNames.X22MNS2R2)))
                return SecurityContexts.X2;
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X31RNT1R2)) || Compare.AreEqual(OId, GetID(DtmParamNames.X32RNS1T2)))
                return SecurityContexts.X3;
            else if (Compare.AreEqual(OId, GetID(DtmParamNames.X41RNT1R1)) || Compare.AreEqual(OId, GetID(DtmParamNames.X42RNS1R1)))
                return SecurityContexts.X4;
            else
                throw new CryptoAsymmetricException("DtmParamSets:GetContext", "The OId is unknown!", new ArgumentException());
        }

        /// <summary>
        /// Returns the security classification prefix
        /// </summary>
        /// 
        /// <param name="Name">The DtmParameters enumeration name</param>
        /// 
        /// <returns>The security classification prefix</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown parameter name is used.</exception>
        public static SecurityContexts GetContext(DtmParamNames Name)
        {
            switch (Name)
            {
                case DtmParamNames.X11RNS1R2:
                case DtmParamNames.X12RNT1S2:
                    return SecurityContexts.X1;
                case DtmParamNames.X21MNR2T2:
                case DtmParamNames.X22MNS2R2:
                    return SecurityContexts.X2;
                case DtmParamNames.X31RNT1R2:
                case DtmParamNames.X32RNS1T2:
                    return SecurityContexts.X3;
                case DtmParamNames.X41RNT1R1:
                case DtmParamNames.X42RNS1R1:
                    return SecurityContexts.X4;
                default:
                    throw new CryptoAsymmetricException("DtmParamSets:GetContext", "The enumeration name is unknown!", new ArgumentException());
            }
        }

        /// <summary>
        /// Retrieve the DtmParameters OId by its enumeration name
        /// </summary>
        /// 
        /// <param name="Name">The enumeration name</param>
        /// 
        /// <returns>The 16 byte DtmParameters OId field</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid or unknown OId is specified</exception>
        public static byte[] GetID(DtmParamNames Name)
        {
            switch (Name)
            {
                case DtmParamNames.X11RNS1R2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
                        new byte[] { (byte)BlockCiphers.SPX, 0, (byte)BlockCiphers.RHX, (byte)Digests.Keccak512, 1, 1, 0, 0 });
                case DtmParamNames.X12RNT1S2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
                        new byte[] { (byte)BlockCiphers.TFX, 0, (byte)BlockCiphers.SHX, (byte)Digests.Keccak512, 1, 2, 0, 0 });
                case DtmParamNames.X21MNR2T2:
                    return ArrayUtils.Concat(MPKCParamSets.GetID(MPKCParamSets.MPKCParamNames.FM12T67S256),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1861),
                        new byte[] { (byte)BlockCiphers.RHX, (byte)Digests.Skein512, (byte)BlockCiphers.THX, (byte)Digests.Skein512, 2, 1, 0, 0 });
                case DtmParamNames.X22MNS2R2:
                    return ArrayUtils.Concat(MPKCParamSets.GetID(MPKCParamSets.MPKCParamNames.FM12T67S256),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1861),
                        new byte[] { (byte)BlockCiphers.SHX, (byte)Digests.Skein512, (byte)BlockCiphers.RHX, (byte)Digests.Skein512, 2, 2, 0, 0 });
                case DtmParamNames.X31RNT1R2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1861),
                        new byte[] { (byte)BlockCiphers.TFX, 0, (byte)BlockCiphers.RHX, (byte)Digests.Skein512, 3, 1, 0, 0 });
                case DtmParamNames.X32RNS1T2:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
                        new byte[] { (byte)BlockCiphers.TFX, 0, (byte)BlockCiphers.RHX, (byte)Digests.Skein512, 3, 2, 0, 0 });
                case DtmParamNames.X41RNT1R1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FA2011743),
                        new byte[] { (byte)BlockCiphers.TFX, 0, (byte)BlockCiphers.RDX, 0, 4, 1, 0, 0 });
                case DtmParamNames.X42RNS1R1:
                    return ArrayUtils.Concat(RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
                        NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FA2011743),
                        new byte[] { (byte)BlockCiphers.SPX, 0, (byte)BlockCiphers.RDX, 0, 4, 2, 0, 0 });
                default:
                    throw new CryptoAsymmetricException("DtmParamSets:GetID", "The Parameter Name is not recognized!", new ArgumentException());
            }
        }
        #endregion

        #region Parameter Sets
        // param name: Security Class 'X' followed by optimization type and sub class: 1 or 2 is best security, 3 is security and speed, 4 is best speed
        // convention: first letter of asymmetric cipher and set/subset for both ciphers, then both symmetric ciphers first letter and type (1 for standard, 2 for extended)

        // X1 //

        /// <summary>
        /// Class 1, X1.1 Configuration: Optimized for maximum security; (this is the recommended X1 parameter set).
        /// <para>Authentication Stage: Ring-LWE and 40 rounds of Serpent.
        /// Primary Stage: NTRU and 22 rounds of RHX with the Keccak512 Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX11RNS1R2 = new DtmParameters(
            // the 16 byte idetifier field containing a description of the cipher (see class notes)
            GetID(DtmParamNames.X11RNS1R2),
            // the auth-stage asymmetric ciphers parameter oid (can also be a serialized parameter)
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            // the primary-stage asymmetric ciphers parameter oid
            NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
            // the auth-stage symmetric ciphers description
            new DtmSession(BlockCiphers.SPX, 32, IVSizes.V128, RoundCounts.R40),
            // the primary-stage symmetric ciphers description
            new DtmSession(BlockCiphers.RHX, 208, IVSizes.V128, RoundCounts.R22, Digests.Keccak512),
            // the random generator used to pad messages
            Prngs.CSPRng,
            // the maximum number of random bytes appended to a public key (actual number of bytes is chosen at random)
            1000,
            // the maximum number of random bytes prepended to a public key
            1000,
            // the maximum number of random bytes appended to the primary auth exchange (including asymmetric parameters)
            200,
            // the maximum number of random bytes prepended to the primary auth exchange
            200,
            // the maximum number of random bytes appended to the primary symmetric key exchange
            200,
            // the maximum number of random bytes prepended to the primary symmetric key exchange
            200,
            // the maximum number of random bytes appended to each post-exchange message (apply message append/prepend to hide the message type)
            0,
            // the maximum number of random bytes prepended to each post-exchange message
            0,
            // the maximum delay time before transmitting the primary public key   
            200,
            // the maximum delay time before transmitting the symmetric key
            10,
            // the maximum delay time before transmitting a message
            0);

        /// <summary>
        /// Class 1, X1.2 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: Ring-LWE and 20 rounds of TwoFish.
        /// Primary Stage: NTRU and 40 rounds of SHX with the Keccak512 Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX12RNT1S2 = new DtmParameters(
            GetID(DtmParamNames.X12RNT1S2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
            new DtmSession(BlockCiphers.TFX, 32, IVSizes.V128, RoundCounts.R20),
            new DtmSession(BlockCiphers.SHX, 208, IVSizes.V128, RoundCounts.R40, Digests.Keccak512),
            Prngs.CSPRng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            100,
            100,
            200);

        // X2 //

        /// <summary>
        /// Class 2, X2.1 Configuration: Optimized for maximum security.
        /// <para>Authentication Stage: McEliece and 22 rounds of RHX.
        /// Primary Stage: NTRU and 22 rounds of THX with the Skein512 Kdf.
        /// Random bytes appended and prepended to exchange entities and message packets.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX21MNR2T2 = new DtmParameters(
            GetID(DtmParamNames.X21MNR2T2),
            MPKCParamSets.GetID(MPKCParamSets.MPKCParamNames.FM12T67S256),
            NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1861),
            new DtmSession(BlockCiphers.RHX, 192, IVSizes.V128, RoundCounts.R22, Digests.Skein512),
            new DtmSession(BlockCiphers.THX, 192, IVSizes.V128, RoundCounts.R22, Digests.Skein512),
            Prngs.CSPRng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            100,
            100,
            200);

        /// <summary>
        /// Class 2, X2.2 Configuration: Optimized for security and speed; (this is the recommended x2 parameter set).
        /// <para>Authentication Stage: McEliece and 40 rounds of SHX.
        /// Primary Stage: NTRU and 22 rounds of RHX with the Skein512 Kdf.
        /// Random bytes appended and prepended to exchange entities.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX22MNS2R2 = new DtmParameters(
            GetID(DtmParamNames.X22MNS2R2),
            MPKCParamSets.GetID(MPKCParamSets.MPKCParamNames.FM12T67S256),
            NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1861),
            new DtmSession(BlockCiphers.SHX, 192, IVSizes.V128, RoundCounts.R40, Digests.Skein512),
            new DtmSession(BlockCiphers.RHX, 192, IVSizes.V128, RoundCounts.R22, Digests.Skein512),
            Prngs.CSPRng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            0,
            0,
            200);

        // X3 //

        /// <summary>
        /// Class 3, X3.1 Configuration: Optimized for security and speed.
        /// <para>Authentication Stage: Ring-LWE and 20 rounds of Twofish.
        /// Primary Stage: NTRU and 22 rounds of RHX with the Skein512 Kdf.
        /// Random bytes appended and prepended to exchange entities.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX31RNT1R2 = new DtmParameters(
            GetID(DtmParamNames.X31RNT1R2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1861),
            new DtmSession(BlockCiphers.TFX, 32, IVSizes.V128, RoundCounts.R20),
            new DtmSession(BlockCiphers.RHX, 192, IVSizes.V128, RoundCounts.R22, Digests.Skein512),
            Prngs.CSPRng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            0,
            0,
            200);

        /// <summary>
        /// Class 3, X3.2 Configuration: Optimized for security and speed.
        /// <para>Authentication Stage: Ring-LWE and 40 rounds of Serpent.
        /// Primary Stage: NTRU and 20 rounds of THX with the Skein512 Kdf.
        /// Random bytes appended and prepended to exchange entities.
        /// Maximum 200 Millisecond transmission delay post primary key creation.</para>
        /// </summary>
        public static readonly DtmParameters DTMX32RNS1T2 = new DtmParameters(
            GetID(DtmParamNames.X32RNS1T2),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.CX1931),
            new DtmSession(BlockCiphers.SPX, 32, IVSizes.V128, RoundCounts.R40),
            new DtmSession(BlockCiphers.THX, 192, IVSizes.V128, RoundCounts.R20, Digests.Skein512),
            Prngs.CSPRng,
            1000,
            1000,
            200,
            200,
            200,
            200,
            0,
            0,
            200);

        // X4 //

        /// <summary>
        /// Class 4, X4.1 Configuration: Optimized for speed.
        /// <para>Authentication Stage: Ring-LWE and 16 rounds of Twofish.
        /// Primary Stage: NTRU and 14 rounds of Rijndael.</para>
        /// </summary>
        public static readonly DtmParameters DTMX41RNT1R1 = new DtmParameters(
            GetID(DtmParamNames.X41RNT1R1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FA2011743),
            new DtmSession(BlockCiphers.TFX, 32, IVSizes.V128, RoundCounts.R16),
            new DtmSession(BlockCiphers.RDX, 32, IVSizes.V128, RoundCounts.R14),
            Prngs.CSPRng);

        /// <summary>
        /// Class 4, X4.2 Configuration: Optimized for speed.
        /// <para>Authentication Stage: Ring-LWE and 32 rounds of Serpent.
        /// Primary Stage: NTRU and 22 rounds of Rijndael.</para>
        /// </summary>
        public static readonly DtmParameters DTMX42RNS1R1 = new DtmParameters(
            GetID(DtmParamNames.X42RNS1R1),
            RLWEParamSets.GetID(RLWEParamSets.RLWEParamNames.N512Q12289),
            NTRUParamSets.GetID(NTRUParamSets.NTRUParamNames.FA2011743),
            new DtmSession(BlockCiphers.SPX, 32, IVSizes.V128, RoundCounts.R32),
            new DtmSession(BlockCiphers.RDX, 64, IVSizes.V128, RoundCounts.R22),
            Prngs.CSPRng);
        #endregion
    }
}
