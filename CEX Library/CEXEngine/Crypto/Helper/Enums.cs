using System;

namespace VTDev.Libraries.CEXEngine.Crypto
{
    #region Enums
    /// <summary>
    /// <para>Block sizes in bits. Can be cast as Block byte size integers, 
    /// i.e. (int sz = BlockSizes.B512) is equal to 64.</para>
    /// </summary>
    public enum BlockSizes : int
    {
        /// <summary>
        /// 128 bit block size
        /// </summary>
        B128 = 16,
        /// <summary>
        /// 256 bit block size
        /// </summary>
        B256 = 32,
        /// <summary>
        /// 512 bit block size
        /// </summary>
        B512 = 64,
        /// <summary>
        /// 1024 bit block size
        /// </summary>
        B1024 = 128
    }

    /// <summary>
    /// Cipher Modes
    /// </summary>
    public enum CipherModes : int
    {
        /// <summary>
        /// Cipher Block Chaining Mode
        /// </summary>
        CBC = 0,
        /// <summary>
        /// Cipher FeedBack Mode
        /// </summary>
        CFB,
        /// <summary>
        /// SIC Counter Mode
        /// </summary>
        CTR,
        /*/// <summary> // test only
        /// Electronic CodeBook Mode
        /// </summary>
        ECB,*/
        /// <summary>
        /// Output FeedBack Mode
        /// </summary>
        OFB
    }

    /// <summary>
    /// Message Digests
    /// </summary>
    public enum Digests : int
    {
        /// <summary>
        /// The Blake digest with a 256 bit return size
        /// </summary>
        Blake256 = 0,
        /// <summary>
        /// The Blake digest with a 512 bit return size
        /// </summary>
        Blake512,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 256 bit return size
        /// </summary>
        Keccak256,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 512 bit return size
        /// </summary>
        Keccak512,
        /// <summary>
        /// The SHA-3 digest based on Keccak with a 1024 bit return size
        /// </summary>
        Keccak1024,
        /// <summary>
        ///The SHA-2 digest with a 256 bit return size
        /// </summary>
        SHA256,
        /// <summary>
        /// The SHA-2 digest with a 512 bit return size
        /// </summary>
        SHA512,
        /// <summary>
        /// The Skein digest with a 256 bit return size
        /// </summary>
        Skein256,
        /// <summary>
        /// The Skein digest with a 512 bit return size
        /// </summary>
        Skein512,
        /// <summary>
        /// The Skein digest with a 1024 bit return size
        /// </summary>
        Skein1024
    }

    /// <summary>
    /// Encryption Ciphers
    /// </summary>
    public enum Engines : int
    {
        /// <summary>
        /// An implementation of the ChaCha Stream Cipher
        /// </summary>
        ChaCha = 0,
        /// <summary>
        /// An implementation of the Twofish and Rijndael Merged Stream Cipher
        /// </summary>
        Fusion,
        /// <summary>
        /// An extended implementation of the Rijndael Block Cipher
        /// </summary>
        RDX,
        /// <summary>
        /// An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
        /// </summary>
        RHX,
        /// <summary>
        /// An implementation based on the Rijndael and Serpent Merged Block Cipher
        /// </summary>
        RSM,
        /*/// <summary> // Depricated, class removed by 1.3.3
        /// (Deprecated, gone by 1.4) An extended implementation of the Rijndael Block Cipher, using a Serpent key schedule
        /// </summary>
        RSX, */
        /*/// <summary> // Depricated, class removed by 1.3.3
        /// A Dual AES CTR parallelized Stream Cipher
        /// </summary>
        DCS, */
        /// <summary>
        /// A Salsa20 Stream Cipher
        /// </summary>
        Salsa,
        /// <summary>
        /// An extended implementation of the Serpent Block Cipher
        /// </summary>
        SPX,
        /// <summary>
        /// The Serpent Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        SHX,
        /// <summary>
        /// An extended implementation of the Twofish Block Cipher
        /// </summary>
        TFX,
        /// <summary>
        /// A Twofish Block Cipher Extended with an HKDF Key Schedule
        /// </summary>
        THX,
        /// <summary>
        /// An implementation based on the Twofish and Serpent Merged Block Ciphers, using an HKDF Key Schedule
        /// </summary>
        TSM
    }

    /// <summary>
    /// Random Generator Digest KDFs
    /// </summary>
    public enum KdfGenerators : int
    {
        /// <summary>
        /// An implementation of a Digest Counter based DRBG
        /// </summary>
        DGCDRBG,
        /// <summary>
        /// A Hash based Key Derivation Function HKDF
        /// </summary>
        HKDF,
        /// <summary>
        /// An implementation of a Hash based Key Derivation Function PBKDF2
        /// </summary>
        PBKDF2,
    }

    /// <summary>
    /// Random Generators
    /// </summary>
    public enum Generators : int
    {
        /// <summary>
        /// An implementation of a Encryption Counter based DRBG
        /// </summary>
        CTRDRBG = 0,
        /// <summary>
        /// An implementation of a Digest Counter based DRBG
        /// </summary>
        DGCDRBG,
        /// <summary>
        /// A Hash based Key Derivation Function HKDF
        /// </summary>
        HKDF,
        /// <summary>
        /// An implementation of a Hash based Key Derivation Function PBKDF2
        /// </summary>
        PBKDF2,
        /// <summary>
        /// An implementation of a Hash based Key Derivation PKCS#5 Version 2
        /// </summary>
        PKCS5
    }

    /// <summary>
    /// KeyPolicy enumeration flags stored in a <see cref="VTDev.Libraries.CEXEngine.Crypto.Structures.KeyPackage"/> structure. 
    /// <para>Used to define how the <see cref="VTDev.Libraries.CEXEngine.Crypto.Helper.KeyFactory"/> class manages access to a key package file.
    /// Values can be combined, and tested with the KeyPackage HasPolicy(group, policy), SetPolicy(package, index, policy) and ClearPolicy(package, index, policy) methods.</para>
    /// </summary>
    [Flags]
    public enum KeyPolicies : long
    {
        /// <summary>
        /// No change to policy is applied. Will not change an existing policy, to clear a policy flag use the ClearPolicy(group, policy) method in KeyPackage
        /// </summary>
        None = 0,
        /// <summary>
        /// Key package subkeys are only valid for only one cycle of decryption, after which the key is locked out
        /// </summary>
        SingleUse = 16,
        /// <summary>
        /// Key package is time sensitive. Expiration date (Ticks) of key is assigned to the OptionFlag in a KeyPackage structure
        /// </summary>
        Volatile = 32,
        /// <summary>
        /// Key package subkeys are valid for only one cycle of decryption, after which the sub-key set is erased in the key package file.
        /// </summary>
        PostOverwrite = 64,
        /// <summary>
        /// An operator may be able to decrypt a file with this key, but information within the key package header should be considered sensitive
        /// </summary>
        NoNarrative = 128,
        /// <summary>
        /// Use of this key will be restricted to the domain id contained in the KeyPackage structures DomainId parameter.
        /// </summary>
        DomainRestrict = 256,
        /// <summary>
        /// Domain id is set as the targets unique identity field, use is restricted to that node. Overrides the DomainRestrict flag.
        /// </summary>
        IdentityRestrict = 512,
        /// <summary>
        /// The key package may only be used by the creator
        /// </summary>
        NoExport = 1024,
        /// <summary>
        /// Master authenticator; key packages created with this flag can be used for encryption by anyone. Should be combined with identity or domain restrict flags, 
        /// and only be used for centralized key generation within a secured network or group framework.
        /// </summary>
        MasterAuth = 2048,
        /// <summary>
        /// If this flag is set, the KeyPackage.KeyAuthority:TargetId field is set to the targets OriginId, and used to authenticate the operator. This is an encryption flag.
        /// </summary>
        PackageAuth = 4096
    }

    /// <summary>
    /// Key authentication scope. 
    /// <para>Indicates at which privilege level the key can be accessed. 
    /// Used by the <see cref="VTDev.Libraries.CEXEngine.Crypto.Helper.KeyFactory"/> class as an access level description.</para>
    /// </summary>
    public enum KeyScope : int
    {
        /// <summary>
        /// Creator of this key; full access
        /// </summary>
        Creator = 1,
        /// <summary>
        /// Key recipient; decrypt only access
        /// </summary>
        Operator,
        /// <summary>
        /// The operator is denied access to this key
        /// </summary>
        NoAccess
    }

    /// <summary>
    /// <see cref="VTDev.Libraries.CEXEngine.Crypto.Structures.KeyPackage"/> subkey policy flags describing the current state of that subkey set.
    /// <para>Used by the <see cref="VTDev.Libraries.CEXEngine.Crypto.Helper.KeyFactory"/> class to set a subkey operational state flag.</para>
    /// </summary>
    [Flags]
    public enum KeyStates : long
    {
        /// <summary>
        /// The subkey set is no longer valid for encryption
        /// </summary>
        Expired = 1,
        /// <summary>
        /// The subkey was set to the PostOverwrite policy and has been used for decryption and subsequently erased
        /// </summary>
        Erased = 2,
        /// <summary>
        /// The subkey was set to the SingleUse policy and has been used for decryption and subsequently locked for access
        /// </summary>
        Locked = 4,
        /// <summary>
        /// An action has caused the erasure of the entire subkey set array
        /// </summary>
        Destroyed = 8
    }

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

    /// <summary>
    /// <para>Key Sizes in bits. Can be cast as Key byte size integers, 
    /// i.e. (int sz = KeySizes.K256) is equal to 32.</para>
    /// </summary>
    public enum KeySizes : int
    {
        /// <summary>
        /// 128 bit Key
        /// </summary>
        K128 = 16,
        /// <summary>
        /// 192 bit Key
        /// </summary>
        K192 = 24,
        /// <summary>
        /// 256 bit Key
        /// </summary>
        K256 = 32,
        /// <summary>
        /// 384 bit Key
        /// </summary>
        K384 = 48,
        /// <summary>
        /// 448 bit Key
        /// </summary>
        K448 = 56,
        /// <summary>
        /// 512 bit Key
        /// </summary>
        K512 = 64,
        /// <summary>
        /// 768 bit Key
        /// </summary>
        K768 = 96,
        /// <summary>
        /// 1024 bit Key
        /// </summary>
        K1024 = 128,
        /// <summary>
        /// 1088 bit Key
        /// </summary>
        K1088 = 136,
        /// <summary>
        /// 1280 bit Key
        /// </summary>
        K1280 = 160,
        /// <summary>
        /// 1536 bit Key
        /// </summary>
        K1536 = 192,
        /// <summary>
        /// 1664 bit Key
        /// </summary>
        K1664 = 208,
        /// <summary>
        /// 1792 bit Key
        /// </summary>
        K1792 = 224,
        /// <summary>
        /// 2048 bit Key
        /// </summary>
        K2048 = 256,
        /// <summary>
        /// 2240 bit Key
        /// </summary>
        K2240 = 280,
        /// <summary>
        /// 2304 bit Key
        /// </summary>
        K2304 = 288,
        /// <summary>
        /// 2560 bit Key
        /// </summary>
        K2560 = 320,
        /// <summary>
        /// 2816 bit Key 
        /// </summary>
        K2816 = 352,
        /// <summary>
        /// 3072 bit Key
        /// </summary>
        K3072 = 384,
        /// <summary>
        /// 3584 bit Key
        /// </summary>
        K3584 = 448,
        /// <summary>
        /// 4096 bit Key
        /// </summary>
        K4096 = 512,
        /// <summary>
        /// 4608 bit Key
        /// </summary>
        K4608 = 576,
        /// <summary>
        /// 5120 bit Key
        /// </summary>
        K5120 = 640
    }

    /// <summary>
    /// Message Authentication Code Generators
    /// </summary>
    public enum Macs : int
    {
        /// <summary>
        /// A Cipher based Message Authentication Code wrapper (CMAC)
        /// </summary>
        CMAC = 0,
        /// <summary>
        /// A Hash based Message Authentication Code wrapper (HMAC)
        /// </summary>
        HMAC,
        /// <summary>
        /// SHA256 Hash based Message Authentication Code
        /// </summary>
        SHA256HMAC,
        /// <summary>
        /// SHA512 Hash based Message Authentication Code
        /// </summary>
        SHA512HMAC,
        /// <summary>
        /// A Variably Modified Permutation Composition based Message Authentication Code (VMPC-MAC)
        /// </summary>
        VMPCMAC
    }

    /// <summary>
    /// Pseudo Random Generators
    /// </summary>
    public enum Prngs : int
    {
        /// <summary>
        /// A Blum-Blum-Shub random number generator
        /// </summary>
        BBSG = 0,
        /// <summary>
        /// A Cubic Congruential Generator II (CCG) random number generator
        /// </summary>
        CCG,
        /// <summary>
        ///  A Secure PRNG using RNGCryptoServiceProvider
        /// </summary>
        CSPRng,
        /// <summary>
        /// A Modular Exponentiation Generator (MODEXPG) random number generator
        /// </summary>
        MODEXPG,
        /// <summary>
        /// A Quadratic Congruential Generator I (QCG-I) random number generator
        /// </summary>
        QCG1,
        /// <summary>
        /// A Quadratic Congruential Generator II (QCG-II) random number generator
        /// </summary>
        QCG2
    }

    /// <summary>
    /// Padding Modes
    /// </summary>
    public enum PaddingModes : int
    {
        /// <summary>
        /// ISO7816 Padding Mode
        /// </summary>
        ISO7816 = 0,
        /// <summary>
        /// PKCS7 Padding Mode
        /// </summary>
        PKCS7,
        /// <summary>
        /// Trailing Bit Complement Padding Mode
        /// </summary>
        TBC,
        /// <summary>
        /// X923 Padding Mode
        /// </summary>
        X923,
        /*/// <summary> // test only
        /// Zero Padding Mode
        /// </summary>
        Zeros*/
    }

    /// <summary>
    /// Rounds Count. Can be cast as round count integers, 
    /// i.e. (int ct = RoundCounts.R12) is equal to 12.
    /// </summary>
    public enum RoundCounts : int
    {
        /// <summary>
        /// 8 Rounds: ChaCha
        /// </summary>
        R8 = 8,
        /// <summary>
        /// 10 Rounds: ChaCha, RHX, RSM
        /// </summary>
        R10 = 10,
        /// <summary>
        /// 12 Rounds: ChaCha, RHX
        /// </summary>
        R12 = 12,
        /// <summary>
        /// 14 Rounds: ChaCha, RHX
        /// </summary>
        R14 = 14,
        /// <summary>
        /// 16 Rounds: ChaCha, Fusion, TFX, THX, TSM
        /// </summary>
        R16 = 16,
        /// <summary>
        /// 18 Rounds: ChaCha, Fusion, RSM, TFX, THX, TSM
        /// </summary>
        R18 = 18,
        /// <summary>
        /// 20 Rounds: ChaCha, Fusion, TFX, THX, TSM
        /// </summary>
        R20 = 20,
        /// <summary>
        /// 22 Rounds: ChaCha, Fusion, RHX, TFX, THX, TSM
        /// </summary>
        R22 = 22,
        /// <summary>
        /// 24 Rounds: ChaCha, Fusion, TFX, THX, TSM
        /// </summary>
        R24 = 24,
        /// <summary>
        /// 26 Rounds: ChaCha, Fusion, RSM, TFX, THX, TSM
        /// </summary>
        R26 = 26,
        /// <summary>
        /// 28 Rounds: ChaCha, Fusion, TFX, THX, TSM
        /// </summary>
        R28 = 28,
        /// <summary>
        /// 30 Rounds: ChaCha, Fusion, TFX, THX, TSM
        /// </summary>
        R30 = 30,
        /// <summary>
        /// 32 Rounds: Fusion, SHX, SPX, TFX, THX, TSM
        /// </summary>
        R32 = 32,
        /// <summary>
        /// 34 Rounds, RSM
        /// </summary>
        R34 = 34,
        /// <summary>
        /// 38 Rounds, RHX
        /// </summary>
        R38 = 38,
        /// <summary>
        /// 40 Rounds: SHX, SPX
        /// </summary>
        R40 = 40,
        /// <summary>
        /// 42 Rounds: RSM
        /// </summary>
        R42 = 42,
        /// <summary>
        /// 48 Rounds: SHX, SPX
        /// </summary>
        R48 = 48,
        /// <summary>
        /// 56 Rounds: SHX, SPX
        /// </summary>
        R56 = 56,
        /// <summary>
        /// 64 Rounds: SHX, SPX
        /// </summary>
        R64 = 64,
        /// <summary>
        /// 80 Rounds: SHX
        /// </summary>
        R80 = 80,
        /// <summary>
        /// 96 Rounds: SHX
        /// </summary>
        R96 = 96,
        /// <summary>
        /// 128 Rounds: SHX
        /// </summary>
        R128 = 128
    }
    #endregion
}