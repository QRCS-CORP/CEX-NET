#region Enums
/// <summary>
/// Encryption Algorithms
/// </summary>
public enum Engines : int
{
    ChaCha,
    Fusion,
    RDX,
    RHX,
    RSM,
    RSX,
    DCS,
    Salsa,
    SPX,
    SHX,
    TFX,
    THX,
    TSM
}

/// <summary>
/// Key sizes
/// </summary>
public enum KeySizes : ushort
{
    K128 = 0,
    K192,
    K256,
    K384,
    K448,
    K512,
    K1024,
    K1536,
    K2560,
    K3584,
    K4608
}

/// <summary>
/// IV sizes
/// </summary>
public enum IVSizes : ushort
{
    V64 = 0,
    V128,
    V256
}

/// <summary>
/// Block sizes
/// </summary>
public enum BlockSizes : int
{
    B128,
    B256,
    B512
}

/// <summary>
/// Cipher modes
/// </summary>
public enum CipherModes : int
{
    None = 0,
    CBC,
    CTR,
    ECB
}

/// <summary>
/// Padding modes
/// </summary>
public enum PaddingModes : int
{
    None = 0,
    Zeros,
    PKCS7,
    X923
}

/// <summary>
/// Rounds count
/// </summary>
public enum RoundCounts : int
{
    R8,
    R10,
    R12,
    R14,
    R16,
    R18,
    R20,
    R22,
    R24,
    R26,
    R28,
    R30,
    R32,
    R34,
    R38,
    R40,
    R42,
    R48,
    R56,
    R64,
    R80,
    R96,
    R128
}
#endregion