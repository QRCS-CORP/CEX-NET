#region Enums
/// <summary>
/// Encryption Algorithm
/// </summary>
public enum Algorithms : int
{
    RDX,
    RSX,
    DCS,
}

/// <summary>
/// Key sizes
/// </summary>
public enum KeySizes : ushort
{
    K128 = 0,
    K192,
    K256,
    K512,
}

/// <summary>
/// IV sizes
/// </summary>
public enum IVSizes : ushort
{
    V128 = 0,
    V256,
}

/// <summary>
/// Block sizes
/// </summary>
public enum BlockSizes : int
{
    B16,
    B32,
}

/// <summary>
/// Cipher modes
/// </summary>
public enum CipherModes : int
{
    None = 0,
    CBC,
    CTR,
    PSC,
}

/// <summary>
/// Padding modes
/// </summary>
public enum PaddingModes : int
{
    None = 0,
    Zeros,
    PKCS7,
    X923,
}
#endregion