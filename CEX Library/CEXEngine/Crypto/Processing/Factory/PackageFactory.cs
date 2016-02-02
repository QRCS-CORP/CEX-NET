#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Factory
{
    /// <summary>
    /// PackageFactory: Used to create or extract a Key Package file.
    /// <para>This class works in conjunction with the <see cref="PackageKey"/> structure to create and manage key package files; encryption key bundles, that contain cipher Key and IV material, 
    /// and optionally an HMAC key used for message authentication.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example using the <see cref="Create(PackageKey, SeedGenerators, Digests)"/> method:</description>
    /// <code>
    /// // populate a KeyAuthority structure
    /// KeyAuthority authority =  new KeyAuthority(domainId, originId, packageId, packageTag, keyPolicy);
    /// // create a key file
    /// MemoryStream keyStream = new MemoryStream();
    /// new PackageFactory(keyStream, authority).Create(PackageKey);
    /// </code>
    /// 
    /// <description>Example using the <see cref="Extract(byte[], out CipherDescription, out KeyParams, out byte[])"/> method to get an existing key for decryption:</description>
    /// <code>
    /// // populate a KeyAuthority structure
    /// KeyAuthority authority =  new KeyAuthority(domainId, originId, packageId, packageTag, keyPolicy);
    /// KeyParams keyparam;
    /// CipherDescription description;
    /// byte[] extKey;
    /// byte[] keyId;
    /// 
    /// // extract a key for decryption
    /// using (PackageFactory factory = new PackageFactory(KeyStream, authority))
    ///     factory.Extract(keyId, out description, out keyparam, out extKey);
    /// </code>
    /// 
    /// <description>Example using the <see cref="NextKey(out CipherDescription, out KeyParams, out byte[])"/> method to get an unused key for encryption:</description>
    /// <code>
    /// // populate a KeyAuthority structure
    /// KeyAuthority authority =  new KeyAuthority(domainId, originId, packageId, packageTag, keyPolicy);
    /// KeyParams keyparam;
    /// CipherDescription description;
    /// byte[] extKey;
    ///
    /// // get the next available encryption subkey
    /// using (PackageFactory factory = new PackageFactory(KeyStream, authority))
    ///     keyId = factory.NextKey(out description, out keyparam, out extKey)
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
    /// <revision date="2015/02/23" version="1.3.2.0">Reconstructed and expanded to process CipherDescription, KeyAuthority, and PackageKey structures</revision>
    /// <revision date="2015/05/18" version="1.3.5.0">Renamed to PackageFactory</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures PackageKey Structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.KeyAuthority">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures KeyAuthority structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherDescription Structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies">VTDev.Libraries.CEXEngine.Crypto.Enumeration KeyPolicies Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates">VTDev.Libraries.CEXEngine.Crypto KeyStates Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyGenerator">VTDev.Libraries.CEXEngine.Crypto.KeyGenerator class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams">VTDev.Libraries.CEXEngine.Crypto.Processing.Structure KeyParams class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream">VTDev.Libraries.CEXEngine.Crypto.Processing CipherStream class</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <para>A PackageKey file contains a <see cref="KeyAuthority"/> structure that defines its identity and security settings, 
    /// a <see cref="CipherDescription"/> that contains the settings required to create a specific cipher instance, and the 'subkey set', an array of unique subkey id strings and 
    /// policy flags that identify and control each subkey.</para>
    /// <para>A PackageKey can contain one subkey, or many thousands of subkeys. Each subkey provides a unique keying material, and can only be used once for encryption; 
    /// guaranteeing a unique Key, IV, and HMAC key is used for every single encryption cycle.</para>
    /// <para>Each subkey in the Key Package contains a unique policy flag, which can be used to mark a key as locked(decryption) or expired(encryption), or trigger an erasure 
    /// of a specific subkey after the key is read for decryption using the <see cref="Extract(byte[], out CipherDescription, out KeyParams, out byte[])"/> function.</para>
    /// 
    /// <list type="bullet">
    /// <item><description>Constructors may use either a memory or file stream, and a <see cref="KeyAuthority"/> structure.</description></item>
    /// <item><description>The <see cref="Create(PackageKey, SeedGenerators, Digests)"/> method auto-generates the keying material.</description></item>
    /// <item><description>The Extract() method retrieves a populated cipher description (CipherDescription), key material (KeyParams), and the file extension key from the key file.</description></item>
    /// </list>
    /// </remarks>
    public sealed class PackageFactory : IDisposable
    {
        #region Constants
        // fewer than 10 subkeys per package is best security
        private const int SUBKEY_MAX = 100000;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private Stream _keyStream;
        private PackageKey _keyPackage;
        private KeyAuthority _keyOwner;
        #endregion

        #region Properties
        /// <summary>
        /// The access rights available to the current user of this <see cref="PackageKey"/>
        /// </summary>
        public KeyScope AccessScope { private set; get; }

        /// <summary>
        /// Are we the Creator of this PackageKey
        /// </summary>
        public bool IsCreator { private set; get; }

        /// <summary>
        /// The PackageKey <see cref="KeyPolicies">policy flags</see>
        /// </summary>
        public long KeyPolicy { private set; get; }

        /// <summary>
        /// The last error string
        /// </summary>
        public string LastError { private set; get; }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class with a key file path. 
        /// <para>If the key exixts, permissions are tested, otherwise this path is used as the new key path and file name.</para>
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream used to create or extract the key file</param>
        /// <param name="Authority">The local KeyAuthority credentials structure</param>
        public PackageFactory(Stream KeyStream, KeyAuthority Authority)
        {
            // store authority
            _keyOwner = Authority;
            // file or memory stream
            _keyStream = KeyStream;

            if (_keyStream.Length > 0)
                AccessScope = Authenticate();
        }

        private PackageFactory()
        {
        }

        /// <summary>
        /// Finalizer: ensure resources are destroyed
        /// </summary>
        ~PackageFactory()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Authentication tests; specific target domain or identity, passphrase, 
        /// and export permissions within the PackageKey key policy settings are checked
        /// </summary>
        /// 
        /// <returns>Authorized to use this key</returns>
        public KeyScope Authenticate()
        {
            try
            {
                // get the key headers
                _keyPackage = GetPackage();
                // store the master policy flag
                KeyPolicy = _keyPackage.KeyPolicy;
                // did we create this key
                IsCreator = Compare.IsEqual(_keyOwner.OriginId, _keyPackage.Authority.OriginId);

                // key made by master auth, valid only if authenticated by PackageAuth, IdentityRestrict or DomainRestrict
                if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.MasterAuth))
                {
                    if (Compare.IsEqual(_keyOwner.DomainId, _keyPackage.Authority.DomainId))
                    {
                        LastError = "";
                        return KeyScope.Creator;
                    }
                    else if (Compare.IsEqual(_keyOwner.PackageId, _keyPackage.Authority.PackageId))
                    {
                        LastError = "";
                        return KeyScope.Creator;
                    }
                    else if (Compare.IsEqual(_keyOwner.TargetId, _keyPackage.Authority.TargetId))
                    {
                        LastError = "";
                        return KeyScope.Creator;
                    }
                }

                // the key targets a specific installation identity
                if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.IdentityRestrict))
                {
                    // test only if not creator
                    if (!Compare.IsEqual(_keyOwner.OriginId, _keyPackage.Authority.OriginId))
                    {
                        // owner target field is set as a target OriginId hash
                        if (!Compare.IsEqual(_keyOwner.TargetId, _keyPackage.Authority.TargetId))
                        {
                            LastError = "You are not the intendant recipient of this key! Access is denied.";
                            return KeyScope.NoAccess;
                        }
                    }
                }

                if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.DomainRestrict))
                {
                    // the key is domain restricted
                    if (!Compare.IsEqual(_keyOwner.DomainId, _keyPackage.Authority.DomainId))
                    {
                        LastError = "Domain identification check has failed! You must be a member of the same Domain as the Creator of this key.";
                        return KeyScope.NoAccess;
                    }
                }

                // the key package id is an authentication passphrase hash
                if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.PackageAuth))
                {
                    if (!Compare.IsEqual(_keyOwner.PackageId, _keyPackage.Authority.PackageId))
                    {
                        LastError = "Key Package authentication has failed! Access is denied.";
                        return KeyScope.NoAccess;
                    }
                }

                // test for volatile flag
                if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.Volatile))
                {
                    if (_keyPackage.Authority.OptionFlag != 0 && _keyPackage.Authority.OptionFlag < DateTime.Now.Ticks)
                    {
                        LastError = "This key has expired and can no longer be used! Access is denied.";
                        return KeyScope.NoAccess;
                    }
                }

                // only the key creator is allowed access 
                if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.NoExport))
                {
                    if (!Compare.IsEqual(_keyOwner.OriginId, _keyPackage.Authority.OriginId))
                    {
                        LastError = "Only the Creator of this key is authorized! Access is denied.";
                        return KeyScope.NoAccess;
                    }
                }

                LastError = "";
                return IsCreator ? KeyScope.Creator : KeyScope.Operator;
            }
            catch (Exception Ex)
            {
                LastError = Ex.Message;
                return KeyScope.NoAccess;
            }
        }

        /// <summary>
        /// Test a key to see if it contains a subkey with a specific id
        /// </summary>
        /// 
        /// <param name="KeyId">The subkey id to test</param>
        /// 
        /// <returns>The index of the subkey, or -1 if key is not in the PackageKey</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the user has insufficient access rights to access this PackageKey</exception>
        public int ContainsSubKey(byte[] KeyId)
        {
            if (AccessScope.Equals(KeyScope.NoAccess))
                throw new CryptoProcessingException("PackageFactory:ContainsSubKey", "You do not have permission to access this key!", new UnauthorizedAccessException());

            for (int i = 0; i < _keyPackage.SubKeyID.Length; i++)
            {
                if (Compare.IsEqual(KeyId, _keyPackage.SubKeyID[i]))
                    return i;
            }
            return -1;
        }

        /// <summary>
        /// Create a key file using a <see cref="PackageKey"/> structure; containing the cipher description and operating ids and flags.
        /// </summary>
        /// 
        /// <param name="Package">The <see cref="PackageKey">Key Header</see> containing the cipher description and operating ids and flags</param>
        /// <param name="SeedEngine">The <see cref="SeedGenerators">Random Generator</see> used to create the stage 1 seed material during key generation.</param>
        /// <param name="DigestEngine">The <see cref="Digests">Digest Engine</see> used in the stage II phase of key generation.</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a key file exists at the path specified, the path is read only, the CipherDescription or KeyAuthority structures are invalid, or
        /// number of SubKeys specified is either less than 1 or more than the maximum allowed (100,000)</exception>
        public void Create(PackageKey Package, SeedGenerators SeedEngine = SeedGenerators.CSPRsg, Digests DigestEngine = Digests.SHA512)
        {
            // if you are getting exceptions.. read the docs!
            if (!CipherDescription.IsValid(Package.Description))
                throw new CryptoProcessingException("PackageFactory:Create", "The key package cipher settings are invalid!", new FormatException());
            if (!KeyAuthority.IsValid(Package.Authority))
                throw new CryptoProcessingException("PackageFactory:Create", "The key package key authority settings are invalid!", new FormatException());
            if (Package.SubKeyCount < 1)
                throw new CryptoProcessingException("PackageFactory:Create", "The key package must contain at least 1 key!", new ArgumentOutOfRangeException());
            if (Package.SubKeyCount > SUBKEY_MAX)
                throw new CryptoProcessingException("PackageFactory:Create", String.Format("The key package can not contain more than {0} keys!", SUBKEY_MAX), new ArgumentOutOfRangeException());

            // get the size of a subkey set
            int subKeySize = Package.Description.KeySize;

            if (Package.Description.IvSize > 0)
                subKeySize += Package.Description.IvSize;
            
            if (Package.Description.MacSize > 0)
                subKeySize += Package.Description.MacSize;

            if (subKeySize < 0)
                throw new CryptoProcessingException("PackageFactory:Create", "The key package cipher settings are invalid!", new Exception());

            try
            {
                // store the auth struct and policy
                _keyOwner = Package.Authority;
                KeyPolicy = Package.KeyPolicy;
                // get the serialized header
                byte[] header = Package.ToBytes();
                // size key buffer
                byte[] buffer = new byte[subKeySize * Package.SubKeyCount];

                // generate the keying material
                using (KeyGenerator keyGen = new KeyGenerator(SeedEngine, DigestEngine))
                    keyGen.GetBytes(buffer);

                BinaryWriter keyWriter = new BinaryWriter(_keyStream);
                // pre-set the size to avoid fragmentation
                keyWriter.BaseStream.SetLength(PackageKey.GetHeaderSize(Package) + (subKeySize * Package.SubKeyCount));

                if (IsEncrypted(Package.KeyPolicy))
                {
                    // add policy flags, only part of key not encrypted
                    keyWriter.Write(Package.KeyPolicy);
                    // get salt, return depends on auth flag settings
                    byte[] salt = GetSalt();
                    // create a buffer for encrypted data
                    int hdrLen = header.Length - PackageKey.GetPolicyOffset();
                    byte[] data = new byte[buffer.Length + hdrLen];
                    // copy header and key material
                    Buffer.BlockCopy(header, PackageKey.GetPolicyOffset(), data, 0, hdrLen);
                    Buffer.BlockCopy(buffer, 0, data, hdrLen, buffer.Length);
                    // encrypt the key and header
                    TransformBuffer(data, salt);
                    // write to file
                    keyWriter.Write(data);
                    // don't wait for gc
                    Array.Clear(salt, 0, salt.Length);
                    Array.Clear(data, 0, data.Length);
                }
                else
                {
                    // write the keypackage header
                    keyWriter.Write(header, 0, header.Length);
                    // write the keying material
                    keyWriter.Write(buffer, 0, buffer.Length);
                }

                // cleanup
                _keyStream.Seek(0, SeekOrigin.Begin);
                Array.Clear(header, 0, header.Length);
                Array.Clear(buffer, 0, buffer.Length);
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Extract a subkey set (KeyParam), a file extension key, and a CipherDescription. 
        /// <para>Used only when calling a Decryption function to get a specific subkey 
        /// The KeyId field corresponds with the KeyId field contained in a MessageHeader structure.</para>
        /// </summary>
        /// 
        /// <param name="KeyId">The KeyId array used to identify a subkey set; set as the KeyId in a MessageHeader structure</param>
        /// <param name="Description">out: The CipherDescription structure; the properties required to create a specific cipher instance</param>
        /// <param name="KeyParam">out: The KeyParams class containing a unique key, initialization vector and HMAC key</param>
        /// <param name="ExtensionKey">out: The random key used to encrypt the message file extension</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the user has insufficient access rights to access this PackageKey, or the PackageKey does not contain the KeyId specified</exception>
        public void Extract(byte[] KeyId, out CipherDescription Description, out KeyParams KeyParam, out byte[] ExtensionKey)
        {
            if (AccessScope.Equals(KeyScope.NoAccess))
                throw new CryptoProcessingException("PackageFactory:Extract", "You do not have permission to access this key!", new UnauthorizedAccessException());

            try
            {
                long keyPos;
                int index;
                // get the key data
                MemoryStream keyStream = GetKeyStream();
                // get the keying materials starting offset within the key file
                keyPos = PackageKey.SubKeyOffset(keyStream, KeyId);

                if (keyPos == -1)
                    throw new CryptoProcessingException("PackageFactory:Extract", "This package does not contain the key file!", new ArgumentException());

                // get the index
                index = PackageKey.IndexFromId(keyStream, KeyId);
                // key flagged SingleUse was used for decryption and is locked out
                if (PackageKey.KeyHasPolicy(_keyPackage.SubKeyPolicy[index], (long)PackageKeyStates.Locked))
                    throw new CryptoProcessingException("PackageFactory:Extract", "SubKey is locked. The subkey has a single use policy and was previously used to decrypt the file.", new Exception());
                // key flagged PostOverwrite was used for decryption and was erased
                if (PackageKey.KeyHasPolicy(_keyPackage.SubKeyPolicy[index], (long)PackageKeyStates.Erased))
                    throw new CryptoProcessingException("PackageFactory:Extract", "SubKey is erased. The subkey has a post erase policy and was previously used to decrypt the file.", new Exception());

                // get the cipher description
                Description = _keyPackage.Description;
                // get the keying material
                KeyParam = GetKeySet(keyStream, _keyPackage.Description, keyPos);
                // encrypts the file extension
                ExtensionKey = _keyPackage.ExtensionKey;

                // test flags for overwrite or single use policies
                if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.PostOverwrite))
                    PackageKey.SubKeySetPolicy(keyStream, index, (long)PackageKeyStates.Erased);
                else if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.SingleUse))
                    PackageKey.SubKeySetPolicy(keyStream, index, (long)PackageKeyStates.Locked);

                // post overwrite flag set, erase the subkey
                if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.PostOverwrite))
                {
                    int keySize = Description.KeySize + Description.IvSize + Description.MacSize;
                    // overwrite the region within file
                    Erase(keyPos, keySize);
                    // clear this section of the key
                    keyStream.Seek(keyPos, SeekOrigin.Begin);
                    keyStream.Write(new byte[keySize], 0, keySize);
                }

                // write to file
                WriteKeyStream(keyStream);
            }
            catch 
            {
                throw;
            }
        }

        /// <summary>
        /// Test the PackageKey for remaining valid subkeys
        /// </summary>
        /// 
        /// <returns>PackageKey contains subkeys that are valid for encryption</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the user has insufficient access rights to access this PackageKey</exception>
        public bool HasExpired()
        {
            if (AccessScope.Equals(KeyScope.NoAccess))
                throw new CryptoProcessingException("PackageFactory:HasExpired", "You do not have permission to access this key!", new UnauthorizedAccessException());

            for (int i = 0; i < _keyPackage.SubKeyCount; i++)
            {
                if (!PackageKey.KeyHasPolicy(_keyPackage.SubKeyPolicy[i], (long)PackageKeyStates.Expired))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Test a PackageKey subkey for expired status
        /// </summary>
        /// 
        /// <param name="KeyId">The subkey id to test</param>
        /// 
        /// <returns>Returns true if subkey has expired and can not be used for encryption, false if a valid key</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the user has insufficient access rights to access this PackageKey</exception>
        public bool HasExpired(byte[] KeyId)
        {
            if (AccessScope.Equals(KeyScope.NoAccess))
                throw new CryptoProcessingException("PackageFactory:HasExpired", "You do not have permission to access this key!", new UnauthorizedAccessException());

            int index = ContainsSubKey(KeyId);
            if (index < 0)
                return true;

            return (PackageKey.KeyHasPolicy(_keyPackage.SubKeyPolicy[index], (int)PackageKeyStates.Expired));
        }

        /// <summary>
        /// Get information about the key file in the form of an <see cref="PackageInfo"/> structure
        /// </summary>
        /// 
        /// <returns>A <see cref="PackageInfo"/> structure</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the user has insufficient access rights to access this PackageKey</exception>
        public PackageInfo KeyInfo()
        {
            if (AccessScope.Equals(KeyScope.NoAccess))
                throw new CryptoProcessingException("PackageFactory:KeyInfo", "You do not have permission to access this key!", new UnauthorizedAccessException());

            PackageInfo info = new PackageInfo(_keyPackage);

            // return limited data
            if (PackageKey.KeyHasPolicy(KeyPolicy, (long)KeyPolicies.NoNarrative))
            {
                info.Origin = Guid.Empty;
                info.Policies.Clear();
            }

            return info;
        }

        /// <summary>
        /// Extract the next valid subkey set (Expired flag not set) as a KeyParam, and a CipherDescription structure. 
        /// <para>Used only when calling a Encryption function.</para>
        /// </summary>
        /// 
        /// <param name="Description">out: The CipherDescription structure; the properties required to create a specific cipher instance</param>
        /// <param name="KeyParam">out: The KeyParams class containing a unique key, initialization vector and HMAC key</param>
        /// <param name="ExtensionKey">out: The random key used to encrypt the message file extension</param>
        /// 
        /// <returns>The KeyId array used to identify a subkey set; set as the KeyId in a MessageHeader structure</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the user has insufficient access rights to perform encryption with this key.</exception>
        public byte[] NextKey(out CipherDescription Description, out KeyParams KeyParam, out byte[] ExtensionKey)
        {
            if (!AccessScope.Equals(KeyScope.Creator))
                throw new CryptoProcessingException("PackageFactory:NextKey", "You do not have permission to encrypt with this key!", new UnauthorizedAccessException());

            try
            {
                // get the key data
                MemoryStream keyStream = GetKeyStream();
                // get the next unused key for encryption
                int index = PackageKey.NextSubkey(keyStream);

                if (index == -1)
                    throw new CryptoProcessingException("PackageFactory:NextKey", "The key file has expired! There are no keys left available for encryption.", new Exception());

                // get the cipher description
                Description = _keyPackage.Description;
                // get the file extension key
                ExtensionKey = _keyPackage.ExtensionKey;
                // store the subkey identity, this is written into the message header to identify the subkey
                byte[] keyId = _keyPackage.SubKeyID[index];
                // get the starting position of the keying material within the package
                long keyPos = PackageKey.SubKeyOffset(keyStream, keyId);

                // no unused keys in the package file
                if (keyPos == -1)
                    throw new CryptoProcessingException("PackageFactory:NextKey", "The key file has expired! There are no keys left available for encryption.", new Exception());

                // get the keying material
                KeyParam = GetKeySet(keyStream, _keyPackage.Description, keyPos);
                // mark the subkey as expired
                PackageKey.SubKeySetPolicy(keyStream, index, (long)PackageKeyStates.Expired);
                // write to file
                WriteKeyStream(keyStream);
                // return the subkey id
                return keyId;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Get the policy flags for a subkey
        /// </summary>
        /// 
        /// <param name="KeyId">Id of the subkey to query</param>
        /// 
        /// <returns>Sub key policy flag, or -1 if not key id found</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the user has insufficient access rights to access this PackageKey</exception>
        public Int64 Policy(byte[] KeyId)
        {
            if (AccessScope.Equals(KeyScope.NoAccess))
                throw new CryptoProcessingException("PackageFactory:Policy", "You do not have permission to access this key!", new UnauthorizedAccessException());

            int index = ContainsSubKey(KeyId);
            if (index < 0)
                return -1;

            if (index > _keyPackage.SubKeyPolicy.Length)
                return -1;

            return _keyPackage.SubKeyPolicy[index];
        }
        #endregion

        #region Private Methods
        /// <remarks>
        /// 4 stage overwrite: random, reverse random, ones, zeros. 
        /// Last overwrite stage is zeros in Extract() method.
        /// </remarks>
        private void Erase(long Offset, long Length)
        {
            byte[] buffer =  new byte[Length];

            // get p-rand buffer
            using (CSPPrng csp = new CSPPrng())
                csp.GetBytes(buffer);

            // rand
            Overwrite(buffer, Offset, Length);
            // reverse rand
            Array.Reverse(buffer);
            Overwrite(buffer, Offset, Length);
            // ones
            for (int i = 0; i < buffer.Length; i++)
                buffer[i] = (byte)255;
            Overwrite(buffer, Offset, Length);
        }

        /// <remarks>
        /// Returns the PackageKey structure
        /// </remarks>
        private PackageKey GetPackage()
        {
            MemoryStream keyStream = GetKeyStream();
            PackageKey package = new PackageKey(keyStream);
            keyStream.Dispose();

            return package;
        }

        /// <remarks>
        /// Returns the populated KeyParams class
        /// </remarks>
        private KeyParams GetKeySet(MemoryStream KeyStream, CipherDescription Description, long Position)
        {
            KeyParams keyParam;
            KeyStream.Seek(Position, SeekOrigin.Begin);

            // create the keyparams class
            if (Description.MacSize > 0 && Description.IvSize > 0)
            {
                byte[] key = new byte[Description.KeySize];
                byte[] iv = new byte[Description.IvSize];
                byte[] ikm = new byte[Description.MacSize];

                KeyStream.Read(key, 0, key.Length);
                KeyStream.Read(iv, 0, iv.Length);
                KeyStream.Read(ikm, 0, ikm.Length);
                keyParam = new KeyParams(key, iv, ikm);
            }
            else if (Description.IvSize > 0)
            {
                byte[] key = new byte[Description.KeySize];
                byte[] iv = new byte[Description.IvSize];

                KeyStream.Read(key, 0, key.Length);
                KeyStream.Read(iv, 0, iv.Length);
                keyParam = new KeyParams(key, iv);
            }
            else if (Description.MacSize > 0)
            {
                byte[] key = new byte[Description.KeySize];
                byte[] ikm = new byte[Description.MacSize];

                KeyStream.Read(key, 0, key.Length);
                KeyStream.Read(ikm, 0, ikm.Length);
                keyParam = new KeyParams(key, null, ikm);
            }
            else
            {
                byte[] key = new byte[Description.KeySize];
                KeyStream.Read(key, 0, key.Length);
                keyParam = new KeyParams(key);
            }

            return keyParam;
        }

        /// <remarks>
        /// Get the working copy of the key package as a stream
        /// </remarks>
        private MemoryStream GetKeyStream()
        {
            MemoryStream keymem = null;

            try
            {
                BinaryReader keyReader = new BinaryReader(_keyStream);
                // output stream and writer
                keymem = new MemoryStream((int)keyReader.BaseStream.Length);
                BinaryWriter keyWriter = new BinaryWriter(keymem);

                // add policy flags
                KeyPolicy = keyReader.ReadInt64();
                keyWriter.Write(KeyPolicy);
                // get the data
                byte[] data = keyReader.ReadBytes((int)(keyReader.BaseStream.Length - PackageKey.GetPolicyOffset()));

                // decrypt
                if (IsEncrypted(KeyPolicy))
                {
                    // get the salt
                    byte[] salt = GetSalt();
                    // decrypt the key
                    TransformBuffer(data, salt);
                    // clear the salt
                    Array.Clear(salt, 0, salt.Length);
                }

                // copy to stream
                keyWriter.Write(data);
                // don't wait for gc
                Array.Clear(data, 0, data.Length);
                // reset position
                keymem.Seek(0, SeekOrigin.Begin);
                _keyStream.Seek(0, SeekOrigin.Begin);

                return keymem;
            }
            catch
            {
                throw;
            }
        }

        /// <remarks>
        /// Get the salt value used to encrypt the key.
        /// Salt is derived from authentication fields in the package header.
        /// </remarks>
        private byte[] GetSalt()
        {
            byte[] salt = null;
            int offset = 0;

            if (HasFlag(KeyPolicy, KeyPolicies.PackageAuth))
            {
                // hash of user passphrase
                salt = new byte[_keyOwner.PackageId.Length];
                Buffer.BlockCopy(_keyOwner.PackageId, 0, salt, 0, salt.Length);
                offset += _keyOwner.PackageId.Length;
            }

            if (HasFlag(KeyPolicy, KeyPolicies.DomainRestrict))
            {
                // hashed domain name or group secret
                if (salt == null)
                    salt = new byte[_keyOwner.DomainId.Length];
                else
                    Array.Resize<byte>(ref salt, offset + _keyOwner.DomainId.Length);

                Buffer.BlockCopy(_keyOwner.DomainId, 0, salt, offset, _keyOwner.DomainId.Length);
                offset += _keyOwner.DomainId.Length;
            }

            if (HasFlag(KeyPolicy, KeyPolicies.IdentityRestrict))
            {
                // add the target id
                if (salt == null)
                    salt = new byte[_keyOwner.TargetId.Length];
                else
                    Array.Resize<byte>(ref salt, offset + _keyOwner.TargetId.Length);

                Buffer.BlockCopy(_keyOwner.DomainId, 0, salt, offset, _keyOwner.TargetId.Length);
            }

            return salt;
        }

        private bool HasFlag(long Flags, KeyPolicies Policy)
        {
            return ((Flags & (long)Policy) == (long)Policy);
        }

        private bool IsEncrypted(long Policies)
        {
            return HasFlag(Policies, KeyPolicies.PackageAuth);
        }

        private bool IsEncrypted(PackageKey Package)
        {
            return HasFlag(Package.KeyPolicy, KeyPolicies.PackageAuth);
        }

        /// <remarks>
        /// Overwrite a section of the key file, used by the PostOverwrite policy
        /// </remarks>
        private void Overwrite(byte[] KeyData, long Offset, long Length)
        {
            _keyStream.Seek(Offset, SeekOrigin.Begin);
            _keyStream.Write(KeyData, 0, KeyData.Length);
        }

        /// <remarks>
        /// Encrypts the key package buffer
        /// </remarks>
        private void TransformBuffer(byte[] KeyData, byte[] Salt)
        {
            byte[] kvm = new byte[48];

            // use salt to derive key and counter vector
            using (Keccak512 digest = new Keccak512(384))
                kvm = digest.ComputeHash(Salt);

            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            Buffer.BlockCopy(kvm, 0, key, 0, key.Length);
            Buffer.BlockCopy(kvm, key.Length, iv, 0, iv.Length);
            byte[] outData = new byte[KeyData.Length];

            using (KeyParams keyparam = new KeyParams(key, iv))
            {
                // 32 rounds of serpent
                using (CTR cipher = new CTR(new SHX()))
                {
                    cipher.Initialize(true, keyparam);
                    cipher.Transform(KeyData, outData);
                }
            }
            Buffer.BlockCopy(outData, 0, KeyData, 0, KeyData.Length);
        }

        /// <remarks>
        /// Writes a memorystream to the key package file
        /// </remarks>
        private void WriteKeyStream(MemoryStream InStream)
        {
            InStream.Seek(0, SeekOrigin.Begin);

            try
            {
                using (BinaryWriter keyWriter = new BinaryWriter(_keyStream))
                {
                    using (BinaryReader keyReader = new BinaryReader(InStream))
                    {
                        // policy flag is not encrypted
                        long policies = keyReader.ReadInt64();
                        keyWriter.Write(policies);
                        // get the header and keying material
                        byte[] data = new byte[InStream.Length - PackageKey.GetPolicyOffset()];
                        InStream.Read(data, 0, data.Length);

                        if (IsEncrypted(policies))
                        {
                            // get the salt
                            byte[] salt = GetSalt();
                            // decrypt the key and header
                            TransformBuffer(data, salt);
                            Array.Clear(salt, 0, salt.Length);
                        }

                        // copy to file
                        keyWriter.Write(data, 0, data.Length);
                        // clean up
                        Array.Clear(data, 0, data.Length);
                    }
                }

                InStream.Dispose();
            }
            catch
            {
                throw;
            }
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
                    if (_keyStream != null)
                    {
                        _keyStream.Close();
                        _keyStream.Dispose();
                        _keyStream = null;
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}