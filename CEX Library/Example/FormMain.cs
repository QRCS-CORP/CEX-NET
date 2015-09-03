#region Directives
using System;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Processing;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Factory;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Projects.CEX.Helper;
#endregion

namespace VTDev.Projects.CEX
{
    public partial class FormMain : Form
    {
        #region Constants
        private const string ALL_FILT = "All Files | *.*";
        private const string CENC_EXT = ".cen";
        private const string CKEY_EXT = ".ckey";
        private const string KEY_DEF = "Key";
        private const string FILE_DEFN = "[Select a File to Encrypt or Decrypt]";
        private const string FILE_DESC = "Select a File to Encrypt or Decrypt";
        private const string FOLD_DEFN = "[Save Key File As]";
        private const string FOLD_DESC = "Choose a Key Name and Path";
        private const string KPTH_DEFN = "[Save Key File As]";
        private const string KPTH_DESC = "Save Key File As";
        private const string KEY_DEFN = "[Select a Key File]";
        private const string KEY_DESC = "Select a Key File";
        private const string KEY_FILT = "Key File | *.ckey";
        private const string KEY_NAME = "Key";
        private const string SAVE_DEFN = "[Save File to Destination]";
        private const string SAVE_DESC = "Save File As";
        #endregion

        #region Fields
        private SettingsContainer _container = new SettingsContainer();
        private string _inputPath = "";
        private bool _isEncryption;
        private bool _isParallel = true;
        private string _keyFilePath;
        private string _lastInputPath = "";
        private string _lastKeyPath = "";
        private string _lastOutputPath = "";
        private int _macSize = 64;
        private string _outputPath = "";
        #endregion

        #region Constructor
        public FormMain()
        {
            InitializeComponent();

            // examples testing key factories and processors
            // adjust paths to your installation

            //FactoryTests.KeyFactoryTest();
            //FactoryTests.PackageFactoryTest();
            //FactoryTests.VolumeFactoryTest();
            //ProcessingTests.CompressionCipherTest(@"C:\Tests\Test", @"C:\Tests\Extract", @"C:\Tests\voltest.cep");
            //ProcessingTests.PacketCipherTest();
            //ProcessingTests.StreamCipherTest();
            //ProcessingTests.StreamDigestTest();
            //ProcessingTests.StreamMacTest();
            //ProcessingTests.VolumeCipherTest(@"C:\Tests\Test");
        }
        #endregion

        #region Identity
        /// <summary>
        /// Create a unique id for this installation
        /// </summary>
        /// 
        /// <returns>Unique machine Id</returns>
        private byte[] IdGenerator()
        {
            byte[] localId = new byte[16];

            // create a unique machine id, in an organization this would be assigned
            using (KeyGenerator gen = new KeyGenerator())
                gen.GetBytes(localId);

            return localId;
        }

        /// <summary>
        /// Compare the local Id field with an OID (Origin ID) from a KeyHeader struct 
        /// </summary>
        /// <param name="LocalId">The application identity</param>
        /// <param name="KeyOID">The OID field from a KeyHeader structure</param>
        /// 
        /// <returns>We are Creator</returns>
        private bool IDCheck(byte[] LocalId, byte[] KeyOID)
        {
            if (LocalId == null || KeyOID == null)
                return false;
            if (LocalId.Length != KeyOID.Length)
                return false;

            for (int i = 0; i < LocalId.Length; i++)
            {
                if (LocalId[i] != KeyOID[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Tests for a valid id format
        /// </summary>
        /// 
        /// <param name="LocalId">The 16 byte id</param>
        /// 
        /// <returns>Is valid</returns>
        private bool IdValid(byte[] LocalId)
        {
            if (LocalId == null)
                return false;
            if (LocalId.Length != 16)
                return false;

            // max 0's
            for (int i = 0, c = 0; i < LocalId.Length; i++)
            {
                if (LocalId[i] == 0)
                    c++;
                if (c > 8)
                    return false;
            }

            return true;
        }
        #endregion

        #region Crypto
        /// <remarks>
        /// This method demonstrates using a PackageFactory to extract a key.
        /// StreamMac to verify with a keyed HMAC, that tests the encrypted file before it is conditionally decrypted. 
        /// If accepted the stream is then decrypted using the StreamCipher class.
        /// </remarks>
        private void Decrypt()
        {
            CipherDescription cipherDesc;
            KeyParams keyParam;
            byte[] extKey;

            try
            {
                using (FileStream inStream = new FileStream(_inputPath, FileMode.Open, FileAccess.Read))
                {
                    byte[] keyId = MessageHeader.GetKeyId(inStream);

                    // get the keyheader and key material from the key file
                    using (PackageFactory keyFactory = new PackageFactory(_keyFilePath, _container.Authority))
                    {
                        if (keyFactory.AccessScope == KeyScope.NoAccess)
                        {
                            MessageBox.Show(keyFactory.LastError);
                            return;
                        }
                        keyFactory.Extract(keyId, out cipherDesc, out keyParam, out extKey);
                    }

                    // offset start position is base header + Mac size
                    int hdrOffset = MessageHeader.GetHeaderSize + cipherDesc.MacSize;

                    // decrypt file extension and create a unique path
                    _outputPath = Utilities.GetUniquePath(_outputPath + MessageHeader.GetExtension(inStream, extKey));

                    // if a signing key, test the mac: (MacSize = 0; not signed)
                    if (cipherDesc.MacSize > 0)
                    {
                        // get the hmac for the encrypted file; this could be made selectable
                        // via the KeyHeaderStruct MacDigest and MacSize members.
                        using (StreamMac mstrm = new StreamMac(new SHA512HMAC(keyParam.IKM)))
                        {
                            // get the message header mac
                            byte[] chksum = MessageHeader.GetMessageMac(inStream, cipherDesc.MacSize);

                            // initialize mac stream
                            inStream.Seek(hdrOffset, SeekOrigin.Begin);
                            mstrm.Initialize(inStream);

                            // get the mac; offset by header length + Mac and specify adjusted length
                            byte[] hash = mstrm.ComputeMac(inStream.Length - hdrOffset, hdrOffset);

                            // compare, notify and abort on failure
                            if (!Compare.AreEqual(chksum, hash))
                            {
                                MessageBox.Show("Message hash does not match! The file has been tampered with.");
                                return;
                            }
                        }
                    }

                    // with this constructor, the StreamCipher class creates the cryptographic 
                    // engine using the description contained in the CipherDescription structure.
                    // The (cipher and) engine are automatically destroyed in the cipherstream dispose
                    using (StreamCipher cstrm = new StreamCipher(false, cipherDesc, keyParam))
                    {
                        using (FileStream outStream = new FileStream(_outputPath, FileMode.Create, FileAccess.Write))
                        {
                            // start at an input offset equal to the message header size
                            inStream.Seek(hdrOffset, SeekOrigin.Begin);
                            // use a percentage counter
                            cstrm.ProgressPercent += new StreamCipher.ProgressDelegate(OnProgressPercent);
                            // initialize internals
                            cstrm.Initialize(inStream, outStream);
                            // write the decrypted output to file
                            cstrm.Write();
                        }
                    }
                }
                // destroy the key
                keyParam.Dispose();
            }
            catch (Exception ex)
            {
                if (File.Exists(_outputPath))
                    File.Delete(_outputPath);

                string message = ex.Message == null ? "" : ex.Message;
                MessageBox.Show("An error occured, the file could not be encrypted! " + message);
            }
            finally
            {
                Invoke(new MethodInvoker(() => { Reset(); }));
            }
        }

        /// <remarks>
        /// This method demonstrates using a PackageFactory and StreamCipher class to
        /// both encrypt a file, and optionally sign the message with an SHA512 HMAC.
        /// See the StreamCipher and StreamMac documentation for more examples.
        /// </remarks>
        private void Encrypt()
        {
            CipherDescription keyHeader;
            KeyParams keyParam;

            try
            {
                byte[] keyId = null;
                byte[] extKey = null;

                // get the keyheader and key material from the key file
                using (PackageFactory keyFactory = new PackageFactory(_keyFilePath, _container.Authority))
                {
                    // get the key info
                    PackageInfo pki = keyFactory.KeyInfo();

                    if (!keyFactory.AccessScope.Equals(KeyScope.Creator))
                    {
                        MessageBox.Show(keyFactory.LastError);
                        return;
                    }
                    keyId = (byte[])keyFactory.NextKey(out keyHeader, out keyParam, out extKey).Clone();
                }
                // offset start position is base header + Mac size
                int hdrOffset = MessageHeader.GetHeaderSize + keyHeader.MacSize;

                // with this constructor, the StreamCipher class creates the cryptographic
                // engine using the description in the CipherDescription.
                // The (cipher and) engine are destroyed in the cipherstream dispose
                using (StreamCipher cstrm = new StreamCipher(true, keyHeader, keyParam))
                {
                    using (FileStream inStream = new FileStream(_inputPath, FileMode.Open, FileAccess.Read))
                    {
                        using (FileStream outStream = new FileStream(_outputPath, FileMode.Create, FileAccess.ReadWrite))
                        {
                            // start at an output offset equal to the message header + MAC length
                            outStream.Seek(hdrOffset, SeekOrigin.Begin);
                            // use a percentage counter
                            cstrm.ProgressPercent += new StreamCipher.ProgressDelegate(OnProgressPercent);
                            // initialize internals
                            cstrm.Initialize(inStream, outStream);
                            // write the encrypted output to file
                            cstrm.Write();

                            // write the key id to the header
                            MessageHeader.SetKeyId(outStream, keyId);
                            // write the encrypted file extension
                            MessageHeader.SetExtension(outStream, MessageHeader.GetEncryptedExtension(Path.GetExtension(_inputPath), extKey));

                            // if this is a signing key, calculate the mac 
                            if (keyHeader.MacSize > 0)
                            {
                                // Get the mac for the encrypted file; Mac engine is SHA512 by default, 
                                // configurable via the CipherDescription MacSize and MacEngine members.
                                // This is where you would select and initialize the correct Digest via the
                                // CipherDescription members, and initialize the corresponding digest. 
                                // For expedience, this example is fixed on the default SHA512.
                                // An optional progress event is available in the StreamMac class.
                                using (StreamMac mstrm = new StreamMac(new SHA512HMAC(keyParam.IKM)))
                                {
                                    // seek to end of header
                                    outStream.Seek(hdrOffset, SeekOrigin.Begin);
                                    // initialize mac stream
                                    mstrm.Initialize(outStream);
                                    // get the hash; specify offset and adjusted size
                                    byte[] hash = mstrm.ComputeMac(outStream.Length - hdrOffset, hdrOffset);
                                    // write the keyed hash value to the message header
                                    MessageHeader.SetMessageMac(outStream, hash);
                                }
                            }
                        }
                    }
                }
                // destroy the key
                keyParam.Dispose();
            }
            catch (Exception ex)
            {
                if (File.Exists(_outputPath))
                    File.Delete(_outputPath);

                string message = ex.Message == null ? "" : ex.Message;
                MessageBox.Show("An error occured, the file could not be encrypted! " + message);
            }
            finally
            {
                Invoke(new MethodInvoker(() => { Reset(); }));
            }
        }

        /// <summary>
        /// Demonstrates saving a key file using the PackageFactory class
        /// </summary>
        private void SaveKey()
        {
            try
            {
                // add the time/date expiration stamp if key policy is volatile
                if (HasPolicy(KeyPolicies.Volatile))
                {
                    if (dtVolatileTime.Value.Ticks > DateTime.Now.Ticks)
                        _container.Authority.OptionFlag = dtVolatileTime.Value.Ticks;
                    else
                        throw new Exception("Invalid Expiry time. If a key is marked as Volatile, the expired time must be greater than the current time.");
                }

                // get the key tag description
                if (!string.IsNullOrEmpty(txtKeyDescription.Text))
                {
                    byte[] data = new byte[32];
                    byte[] tag = Encoding.ASCII.GetBytes(txtKeyDescription.Text);
                    Array.Copy(tag, data, tag.Length < 32 ? tag.Length : 32);
                    _container.Authority.PackageTag = data;
                }

                // get the number of subkeys to create in this package
                int keyCount = 1;
                if (!string.IsNullOrEmpty(txtSubKeyCount.Text) && txtSubKeyCount.Text != "0")
                    int.TryParse(txtSubKeyCount.Text, out keyCount);

                // create a PackageKey; a key package can contain 1 or many thousands of 'subkeys'. Each subkey set
                // contains one group of unique random keying material; key, iv, and optional hmac key. 
                // Each key set is used only once for encryption, guaranteeing that a unique set of values is used for every encryption cycle.
                PackageKey package = new PackageKey(
                    _container.Authority,           // the KeyAuthority structure
                    _container.Description,         // the CipherDescription structure
                    keyCount,                       // the number of subkeys to add to this key package
                    IdGenerator());                 // the file extension encryption key

                // create and write the key
                using (PackageFactory factory = new PackageFactory(_keyFilePath, _container.Authority))
                    factory.Create(package);

                // store path
                _lastKeyPath = Path.GetDirectoryName(_keyFilePath);

                Reset();
                lblStatus.Text = "The Key has been saved!";
            }
            catch (Exception ex)
            {
                if (File.Exists(_keyFilePath))
                    File.Delete(_keyFilePath);

                string message = ex.Message == null ? "" : ex.Message;
                MessageBox.Show("An error occured, the key could not be created! " + message);
            }
        }

        /// <summary>
        /// Compares keys between a message file and a key file
        /// </summary>
        private bool IsMatchingKey(string MessagePath, string KeyPath)
        {
            bool isEqual = false;

            if (File.Exists(MessagePath) && File.Exists(KeyPath))
            {
                using (FileStream msgFile = new FileStream(MessagePath, FileMode.Open, FileAccess.Read))
                {
                    byte[] messageId = MessageHeader.GetKeyId(msgFile);

                    using (PackageFactory factory = new PackageFactory(KeyPath, _container.Authority))
                        isEqual = factory.ContainsSubKey(messageId) > -1;
                }
            }

            return isEqual;
        }
        #endregion

        #region Helpers
        private void IsEnabled(bool State)
        {
            pnlKey.Enabled = State;
            pnlEncrypt.Enabled = State;
            tsMain.Enabled = State;
        }

        private string GetFileOpenPath(string Description, string FileFilter = ALL_FILT, string DefaultDirectory = "")
        {
            using (OpenFileDialog openDialog = new OpenFileDialog() {
                AutoUpgradeEnabled = false,
                CheckFileExists = true,
                Filter = FileFilter,
                RestoreDirectory = true,
                Title = Description })
            {
                if (!string.IsNullOrEmpty(DefaultDirectory))
                    openDialog.InitialDirectory = DefaultDirectory;
                if (openDialog.ShowDialog() == DialogResult.OK)
                    return openDialog.FileName;
            }

            return string.Empty;
        }

        private string GetFileSavePath(string Description, string Filter = ALL_FILT, string FilePath = "", string DefaultDirectory = "")
        {
            using (SaveFileDialog saveDialog = new SaveFileDialog() { 
                AddExtension = true,
                AutoUpgradeEnabled = false,
                CheckPathExists = true,
                Filter = Filter,
                FileName = FilePath,
                OverwritePrompt = true,
                Title = Description,
                RestoreDirectory = true })
            {
                if (!string.IsNullOrEmpty(DefaultDirectory))
                    saveDialog.InitialDirectory = DefaultDirectory;
                if (saveDialog.ShowDialog() == DialogResult.OK)
                    return saveDialog.FileName;
            }

            return string.Empty;
        }

        private void LoadComboParams()
        {
            ComboHelper.LoadEnumValues(cbEngines, typeof(SymmetricEngines));
            ComboHelper.LoadEnumValues(cbCipherMode, typeof(CipherModes));
            ComboHelper.LoadEnumValues(cbPaddingMode, typeof(PaddingModes));
            ComboHelper.LoadEnumValues(cbHkdf, typeof(Digests));
            ComboHelper.LoadEnumValues(cbHmac, typeof(Digests));

            cbVectorSize.SelectedIndex = 0;
            cbCipherMode.SelectedIndex = 3;
            cbPaddingMode.SelectedIndex = 3;
            cbHkdf.SelectedIndex = 4;
            cbHmac.SelectedIndex = 2;
        }

        private void Reset()
        {
            dtVolatileTime.Value = DateTime.Now.AddDays(1);
            tsMain.Enabled = true;
            btnEncrypt.Enabled = false;
            btnKeyFile.Enabled = false;
            btnOutputFile.Enabled = false;
            pnlKey.Enabled = true;
            pnlEncrypt.Enabled = true;
            lblStatus.Text = "Waiting..";
            txtInputFile.Text = FILE_DEFN;
            txtKeyFile.Text = KEY_DEFN;
            txtOutputFile.Text = SAVE_DEFN;
            _inputPath = string.Empty;
            _keyFilePath = string.Empty;
            _outputPath = string.Empty;
            pbStatus.Value = 0;
        }

        private void SetKeySizes(SymmetricEngines CipherEngine, Digests KdfEngine)
        {
            cbKeySize.Items.Clear();

            if (CipherEngine == SymmetricEngines.Fusion ||
                CipherEngine == SymmetricEngines.RHX ||
                CipherEngine == SymmetricEngines.RSM ||
                CipherEngine == SymmetricEngines.SHX ||
                CipherEngine == SymmetricEngines.TSM ||
                CipherEngine == SymmetricEngines.THX)
            {
                cbHkdf.Enabled = true;

                switch (KdfEngine)
                {
                    case Digests.Blake256:
                    case Digests.Skein256:
                        cbKeySize.Items.Add(KeySizes.K512);
                        cbKeySize.Items.Add(KeySizes.K768);
                        cbKeySize.Items.Add(KeySizes.K1024);
                        cbKeySize.Items.Add(KeySizes.K1280);
                        break;
                    case Digests.SHA256:
                        cbKeySize.Items.Add(KeySizes.K768);
                        cbKeySize.Items.Add(KeySizes.K1280);
                        cbKeySize.Items.Add(KeySizes.K1792);
                        cbKeySize.Items.Add(KeySizes.K2304);
                        break;
                    case Digests.Blake512:
                    case Digests.Skein512:
                        cbKeySize.Items.Add(KeySizes.K1024);
                        cbKeySize.Items.Add(KeySizes.K1536);
                        cbKeySize.Items.Add(KeySizes.K2048);
                        cbKeySize.Items.Add(KeySizes.K2560);
                        break;
                    case Digests.Keccak512:
                        cbKeySize.Items.Add(KeySizes.K1088);
                        cbKeySize.Items.Add(KeySizes.K1664);
                        cbKeySize.Items.Add(KeySizes.K2240);
                        cbKeySize.Items.Add(KeySizes.K2816);
                        break;
                    case Digests.SHA512:
                        cbKeySize.Items.Add(KeySizes.K1536);
                        cbKeySize.Items.Add(KeySizes.K2560);
                        cbKeySize.Items.Add(KeySizes.K3584);
                        cbKeySize.Items.Add(KeySizes.K4608);
                        break;
                    case Digests.Skein1024:
                        cbKeySize.Items.Add(KeySizes.K2048);
                        cbKeySize.Items.Add(KeySizes.K3072);
                        cbKeySize.Items.Add(KeySizes.K4096);
                        cbKeySize.Items.Add(KeySizes.K5120);
                        break;
                }
            }
            else if (CipherEngine == SymmetricEngines.RDX ||
                CipherEngine == SymmetricEngines.SPX ||
                CipherEngine == SymmetricEngines.TFX)
            {
                cbHkdf.Enabled = false;
                cbKeySize.Items.Add(KeySizes.K128);
                cbKeySize.Items.Add(KeySizes.K256);
                cbKeySize.Items.Add(KeySizes.K512);
            }
            else if (CipherEngine == SymmetricEngines.ChaCha ||
                CipherEngine == SymmetricEngines.Salsa)
            {
                cbHkdf.Enabled = false;
                cbKeySize.Items.Add(KeySizes.K128);
                cbKeySize.Items.Add(KeySizes.K256);
                cbKeySize.Items.Add(KeySizes.K384);
                cbKeySize.Items.Add(KeySizes.K448);
            }

            ComboHelper.SetSelectedIndex(cbKeySize, 1);
        }

        private void SetComboParams(SymmetricEngines Engine)
        {
            cbCipherMode.Enabled = true;
            cbPaddingMode.Enabled = true;
            cbRounds.Enabled = true;
            cbVectorSize.Enabled = true;
            cbRounds.Items.Clear();
            cbVectorSize.Items.Clear();
            cbVectorSize.Items.Add(IVSizes.V128);
            cbVectorSize.SelectedIndex = 0;

            switch (Engine)
            {
                case SymmetricEngines.ChaCha:
                case SymmetricEngines.Salsa:
                    cbCipherMode.Enabled = false;
                    cbPaddingMode.Enabled = false;
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 8, 30);
                    ComboHelper.SetSelectedIndex(cbRounds, 6);
                    cbVectorSize.Items.Clear();
                    cbVectorSize.Items.Add(IVSizes.V64);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case SymmetricEngines.Fusion:
                    cbCipherMode.Enabled = false;
                    cbPaddingMode.Enabled = false;
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case SymmetricEngines.RDX:
                    cbRounds.Enabled = false;
                    cbVectorSize.Items.Add(IVSizes.V256);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case SymmetricEngines.RHX:
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 10, 38);
                    ComboHelper.SetSelectedIndex(cbRounds, 2);
                    cbVectorSize.Items.Add(IVSizes.V256);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case SymmetricEngines.RSM:
                    cbRounds.Items.Add(RoundCounts.R10);
                    cbRounds.Items.Add(RoundCounts.R18);
                    cbRounds.Items.Add(RoundCounts.R26);
                    cbRounds.Items.Add(RoundCounts.R34);
                    cbRounds.Items.Add(RoundCounts.R42);
                    ComboHelper.SetSelectedIndex(cbRounds, 1);
                    cbVectorSize.Items.Add(IVSizes.V256);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case SymmetricEngines.SHX:
                    cbRounds.Items.Add(RoundCounts.R32);
                    cbRounds.Items.Add(RoundCounts.R40);
                    cbRounds.Items.Add(RoundCounts.R48);
                    cbRounds.Items.Add(RoundCounts.R56);
                    cbRounds.Items.Add(RoundCounts.R64);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case SymmetricEngines.SPX:
                    cbRounds.Items.Add(RoundCounts.R32);
                    cbRounds.Items.Add(RoundCounts.R40);
                    cbRounds.Items.Add(RoundCounts.R48);
                    cbRounds.Items.Add(RoundCounts.R56);
                    cbRounds.Items.Add(RoundCounts.R64);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case SymmetricEngines.TFX:
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case SymmetricEngines.TSM:
                    cbRounds.Items.Add(RoundCounts.R16);
                    cbRounds.Items.Add(RoundCounts.R24);
                    cbRounds.Items.Add(RoundCounts.R32);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                default:
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
            }
        }
        #endregion

        #region Event Handlers
        #region Controls
        private void OnCipherModeChanged(object sender, EventArgs e)
        {
            CipherModes cmode = CipherModes.CTR;
            Enum.TryParse<CipherModes>(((ComboBox)sender).Text, out cmode);
            _container.Description.CipherType = (int)cmode;
        }

        private void OnEngineChanged(object sender, EventArgs e)
        {
            SymmetricEngines engine = SymmetricEngines.RHX;
            Enum.TryParse<SymmetricEngines>(((ComboBox)sender).Text, out engine);
            _container.Description.EngineType = (int)engine;

            Digests digest = Digests.SHA512;
            if (cbHkdf.Items.Count > 0)
                digest = (Digests)cbHkdf.SelectedItem;

            SetKeySizes(engine, digest);
            SetComboParams(engine);
        }

        private void OnHkdfChanged(object sender, EventArgs e)
        {
            Digests digest = Digests.SHA512;
            Enum.TryParse<Digests>(((ComboBox)sender).Text, out digest);
            SetKeySizes((SymmetricEngines)cbEngines.SelectedItem, digest);
            _container.Description.KdfEngine = (int)digest;
        }

        private void OnHmacChanged(object sender, EventArgs e)
        {
            Digests digest = Digests.Keccak512;
            Enum.TryParse<Digests>(((ComboBox)sender).Text, out digest);
            _container.Description.MacEngine = (int)digest;

            switch (digest)
            {
                case Digests.Blake256:
                case Digests.SHA256:
                case Digests.Skein256:
                    _macSize = 32;
                    break;
                case Digests.Blake512:
                case Digests.SHA512:
                case Digests.Skein512:
                case Digests.Keccak512:
                    _macSize = 64;
                    break;
                case Digests.Skein1024:
                    _macSize = 128;
                    break;
            }
        }

        private void OnInfoButtonClick(object sender, EventArgs e)
        {
            using (PackageFactory keyFactory = new PackageFactory(_keyFilePath, _container.Authority))
            {
                using (FormInfo frmInfo = new FormInfo())
                {
                    frmInfo.SetInfo(keyFactory.KeyInfo());
                    frmInfo.ShowDialog(this);
                }
            }
        }
        
        private void OnModifyPoliciesClick(object sender, EventArgs e)
        {
            TogglePanel("tsbOptions");
        }

        private void OnKeyPolicyChanged(object sender, EventArgs e)
        {
            CheckBox chk = sender as CheckBox;
            KeyPolicies flag = KeyPolicies.None;

            if (chk.Name.Equals("chkSign"))
            {
                // mac size set to 0 means no signing
                if (!chk.Checked)
                    _container.Description.MacSize = 0;
                else
                    _container.Description.MacSize = _macSize;
            }
            else if (chk.Name.Equals("chkDomainRestrict"))
                flag = KeyPolicies.DomainRestrict;
            else if (chk.Name.Equals("chkVolatile"))
                flag = KeyPolicies.Volatile;
            else if (chk.Name.Equals("chkSingleUse"))
                flag = KeyPolicies.SingleUse;
            else if (chk.Name.Equals("chkPostOverwrite"))
                flag = KeyPolicies.PostOverwrite;
            else if (chk.Name.Equals("chkPackageAuth"))
                flag = KeyPolicies.PackageAuth;
            else if (chk.Name.Equals("chkNoNarrative"))
                flag = KeyPolicies.NoNarrative;
            else if (chk.Name.Equals("chkNoExport"))
                flag = KeyPolicies.NoExport;

            if (flag != KeyPolicies.None)
            {
                if (chk.Checked)
                    SetPolicy(flag);
                else
                    ClearPolicy(flag);
            }
        }

        private void OnKeySizeChanged(object sender, EventArgs e)
        {
            KeySizes ksize = KeySizes.K256;
            Enum.TryParse<KeySizes>(((ComboBox)sender).Text, out ksize);
            _container.Description.KeySize = (int)ksize;
        }

        private void OnPaddingModeChanged(object sender, EventArgs e)
        {
            PaddingModes padding = PaddingModes.PKCS7;
            Enum.TryParse<PaddingModes>(((ComboBox)sender).Text, out padding);
            _container.Description.PaddingType = (int)padding;
        }

        private void OnProgressPercent(object sender, ProgressChangedEventArgs e)
        {
            if (pbStatus.InvokeRequired)
                pbStatus.Invoke(new MethodInvoker(delegate { pbStatus.Value = (int)e.ProgressPercentage; }));
        }

        private void OnRoundsChanged(object sender, EventArgs e)
        {
            RoundCounts rcount = RoundCounts.R10;
            Enum.TryParse<RoundCounts>(((ComboBox)sender).Text, out rcount);
            _container.Description.RoundCount = (int)rcount;
        }

        private void OnSubKeyCountKeyPress(object sender, KeyPressEventArgs e)
        {
            e.Handled = (!char.IsDigit(e.KeyChar) /*&& !char.IsControl(e.KeyChar)*/);
        }

        private void OnSubKeyCountTextChanged(object sender, EventArgs e)
        {
            TextBox txt = sender as TextBox;
            if (txt.Text.Length == 1 && txt.Text == "0")
                txt.Text = "1";
        }

        private void OnVectorSizeChanged(object sender, EventArgs e)
        {
            IVSizes ivsize = IVSizes.V128;
            Enum.TryParse<IVSizes>(((ComboBox)sender).Text, out ivsize);
            _container.Description.IvSize = (int)ivsize;

            if (_container.Description.EngineType == (int)SymmetricEngines.ChaCha || _container.Description.EngineType == (int)SymmetricEngines.Salsa)
                _container.Description.BlockSize = (int)BlockSizes.B1024;
            else
                _container.Description.BlockSize = (int)ivsize;
        }
        #endregion

        #region Processing
        private void OnCreateKeyClick(object sender, EventArgs e)
        {
            Reset();

            string filePath = GetFileSavePath(KPTH_DESC, KEY_FILT, KEY_DEF, _lastKeyPath);
            if (string.IsNullOrEmpty(filePath)) return;

            if (!Utilities.DirectoryIsWritable(Path.GetDirectoryName(filePath)))
            {
                MessageBox.Show("You do not have permission to create files in this directory! Choose a different path..");
                _keyFilePath = string.Empty;
            }
            else
            {
                _keyFilePath = Utilities.GetUniquePath(filePath);
                SaveKey();
            }
        }

        private void OnEncryptFileClick(object sender, EventArgs e)
        {
            lblStatus.Text = "Processing..";
            IsEnabled(false);

            Task cipherTask;
            if (_isEncryption)
            {
                cipherTask = Task.Factory.StartNew(() =>
                {
                    Encrypt();
                });
            }
            else
            {
                cipherTask = Task.Factory.StartNew(() =>
                {
                    Decrypt();
                });
            }
        }

        private void OnGenerateHashClick(object sender, EventArgs e)
        {
            if (ShowAuthDialog())
            {
                chkPackageAuth.Enabled = true;
                chkPackageAuth.Checked = true;
            }
        }

        private void OnLinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            LinkLabel lnk = sender as LinkLabel;

            if (lnk.Name == "lnkHome")
                OpenInBrowser(@"http://www.vtdev.com/cexhome.html");
            else if (lnk.Name == "lnkDocumentation")
                OpenInBrowser(@"http://www.vtdev.com/CEX/Help/index.html");
            else if (lnk.Name == "lnkGithub")
                OpenInBrowser(@"https://github.com/Steppenwolfe65/CEX");
            else
                OpenInBrowser(@"http://www.vtdev.com/");
        }

        private void OnSelectInputClick(object sender, EventArgs e)
        {
            Reset();

            string inputFile = GetFileOpenPath(FILE_DESC, ALL_FILT, _lastInputPath);

            if (!string.IsNullOrEmpty(inputFile) && File.Exists(inputFile))
            {
                _inputPath = inputFile;
                txtInputFile.Text = _inputPath;
                btnOutputFile.Enabled = true;

                if (!string.IsNullOrEmpty(_inputPath))
                    _lastInputPath = Path.GetDirectoryName(_inputPath);

                if (_inputPath.Contains(CENC_EXT))
                {
                    btnEncrypt.Text = "Decrypt";
                    _isEncryption = false;
                }
                else
                {
                    btnEncrypt.Text = "Encrypt";
                    _isEncryption = true;
                }

                string folderPath = Path.GetDirectoryName(inputFile);

                if (Utilities.DirectoryIsWritable(folderPath))
                {
                    if (_isEncryption)
                    {
                        string extension = Path.GetExtension(inputFile);
                        string fileName = Path.GetFileNameWithoutExtension(inputFile);
                        _outputPath = Utilities.GetUniquePath(folderPath, fileName, CENC_EXT);
                    }
                    else
                    {
                        _outputPath = Path.Combine(Path.GetDirectoryName(inputFile), Path.GetFileNameWithoutExtension(inputFile));
                    }

                    txtOutputFile.Text = _outputPath;
                    btnKeyFile.Enabled = true;
                }
            }
            else
            {
                btnOutputFile.Enabled = false;
                btnKeyFile.Enabled = false;
            }
        }

        private void OnSelectKeyClick(object sender, EventArgs e)
        {
            string keyFile = GetFileOpenPath(KEY_DESC, KEY_FILT, _lastKeyPath);
            if (string.IsNullOrEmpty(keyFile)) 
                return;

            // get the key policy flag
            long policies = 0;
            using (FileStream keyStream = new FileStream(keyFile, FileMode.Open, FileAccess.Read))
                policies = PackageKey.GetKeyPolicy(keyStream);

            // test if key requires authentication
            if ((policies & (long)KeyPolicies.PackageAuth) == (long)KeyPolicies.PackageAuth)
            {
                // ask for passphrase
                if (ShowAuthDialog())
                {
                    using (PackageFactory keyFactory = new PackageFactory(keyFile, _container.Authority))
                    {
                        if (keyFactory.AccessScope == KeyScope.NoAccess)
                        {
                            Array.Clear(_container.Authority.PackageId, 0, _container.Authority.PackageId.Length);
                            MessageBox.Show("Passphrase does not match! This key requires authentication.");
                            txtKeyFile.Text = KEY_DEFN;
                            btnEncrypt.Enabled = false;
                            return;
                        }
                    }
                }
                else
                {
                    MessageBox.Show("Access denied! This key requires authentication.");
                    txtKeyFile.Text = KEY_DEFN;
                    btnEncrypt.Enabled = false;
                    return;
                }
            }

            if (!_isEncryption)
            {
                if (IsMatchingKey(_inputPath, keyFile))
                {
                    _keyFilePath = keyFile;
                    txtKeyFile.Text = keyFile;
                    btnEncrypt.Enabled = true;
                    btnInfo.Enabled = true;
                }
                else
                {
                    _keyFilePath = string.Empty;
                    txtKeyFile.Text = KEY_DEFN;
                    btnEncrypt.Enabled = false;
                    MessageBox.Show("Key does not match the message! Choose a different key..");
                }
            }
            else
            {
                _keyFilePath = keyFile;
                txtKeyFile.Text = _keyFilePath;
                btnEncrypt.Enabled = true;
                btnInfo.Enabled = true;
            }

            if (!string.IsNullOrEmpty(_keyFilePath))
                _lastKeyPath = Path.GetDirectoryName(_keyFilePath);
        }

        private void OnSelectOutputClick(object sender, EventArgs e)
        {
            string filePath = GetFileSavePath(SAVE_DESC, ALL_FILT, "", _lastOutputPath);
            if (string.IsNullOrEmpty(filePath)) return;

            if (!Utilities.DirectoryIsWritable(Path.GetDirectoryName(filePath)))
            {
                MessageBox.Show("You do not have permission to create files in this directory! Choose a different path..");
                txtOutputFile.Text = SAVE_DEFN;
                _outputPath = string.Empty;
                btnKeyFile.Enabled = false;
            }
            else
            {
                _outputPath = Utilities.GetUniquePath(filePath);
                if (!string.IsNullOrEmpty(_outputPath))
                    _lastOutputPath = Path.GetDirectoryName(_outputPath);
                txtOutputFile.Text = _outputPath;
                btnKeyFile.Enabled = true;
            }
        }

        private void OnToolButtonClick(object sender, EventArgs e)
        {
            ToolStripButton tsb = sender as ToolStripButton;
            TogglePanel(tsb.Name);
            this.Invalidate(true);
        }
        #endregion

        #region Form and Menu
        private void OnFormClose(object sender, FormClosingEventArgs e)
        {
            SaveSettings();
        }

        private void OnFormLoad(object sender, EventArgs e)
        {
            _isParallel = Environment.ProcessorCount > 1;
            Reset();
            LoadComboParams();
            SetComboParams(SymmetricEngines.RHX);
            LoadSettings();
        }
        #endregion
        #endregion

        #region Settings
        private void LoadDefaults()
        {
            byte[] origin = _container.Authority.OriginId;
            if (!IdValid(origin))
                origin = Utilities.GetOriginId();

            _container = new SettingsContainer()
            {
                Authority = new KeyAuthority(Utilities.GetDomainId(), origin, new byte[0], new byte[0], KeyPolicies.None),
                Description = new CipherDescription(SymmetricEngines.RHX, (int)KeySizes.K2560, IVSizes.V128, CipherModes.CTR, PaddingModes.X923, BlockSizes.B128, RoundCounts.R22),
                DomainRestrictChecked = false,
                NoNarrativeChecked = false,
                PackageAuthChecked = false,
                PostOverwriteChecked = false,
                SignChecked = false,
                SingleUseChecked = false,
                VolatileChecked = false
            };
        }

        private void LoadSettings()
        {
            if (string.IsNullOrEmpty(Properties.Settings.Default.AppSettings))
            {
                // first run
                LoadDefaults();
                return;
            }
            else
            {
                try
                {
                    // get the encrypted _container string and convert to byte array
                    byte[] appData = Convert.FromBase64String(Properties.Settings.Default.AppSettings);
                    // decrypt the array with DAPI, requires same user context
                    appData = DataProtect.DecryptProtectedData(appData, Utilities.GetCredentials());
                    // deserialize the settings container
                    _container = SettingsContainer.DeSerialize(new MemoryStream(appData));
                    _container.Authority.OptionFlag = 0;
                    _container.Authority.KeyPolicy = 0;
                    // apply the container values to controls
                    cbEngines.SelectedIndex = _container.Description.EngineType;
                    SetComboParams((SymmetricEngines)_container.Description.EngineType);
                    SetKeySizes((SymmetricEngines)_container.Description.EngineType, (Digests)_container.Description.KdfEngine);
                    cbCipherMode.SelectedIndex = _container.Description.CipherType;
                    cbHkdf.SelectedIndex = _container.Description.KdfEngine;
                    cbHmac.SelectedIndex = _container.Description.MacEngine;
                    cbKeySize.SelectedIndex = ComboHelper.IndexFromValue(_container.Description.KeySize, typeof(KeySizes), cbKeySize);
                    cbPaddingMode.SelectedIndex = _container.Description.PaddingType;
                    cbRounds.SelectedIndex = ComboHelper.IndexFromValue(_container.Description.RoundCount, typeof(RoundCounts), cbRounds);
                    cbVectorSize.SelectedIndex = ComboHelper.IndexFromValue(_container.Description.IvSize, typeof(IVSizes), cbVectorSize);
                    chkDomainRestrict.Checked = _container.DomainRestrictChecked;
                    chkNoExport.Checked = _container.NoExportChecked;
                    chkNoNarrative.Checked = _container.NoNarrativeChecked;
                    chkPackageAuth.Checked = _container.PackageAuthChecked;
                    chkPostOverwrite.Checked = _container.PostOverwriteChecked;
                    chkSign.Checked = _container.SignChecked;
                    chkSingleUse.Checked = _container.SingleUseChecked;
                    chkVolatile.Checked = _container.VolatileChecked;
                    _container.Authority.DomainId = Utilities.GetDomainId();
                }
                catch
                {
                    LoadDefaults();
                }
            }
        }

        private void SaveSettings()
        {
            try
            {
                Array.Clear(_container.Authority.DomainId, 0, _container.Authority.DomainId.Length);
                Array.Clear(_container.Authority.PackageId, 0, _container.Authority.PackageId.Length);
                Array.Clear(_container.Authority.PackageTag, 0, _container.Authority.PackageTag.Length);
                
                _container.DomainRestrictChecked = chkDomainRestrict.Checked;
                _container.NoExportChecked = chkNoExport.Checked;
                _container.NoNarrativeChecked = chkNoNarrative.Checked;
                _container.PackageAuthChecked = false;
                _container.PostOverwriteChecked = chkPostOverwrite.Checked;
                _container.SignChecked = chkSign.Checked;
                _container.SingleUseChecked = chkSingleUse.Checked;
                _container.VolatileChecked = chkVolatile.Checked;
                
                // get the settings container as a byte array
                byte[] appData = SettingsContainer.Serialize(_container).ToArray();
                // encrypt with dapi and copy to settings
                Properties.Settings.Default.AppSettings = Convert.ToBase64String(DataProtect.EncryptProtectedData(appData, Utilities.GetCredentials()));
            }
            finally
            {
                Properties.Settings.Default.Save();
            }
        }
        #endregion

        #region Helpers
        private void ClearPolicy(KeyPolicies KeyPolicy)
        {
            if (HasPolicy(KeyPolicy))
                _container.Authority.KeyPolicy &= ~(long)KeyPolicy;
        }

        private bool HasPolicy(KeyPolicies KeyPolicy)
        {
            return ((_container.Authority.KeyPolicy & (long)KeyPolicy) == (long)KeyPolicy);
        }

        private void OpenInBrowser(string Page)
        {
            try { System.Diagnostics.Process.Start(Page); }
            catch { }
        }

        private void SetPolicy(KeyPolicies KeyPolicy)
        {
            if (!HasPolicy(KeyPolicy))
                _container.Authority.KeyPolicy |= (long)KeyPolicy;
        }

        private bool ShowAuthDialog()
        {
            bool valid = false;
            FormGenerate frm = new FormGenerate();
            frm.ShowDialog(this);

            if (frm.Passphrase != null)
            {
                _container.Authority.PackageId = (byte[])frm.Passphrase.Clone();
                valid = true;
            }
            frm.Destroy();

            return valid;
        }

        private void TogglePanel(string PanelName)
        {
            pbStatus.Visible = false;
            lblStatus.Visible = false;

            if (PanelName.Equals("tsbKey"))
            {
                pnlKey.Visible = true;
                pnlEncrypt.Visible = false;
                pnlOptions.Visible = false;
                pnlAbout.Visible = false;
                lblStatus.Visible = true;
                this.Text = "CEX - Create a New Key Package";
            }
            else if (PanelName.Equals("tsbEncrypt"))
            {
                pnlEncrypt.Visible = true;
                pnlKey.Visible = false;
                pnlOptions.Visible = false;
                pnlAbout.Visible = false;
                pbStatus.Visible = true;
                lblStatus.Visible = true;
                this.Text = "CEX - Encrypt or Decrypt a File";
            }
            else if (PanelName.Equals("tsbAbout"))
            {
                pnlEncrypt.Visible = false;
                pnlKey.Visible = false;
                pnlOptions.Visible = false;
                pnlAbout.Visible = true;
                pbStatus.Visible = false;
                lblStatus.Visible = false;
                this.Text = "CEX - Help and Project Links";
            }
            else
            {
                pnlEncrypt.Visible = false;
                pnlKey.Visible = false;
                pnlOptions.Visible = true;
                pnlAbout.Visible = false;
                lblStatus.Visible = false;
                this.Text = "CEX - Set the Key Package Attributes";
            }
        }

        #endregion

        #region Saved
        /// <summary>
        /// Use this method to test speeds on.. anything and everything
        /// </summary>
        private string SpeedTest(Action Test, int Iterations = 1)
        {
            // output results to a label to test compiled times..
            string ft = @"m\:ss\.ff";
            System.Diagnostics.Stopwatch runTimer = new System.Diagnostics.Stopwatch();

            runTimer.Start();

            for (int i = 0; i < Iterations; i++)
                Test();

            runTimer.Stop();

            return TimeSpan.FromMilliseconds(runTimer.Elapsed.TotalMilliseconds).ToString(ft);
        }
        #endregion
    }
}
