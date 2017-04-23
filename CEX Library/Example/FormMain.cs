#region Directives
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Processing;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Factory;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
using VTDev.Libraries.CEXEngine.Crypto.Seed;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Projects.CEX.Helper;
#endregion

// v1.5.6, May. 27, 2016
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
        private string _outputPath = "";
        #endregion

        #region Constructor
        public FormMain()
        {
            InitializeComponent();
        }
        #endregion

        #region Identity
        /// <summary>
        /// Create a block of random
        /// </summary>
        /// 
        /// <returns>pseudo random array</returns>
        private byte[] RandomBlock()
        {
            byte[] localId = new byte[16];

            using (CSPRsg rnd = new CSPRsg())
                rnd.GetBytes(localId);

            return localId;
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
        /// MacStream to verify with a keyed HMAC, that tests the encrypted file before it is conditionally decrypted. 
        /// If accepted the stream is then decrypted using the CipherStream class.
        /// </remarks>
        private void Decrypt()
        {
            CipherDescription cipherDesc;
            KeyParams keyParam;
            byte[] chksum = null;

            try
            {
                // decrypt file extension first
                string ext = GetExtension(_inputPath, _keyFilePath);
                // copy and erase the message header and resize stream
                MemoryStream hdrStream = ExtractHeader(_inputPath);
                MessageDescription msgDesc = new MessageDescription(hdrStream);

                using (FileStream inStream = new FileStream(_inputPath, FileMode.Open, FileAccess.ReadWrite))
                {
                    // get the keyheader and key material from the key file
                    using (PackageFactory keyFactory = new PackageFactory(new FileStream(_keyFilePath, FileMode.Open, FileAccess.ReadWrite), _container.Authority))
                    {
                        if (keyFactory.AccessScope == KeyScope.NoAccess)
                        {
                            Invoke(new MethodInvoker(() => {
                                MessageBox.Show(this, keyFactory.LastError);
                            }));
                            return;
                        }
                        keyFactory.Extract(msgDesc.KeyID, out cipherDesc, out keyParam);//id:149,159.. e:90,141.. k:49,90.. i:63,184.. -g
                    }

                    _outputPath = Utilities.GetUniquePath(_outputPath + ext);

                    // if a signing key, test the mac: (MacSize = 0; not signed)
                    if (cipherDesc.MacKeySize > 0)
                    {
                        if (lblStatus.InvokeRequired)
                            lblStatus.Invoke(new MethodInvoker(delegate { lblStatus.Text = "Calculating the MAC code.."; }));

                        // get the hmac for the encrypted file; this could be made selectable
                        // via the KeyHeaderStruct MacDigest and MacSize members.
                        IDigest dgt = DigestFromName.GetInstance((Digests)_container.Description.MacEngine);

                        using (MacStream mstrm = new MacStream(new HMAC(dgt, keyParam.IKM)))
                        {
                            // get the message mac code
                            chksum = new byte[msgDesc.MacCodeLength];
                            hdrStream.Read(chksum, 0, msgDesc.MacCodeLength);
                            // initialize mac stream
                            inStream.Seek(0, SeekOrigin.Begin);
                            mstrm.ProgressPercent -= OnMacProgress;
                            mstrm.ProgressPercent += OnMacProgress;
                            mstrm.Initialize(inStream);

                            // get the mac; offset by header length + Mac and specify adjusted length
                            byte[] hash = mstrm.ComputeMac(inStream.Length, 0);

                            // compare, notify and abort on failure
                            if (!Evaluate.AreEqual(chksum, hash))
                            {
                                Invoke(new MethodInvoker(() => {
                                    MessageBox.Show(this, "Message hash does not match! The file has been tampered with.");
                                }));
                                return;
                            }
                        }
                    }

                    if (lblStatus.InvokeRequired)
                        lblStatus.Invoke(new MethodInvoker(delegate { lblStatus.Text = "Decrypting the file.."; }));

                    // with this constructor, the CipherStream class creates the cryptographic 
                    // engine using the description contained in the CipherDescription structure.
                    // The (cipher and) engine are automatically destroyed in the cipherstream dispose
                    using (CipherStream cstrm = new CipherStream(cipherDesc))
                    {
                        using (FileStream outStream = new FileStream(_outputPath, FileMode.Create, FileAccess.Write))
                        {
                            // start at an input offset equal to the message header size
                            inStream.Seek(0, SeekOrigin.Begin);
                            // use a percentage counter
                            cstrm.ProgressPercent -= OnCipherProgress;
                            cstrm.ProgressPercent += new CipherStream.ProgressDelegate(OnCipherProgress);
                            // initialize internals
                            cstrm.Initialize(false, keyParam);
                            // write the decrypted output to file
                            cstrm.Write(inStream, outStream);
                        }
                    }
                    // copy the header back
                    if (_outputPath != _inputPath)
                    {
                        if (chksum != null)
                            inStream.Write(chksum, 0, chksum.Length);
                        msgDesc.ToStream().CopyTo(inStream);
                    }
                }

                // in-place decryption
                if (_outputPath == _inputPath)
                {
                    _outputPath = Utilities.GetUniquePath(Path.Combine(Path.GetDirectoryName(_inputPath), Path.GetFileNameWithoutExtension(_inputPath) +
                        MessageDescription.DecryptExtension(msgDesc.Extension, keyParam.ExtKey)));
                    if (File.Exists(_outputPath))
                        File.Delete(_outputPath);
                    File.Move(_inputPath, _outputPath);
                }

                // destroy the key
                keyParam.Dispose();
            }
            catch (Exception ex)
            {
                if (File.Exists(_outputPath))
                    File.Delete(_outputPath);

                string message = ex.Message == null ? "" : ex.Message;
                Invoke(new MethodInvoker(() => {
                    MessageBox.Show(this, "An error occured, the file could not be encrypted! " + message);
                }));
            }
            finally
            {
                Invoke(new MethodInvoker(() => { Reset(); }));
            }
        }

        /// <remarks>
        /// This method demonstrates using a PackageFactory and CipherStream class to
        /// both encrypt a file, and optionally sign the message with an SHA512 HMAC.
        /// See the CipherStream and MacStream documentation for more examples.
        /// </remarks>
        private void Encrypt()
        {
            CipherDescription keyHeader;
            KeyParams keyParam;

            try
            {
                byte[] keyId = null;

                // get the keyheader and key material from the key file
                using (PackageFactory keyFactory = new PackageFactory(new FileStream(_keyFilePath, FileMode.Open, FileAccess.ReadWrite), _container.Authority))
                {
                    if (!keyFactory.AccessScope.Equals(KeyScope.Creator))
                    {
                        Invoke(new MethodInvoker(() => {
                            MessageBox.Show(this, keyFactory.LastError);
                        }));
                        return;
                    }
                    else if (keyFactory.AccessScope.Equals(KeyScope.NoAccess))
                    {
                        Invoke(new MethodInvoker(() => {
                            MessageBox.Show(this, keyFactory.LastError);
                        }));
                        return;
                    }

                    // get the key info
                    PackageInfo pki = keyFactory.KeyInfo();
                    keyId = (byte[])keyFactory.NextKey(out keyHeader, out keyParam).Clone();
                }

                // with this constructor, the CipherStream class creates the cryptographic
                // engine using the description in the CipherDescription.
                // The (cipher and) engine are destroyed in the cipherstream dispose
                using (CipherStream cstrm = new CipherStream(keyHeader))
                {
                    using (FileStream inStream = new FileStream(_inputPath, FileMode.Open, FileAccess.Read))
                    {
                        using (FileStream outStream = new FileStream(_outputPath, FileMode.Create, FileAccess.ReadWrite))
                        {
                            if (lblStatus.InvokeRequired)
                                lblStatus.Invoke(new MethodInvoker(delegate {
                                    lblStatus.Text = "Encrypting the file..";
                                }));

                            // use a percentage counter
                            cstrm.ProgressPercent -= OnCipherProgress;
                            cstrm.ProgressPercent += new CipherStream.ProgressDelegate(OnCipherProgress);
                            // initialize internals
                            cstrm.Initialize(true, keyParam);
                            // write the encrypted output to file
                            cstrm.Write(inStream, outStream);

                            // create the header
                            MemoryStream hdrStream = new MessageDescription(keyId, MessageDescription.EncryptExtension(Path.GetExtension(_inputPath), keyParam.ExtKey), keyHeader.MacKeySize).ToStream();

                            // if this is a signing key, calculate the mac 
                            if (keyHeader.MacKeySize > 0)
                            {
                                if (lblStatus.InvokeRequired)
                                    lblStatus.Invoke(new MethodInvoker(delegate {
                                        lblStatus.Text = "Generating the MAC code..";
                                    }));

                                // This is where you would select and initialize the correct Digest via the
                                // CipherDescription member, and initialize the corresponding digest. 
                                IDigest dgt = DigestFromName.GetInstance((Digests)_container.Description.MacEngine);
                                // Get the mac for the encrypted file; Mac engine is SHA512 by default, 
                                // configurable via the CipherDescription MacSize and MacEngine members.
                                using (MacStream mstrm = new MacStream(new HMAC(dgt, keyParam.IKM)))
                                {
                                    mstrm.ProgressPercent -= OnMacProgress;
                                    mstrm.ProgressPercent += OnMacProgress;
                                    // seek to end of header
                                    outStream.Seek(0, SeekOrigin.Begin);
                                    // initialize mac stream
                                    mstrm.Initialize(outStream);
                                    // get the hash; specify offset and adjusted size
                                    // get the mac value 
                                    byte[] hash = mstrm.ComputeMac(outStream.Length, 0);
                                    // write the mac value to the end of the file
                                    outStream.Write(hash, 0, hash.Length);
                                }
                            }

                            // copy the header to file
                            hdrStream.CopyTo(outStream);
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
                Invoke(new MethodInvoker(() => {
                    MessageBox.Show(this, "An error occured, the file could not be encrypted! " + message);
                }));
            }
            finally
            {
                Invoke(new MethodInvoker(() => { Reset(); }));
            }
        }

        /// <summary>
        /// Copy and remove the message description structure
        /// </summary>
        /// 
        /// <param name="MessagePath">Path to the message file</param>
        /// 
        /// <returns>Serialized MessageDescription structure</returns>
        private MemoryStream ExtractHeader(string MessagePath)
        {
            MemoryStream hdrStream = new MemoryStream();

            using (FileStream inStream = new FileStream(MessagePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            {
                // get the message header
                int len = MessageDescription.GetHeaderSize;
                inStream.Seek(inStream.Length - len, SeekOrigin.Begin);
                inStream.CopyTo(hdrStream);

                int msze = MessageDescription.GetMessageMacSize(hdrStream);
                if (msze > 0)
                {
                    len += msze;
                    inStream.Seek(inStream.Length - len, SeekOrigin.Begin);
                    byte[] code = new byte[msze];
                    inStream.Read(code, 0, msze);
                    hdrStream.Seek(hdrStream.Length, SeekOrigin.Begin);
                    hdrStream.Write(code, 0, msze);
                }

                // erase first
                inStream.Seek(inStream.Length - len, SeekOrigin.Begin);
                byte[] fill = new byte[len];
                inStream.Write(fill, 0, len);
                inStream.SetLength(inStream.Length - len);
                hdrStream.Seek(0, SeekOrigin.Begin);
            }
            return hdrStream;
        }

        /// <summary>
        /// Retrieve the decrypted file extension
        /// </summary>
        /// 
        /// <param name="MessagePath">Full path to the message file</param>
        /// <param name="KeyPath">Full path to the key file</param>
        /// 
        /// <returns>The decrypted file extension</returns>
        private string GetExtension(string MessagePath, string KeyPath)
        {
            string decExt = "";

            if (File.Exists(MessagePath) && File.Exists(KeyPath))
            {
                using (PackageFactory pf = new PackageFactory(new FileStream(KeyPath, FileMode.Open, FileAccess.Read), _container.Authority))
                {
                    using (FileStream ms = new FileStream(MessagePath, FileMode.Open, FileAccess.Read))
                    {
                        ms.Seek(ms.Length - MessageDescription.GetHeaderSize, SeekOrigin.Begin);
                        MessageDescription msg = new MessageDescription(ms);
                        decExt = MessageDescription.DecryptExtension(msg.Extension, pf.GetExtensionKey(msg.KeyID));
                    }
                }
            }

            return decExt;
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

                if (!cbHkdf.Enabled)
                    _container.Description.KdfEngine = 0;

                // create a PackageKey; a key package can contain 1 or many thousands of 'subkeys'. Each subkey set
                // contains one group of unique random keying material; key, iv, and optional hmac key. 
                // Each key set is used only once for encryption, guaranteeing that a unique set of values is used for every encryption cycle.
                PackageKey package = new PackageKey(
                    _container.Authority,           // the KeyAuthority structure
                    _container.Description,         // the CipherDescription structure
                    keyCount);                      // the number of subkeys to add to this key package
                    
                // create and write the key
                using (PackageFactory factory = new PackageFactory(new FileStream(_keyFilePath, FileMode.Create, FileAccess.ReadWrite), _container.Authority))
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
                MessageBox.Show(this, "An error occured, the key could not be created! " + message);
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
                using (PackageFactory pf = new PackageFactory(new FileStream(KeyPath, FileMode.Open, FileAccess.Read), _container.Authority))
                {
                    using (FileStream ms = new FileStream(MessagePath, FileMode.Open, FileAccess.Read))
                    {
                        ms.Seek(ms.Length - MessageDescription.GetHeaderSize, SeekOrigin.Begin);
                        MessageDescription msg = new MessageDescription(ms);
                        isEqual = pf.ContainsSubKey(msg.KeyID) > -1;
                    }
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

        private void LoadComboDefaults()
        {
            ComboHelper.LoadEnumValues(cbEngines, typeof(SymmetricEngines));
            ComboHelper.AddEnumRange(cbCipherMode, typeof(CipherModes), 1, 8);
            ComboHelper.LoadEnumValues(cbPaddingMode, typeof(PaddingModes));
            ComboHelper.LoadEnumValues(cbHkdf, typeof(Digests));
            ComboHelper.LoadEnumValues(cbHmac, typeof(Digests));

            cbVectorSize.SelectedIndex = 0;
            cbCipherMode.SelectedIndex = 2;
            cbPaddingMode.SelectedIndex = 1;
            cbHkdf.SelectedIndex = 5;
            cbHmac.SelectedIndex = 5;
        }

        private void Reset()
        {
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

            if (CipherEngine == SymmetricEngines.RHX ||
                CipherEngine == SymmetricEngines.SHX ||
                CipherEngine == SymmetricEngines.THX)
            {
                switch (KdfEngine)
                {
                    case Digests.None:
                        cbKeySize.Items.Add(KeySizes.K128);
                        cbKeySize.Items.Add(KeySizes.K192);
                        cbKeySize.Items.Add(KeySizes.K256);
                        cbKeySize.Items.Add(KeySizes.K512);
                        break;
                    case Digests.Blake2S256:
                    case Digests.Keccak256:
                    case Digests.Skein256:
                    case Digests.SHA256:
                        cbKeySize.Items.Add(KeySizes.K256);
                        cbKeySize.Items.Add(KeySizes.K512);
                        cbKeySize.Items.Add(KeySizes.K768);
                        cbKeySize.Items.Add(KeySizes.K1024);
                        break;
                    case Digests.Blake2B512:
                    case Digests.Keccak512:
                    case Digests.SHA512:
                    case Digests.Skein512:
                        cbKeySize.Items.Add(KeySizes.K512);
                        cbKeySize.Items.Add(KeySizes.K1024);
                        cbKeySize.Items.Add(KeySizes.K1536);
                        cbKeySize.Items.Add(KeySizes.K2048);
                        break;
                    case Digests.Skein1024:
                        cbKeySize.Items.Add(KeySizes.K1024);
                        cbKeySize.Items.Add(KeySizes.K1536);
                        cbKeySize.Items.Add(KeySizes.K2048);
                        cbKeySize.Items.Add(KeySizes.K2560);
                        break;
                }
                ComboHelper.SetSelectedIndex(cbKeySize, 2);
            }
            else if (CipherEngine == SymmetricEngines.ChaCha ||
                CipherEngine == SymmetricEngines.Salsa)
            {
                cbKeySize.Items.Add(KeySizes.K128);
                cbKeySize.Items.Add(KeySizes.K256);
                ComboHelper.SetSelectedIndex(cbKeySize, 1);
            }
        }

        private void SetComboParams(SymmetricEngines Engine)
        {
            cbCipherMode.Enabled = true;
            cbRounds.Enabled = true;
            cbVectorSize.Enabled = true;
            cbRounds.Items.Clear();
            cbVectorSize.Items.Clear();
            cbVectorSize.Items.Add(IVSizes.V128);
            cbVectorSize.SelectedIndex = 0;
            cbVectorSize.Enabled = cbHkdf.Enabled = Engine != SymmetricEngines.ChaCha && Engine != SymmetricEngines.Salsa;

            if (Engine == SymmetricEngines.ChaCha && Engine == SymmetricEngines.Salsa)
                cbPaddingMode.Enabled = false;
            else if ((CipherModes)_container.Description.CipherType != CipherModes.CTR)
                cbPaddingMode.Enabled = true;

            switch (Engine)
            {
                case SymmetricEngines.ChaCha:
                case SymmetricEngines.Salsa:
                    cbCipherMode.Enabled = false;
                    cbPaddingMode.Enabled = false;
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 8, 20);
                    ComboHelper.SetSelectedIndex(cbRounds, 6);
                    cbVectorSize.Items.Clear();
                    cbVectorSize.Items.Add(IVSizes.V64);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case SymmetricEngines.RHX:
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 10, 38);
                    ComboHelper.SetSelectedIndex(cbRounds, 2);
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
                case SymmetricEngines.THX:
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            SetRounds();
        }
        #endregion

        #region Event Handlers
        #region Controls
        private void OnCipherModeChanged(object sender, EventArgs e)
        {
            CipherModes cmode = CipherModes.CTR;
            Enum.TryParse<CipherModes>(((ComboBox)sender).Text, out cmode);
            _container.Description.CipherType = (int)cmode;
            cbPaddingMode.Enabled = cmode != CipherModes.CTR;
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
            chkSign.Enabled = digest != Digests.None;
            if (!chkSign.Enabled)
                chkSign.Checked = false;

            if (chkSign.Checked)
                _container.Description.MacKeySize = GetMacSize(digest);
        }

        private void OnInfoButtonClick(object sender, EventArgs e)
        {
            using (PackageFactory keyFactory = new PackageFactory(new FileStream(_keyFilePath, FileMode.Open, FileAccess.Read), _container.Authority))
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
                    _container.Description.MacKeySize = 0;
                else
                    _container.Description.MacKeySize = GetMacSize((Digests)_container.Description.MacEngine);
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
            int ksize = GetKeySize();
            _container.Description.KeySize = ksize;
            SetRounds();
        }

        private void OnPaddingModeChanged(object sender, EventArgs e)
        {
            PaddingModes padding = PaddingModes.PKCS7;
            Enum.TryParse<PaddingModes>(((ComboBox)sender).Text, out padding);
            _container.Description.PaddingType = (int)padding;
        }

        private void OnCipherProgress(object sender, CipherStream.ProgressEventArgs args)
        {
            if (pbStatus.InvokeRequired)
                pbStatus.Invoke(new MethodInvoker(delegate { pbStatus.Value = args.Percent; }));
        }

        private void OnMacProgress(object sender, MacStream.ProgressEventArgs args)
        {
            if (pbStatus.InvokeRequired)
                pbStatus.Invoke(new MethodInvoker(delegate { pbStatus.Value = args.Percent; }));
        }

        private void OnRoundsChanged(object sender, EventArgs e)
        {
            RoundCounts rcount = RoundCounts.R10;
            Enum.TryParse<RoundCounts>(((ComboBox)sender).Text, out rcount);
            _container.Description.RoundCount = (int)rcount;
        }

        private void OnSigningChanged(object sender, EventArgs e)
        {
            CheckBox chk = sender as CheckBox;
            Digests digest = Digests.Keccak512;
            Enum.TryParse<Digests>(cbHmac.Text, out digest);

            if (!chk.Checked)
                _container.Description.MacKeySize = 0;
            else
                _container.Description.MacKeySize = GetMacSize(digest);
        }

        private void OnSubKeyCountKeyPress(object sender, KeyPressEventArgs e)
        {
            e.Handled = (!char.IsDigit(e.KeyChar) && !char.IsControl(e.KeyChar));
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
                MessageBox.Show(this, "You do not have permission to create files in this directory! Choose a different path..");
                _keyFilePath = string.Empty;
            }
            else
            {
                _keyFilePath = Utilities.GetUniquePath(filePath);
                SaveKey();
            }
            dtVolatileTime.Value = DateTime.Now.AddDays(1);
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

        private void OnKeyFileTextChanged(object sender, EventArgs e)
        {
            btnInfo.Enabled = txtKeyFile.Text.Length != 0 ? File.Exists(txtKeyFile.Text) : false;
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
                    using (PackageFactory keyFactory = new PackageFactory(new FileStream(keyFile, FileMode.Open, FileAccess.Read), _container.Authority))
                    {
                        if (keyFactory.AccessScope == KeyScope.NoAccess)
                        {
                            Array.Clear(_container.Authority.PackageId, 0, _container.Authority.PackageId.Length);
                            MessageBox.Show(this, "Passphrase does not match! This key requires authentication.");
                            txtKeyFile.Text = KEY_DEFN;
                            btnEncrypt.Enabled = false;
                            return;
                        }
                    }
                }
                else
                {
                    MessageBox.Show(this, "Access denied! This key requires authentication.");
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
                    MessageBox.Show(this, "Key does not match the message! Choose a different key..");
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
                MessageBox.Show(this, "You do not have permission to create files in this directory! Choose a different path..");
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
            LoadComboDefaults();
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
                Description = new CipherDescription(SymmetricEngines.RHX, (int)KeySizes.K256, IVSizes.V128, CipherModes.CTR, PaddingModes.X923, BlockSizes.B128, RoundCounts.R22, Digests.SHA512, 0),
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
                    byte[] appData = Encoding.GetEncoding("Latin1").GetBytes(Properties.Settings.Default.AppSettings);
                    // decrypt the array with DAPI, requires same user context
                    appData = DataProtect.DecryptProtectedData(appData, Utilities.GetCredentials());
                    // deserialize the settings container
                    _container = SettingsContainer.DeSerialize(new MemoryStream(appData));
                    _container.Authority.OptionFlag = 0;
                    _container.Authority.KeyPolicy = 0;
                    // apply the container values to controls
                    cbEngines.SelectedIndex = ComboHelper.IndexFromValue(_container.Description.EngineType, typeof(SymmetricEngines), cbEngines);
                    SetComboParams((SymmetricEngines)_container.Description.EngineType);
                    SetKeySizes((SymmetricEngines)_container.Description.EngineType, (Digests)_container.Description.KdfEngine);
                    cbCipherMode.SelectedIndex = ComboHelper.IndexFromValue(_container.Description.CipherType, typeof(CipherModes), cbCipherMode);
                    cbHkdf.SelectedIndex = ComboHelper.IndexFromValue(_container.Description.KdfEngine, typeof(Digests), cbHkdf);
                    cbHmac.SelectedIndex = ComboHelper.IndexFromValue(_container.Description.MacEngine, typeof(Digests), cbHmac);
                    cbKeySize.SelectedIndex = ComboHelper.IndexFromValue(_container.Description.KeySize, typeof(KeySizes), cbKeySize);
                    cbPaddingMode.SelectedIndex = ComboHelper.IndexFromValue(_container.Description.PaddingType, typeof(PaddingModes), cbPaddingMode);
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
                Properties.Settings.Default.AppSettings = Encoding.GetEncoding("Latin1").GetString(DataProtect.EncryptProtectedData(appData, Utilities.GetCredentials()));
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

        private int GetKeySize()
        {
            KeySizes ksize = KeySizes.K256;
            Enum.TryParse<KeySizes>(cbKeySize.Text, out ksize);
            return (int)ksize;
        }

        private int GetMacSize(Digests DigestType)
        {
            int macSize = 0;

            switch (DigestType)
            {
                case Digests.Blake2S256:
                case Digests.SHA256:
                case Digests.Skein256:
                    macSize = 32;
                    break;
                case Digests.Blake2B512:
                case Digests.SHA512:
                case Digests.Skein512:
                case Digests.Keccak512:
                    macSize = 64;
                    break;
                case Digests.Skein1024:
                    macSize = 128;
                    break;
            }

            return macSize;
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

        private void SetRounds()
        {
            int ksize = GetKeySize();
            cbRounds.Enabled = true;

            if (cbEngines.SelectedIndex == 0)
            {
                if (ksize == 16)
                    cbRounds.SelectedIndex = 0;
                else if (ksize == 24)
                    cbRounds.SelectedIndex = 1;
                else if (ksize == 32)
                    cbRounds.SelectedIndex = 2;
                else
                    cbRounds.SelectedIndex = 6;
            }
            else if (cbEngines.SelectedIndex < 3)
            {
                cbRounds.SelectedIndex = 0;
            }
            else
            {
                cbRounds.SelectedIndex = 6;
            }

            if (cbHkdf.SelectedItem != null)
                cbRounds.Enabled = (Digests)cbHkdf.SelectedItem != Digests.None;
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
    }
}
