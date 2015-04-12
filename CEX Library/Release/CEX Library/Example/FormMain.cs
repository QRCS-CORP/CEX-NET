#region Directives
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.Crypto.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Process;
using VTDev.Libraries.CEXEngine.Queue;
using VTDev.Libraries.CEXEngine.Utility;
using VTDev.Projects.CEX.Helper;
using System.ComponentModel;
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
        private BlockSizes _blockSize;
        private CipherModes _cipherType;
        private Engines _engineType = Engines.RHX;
        private string _inputPath = "";
        private bool _isEncryption;
        private bool _isParallel = true;
        private bool _isSigned;
        private string _keyFilePath;
        private KeySizes _keySize;
        private string _lastKeyPath = "";
        private string _lastInputPath = "";
        private string _lastOutputPath = "";
        private string _outputPath = "";
        private PaddingModes _paddingMode;
        private RoundCounts _roundCount;
        private IVSizes _ivSize;
        #endregion

        #region Constructor
        public FormMain()
        {
            InitializeComponent();
        }
        #endregion

        #region Crypto
        /// <remarks>
        /// This method demonstrates using a KeyHeaderStruct with an HMAC key, 
        /// and a MessageHeaderStruct with a keyed hash value to test 
        /// the validity of an encrypted file before it is conditionally decrypted. 
        /// </remarks>
        private void Decrypt()
        {
            KeyHeaderStruct keyHeader;
            KeyParams keyParam;

            try
            {
                // get the keyheader and key material from the key file
                using (KeyFactory keyFactory = new KeyFactory(_keyFilePath))
                    keyFactory.Extract(out keyParam, out keyHeader);

                // offset start position is base header + Mac size
                int hdrOffset = MessageHeader.GetHeaderSize + keyHeader.MacSize;

                using (FileStream inStream = new FileStream(_inputPath, FileMode.Open, FileAccess.Read))
                {
                    // decrypt file extension and create a unique path
                    _outputPath = Utilities.GetUniquePath(_outputPath + MessageHeader.GetExtension(inStream, keyHeader.ExtensionKey));

                    // if a signing key, test the mac: (MacSize = 0; not signed)
                    if (keyHeader.MacSize > 0)
                    {
                        // get the hmac for the encrypted file; this could be made selectable
                        // via the KeyHeaderStruct MacDigest and MacSize members.
                        using (MacStream mstrm = new MacStream(new SHA512HMAC(keyParam.IKM)))
                        {
                            // get the message header mac
                            byte[] chksum = MessageHeader.GetMessageMac(inStream, keyHeader.MacSize);

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

                    // with this constructor, the CipherStream class creates the cryptographic 
                    // engine using the description contained in the keyheaderstruct.
                    // The (cipher and) engine are automatically destroyed in the cipherstream dispose
                    using (CipherStream cstrm = new CipherStream(false, keyHeader, keyParam))
                    {
                        using (FileStream outStream = new FileStream(_outputPath, FileMode.Create, FileAccess.Write))
                        {
                            // start at an input offset equal to the message header size
                            inStream.Seek(hdrOffset, SeekOrigin.Begin);
                            // use a percentage counter
                            cstrm.ProgressPercent += new CipherStream.ProgressDelegate(OnProgressPercent);
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
        /// This method demonstrates using a KeyHeaderStruct and CipherStream class to
        /// both encrypt a file, and optionally sign the message file with an SHA512 HMAC.
        /// The KeyHeaderStruct usage is optional; if using fixed cipher parameters, a much simpler
        /// construction can be made. See the CipherStream documentation for an example.
        /// </remarks>
        private void Encrypt()
        {
            KeyHeaderStruct keyHeader;
            KeyParams keyParam;

            try
            {
                // get the keyheader and key material from the key file
                using (KeyFactory keyFactory = new KeyFactory(_keyFilePath))
                    keyFactory.Extract(out keyParam, out keyHeader);

                // offset start position is base header + Mac size
                int hdrOffset = MessageHeader.GetHeaderSize + keyHeader.MacSize;

                // with this constructor, the CipherStream class creates the cryptographic
                // engine using the description in the keyheaderstruct.
                // The (cipher and) engine are destroyed in the cipherstream dispose
                using (CipherStream cstrm = new CipherStream(true, keyHeader, keyParam))
                {
                    using (FileStream inStream = new FileStream(_inputPath, FileMode.Open, FileAccess.Read))
                    {
                        using (FileStream outStream = new FileStream(_outputPath, FileMode.Create, FileAccess.ReadWrite))
                        {
                            // start at an output offset equal to the message header + MAC length
                            outStream.Seek(hdrOffset, SeekOrigin.Begin);
                            // use a percentage counter
                            cstrm.ProgressPercent += new CipherStream.ProgressDelegate(OnProgressPercent);
                            // initialize internals
                            cstrm.Initialize(inStream, outStream);
                            // write the encrypted output to file
                            cstrm.Write();

                            // write the key id to the header
                            MessageHeader.SetKeyId(outStream, keyHeader.KeyID);
                            // write the encrypted file extension
                            MessageHeader.SetExtension(outStream, MessageHeader.EncryptExtension(Path.GetExtension(_inputPath), keyHeader.ExtensionKey));

                            // if this is a signing key, calculate the mac 
                            if (keyHeader.MacSize > 0)
                            {
                                // get the mac for the encrypted file; Mac engine is SHA512 by default, 
                                // this is configurable via the KeyHeaderStruct MacSize and MacEngine members.
                                // This is where you would select and initialize the correct Digest via the
                                // KeyHeaderStruct MacDigest and MacSize members, and initialize 
                                // the corresponding digest. For expedience, this example is fixed on the default SHA512.
                                // An optional progress event is available in the MacStream class.
                                using (MacStream mstrm = new MacStream(new SHA512HMAC(keyParam.IKM)))
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
        /// Demonstrates saving a key file using the KeyFactory class
        /// </summary>
        private void SaveKey()
        {
            try
            {
                // using this Create() overload, the keying 
                // material is generated automatically via the
                // cipher description in the KeyHeaderStruct
                new KeyFactory(_keyFilePath).Create(
                    new KeyHeaderStruct(
                    _engineType,
                    (int)_keySize,
                    _ivSize,
                    _cipherType,
                    _paddingMode,
                    _blockSize,
                    _roundCount, 
                    Digests.SHA512,     // this is where the key schedule digest engine is specified, default is SHA-2 512
                    _isSigned ? 64 : 0, // specify the digest size; 0 means this is not a signing key
                    Digests.SHA512));   // this is where you specify the signing digest type

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
                    Guid messageId = MessageHeader.GetKeyId(msgFile);
                    using (FileStream keyFile = new FileStream(KeyPath, FileMode.Open, FileAccess.Read))
                    {
                        Guid keyId = KeyHeader.GetKeyId(keyFile);
                        isEqual =  messageId.Equals(keyId);
                    }
                }
            }

            return isEqual;
        }
        #endregion

        #region Helpers
        private void IsEnabled(bool State)
        {
            grpKey.Enabled = State;
            grpOutput.Enabled = State;
            mnuMain.Enabled = State;
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
            ComboEnumHelper.LoadEnumValues(cbEngines, typeof(Engines));
            ComboEnumHelper.LoadEnumValues(cbCipherMode, typeof(CipherModes));
            ComboEnumHelper.LoadEnumValues(cbPaddingMode, typeof(PaddingModes));
            cbCipherMode.SelectedIndex = 3;
            cbPaddingMode.SelectedIndex = 3;
        }

        private void OpenInBrowser(string WebPage)
        {
            try { System.Diagnostics.Process.Start(WebPage); }
            catch { }
        }

        private void Reset()
        {
            mnuMain.Enabled = true;
            btnEncrypt.Enabled = false;
            btnKeyFile.Enabled = false;
            btnOutputFile.Enabled = false;
            grpKey.Enabled = true;
            grpOutput.Enabled = true;
            lblStatus.Text = "Waiting..";
            txtInputFile.Text = FILE_DEFN;
            txtKeyFile.Text = KEY_DEFN;
            txtOutputFile.Text = SAVE_DEFN;
            _inputPath = string.Empty;
            _keyFilePath = string.Empty;
            _outputPath = string.Empty;
            pbStatus.Value = 0;
        }

        private void SetComboParams(Engines Engine)
        {
            cbCipherMode.Enabled = true;
            cbKeySize.Enabled = true;
            cbPaddingMode.Enabled = true;
            cbRounds.Enabled = true;
            cbVectorSize.Enabled = true;
            cbKeySize.Items.Clear();
            cbRounds.Items.Clear();
            cbVectorSize.Items.Clear();
            cbVectorSize.Items.Add(IVSizes.V128);
            cbVectorSize.SelectedIndex = 0;

            switch (Engine)
            {
                case Engines.ChaCha:
                case Engines.Salsa:
                    cbCipherMode.Enabled = false;
                    cbPaddingMode.Enabled = false;
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K384);
                    cbKeySize.Items.Add(KeySizes.K448);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 1);
                    ComboEnumHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 8, 30);
                    ComboEnumHelper.SetSelectedIndex(cbRounds, 6);
                    cbVectorSize.Items.Clear();
                    cbVectorSize.Items.Add(IVSizes.V64);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case Engines.DCS:
                    cbKeySize.Items.Add(KeySizes.K768);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 0);
                    cbKeySize.Enabled = false;
                    cbCipherMode.Enabled = false;
                    cbPaddingMode.Enabled = false;
                    cbRounds.Enabled = false;
                    cbVectorSize.Items.Clear();
                    cbVectorSize.Enabled = false;
                    break;
                case Engines.Fusion:
                    cbCipherMode.Enabled = false;
                    cbPaddingMode.Enabled = false;
                    ComboEnumHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 0);
                    ComboEnumHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboEnumHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case Engines.RDX:
                    cbRounds.Enabled = false;
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K512);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 1);
                    cbVectorSize.Items.Add(IVSizes.V256);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case Engines.RSX:
                    cbRounds.Enabled = false;
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K512);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 0);
                    cbVectorSize.Items.Add(IVSizes.V256);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case Engines.RHX:
                    _engineType = Engines.RHX;
                    ComboEnumHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 0);
                    ComboEnumHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 10, 38);
                    ComboEnumHelper.SetSelectedIndex(cbRounds, 2);
                    cbVectorSize.Items.Add(IVSizes.V256);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case Engines.RSM:
                    ComboEnumHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 0);
                    cbRounds.Items.Add(RoundCounts.R10);
                    cbRounds.Items.Add(RoundCounts.R18);
                    cbRounds.Items.Add(RoundCounts.R26);
                    cbRounds.Items.Add(RoundCounts.R34);
                    cbRounds.Items.Add(RoundCounts.R42);
                    ComboEnumHelper.SetSelectedIndex(cbRounds, 1);
                    cbVectorSize.Items.Add(IVSizes.V256);
                    cbVectorSize.SelectedIndex = 0;
                    break;
                case Engines.SHX:
                    ComboEnumHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 0);
                    cbRounds.Items.Add(RoundCounts.R32);
                    cbRounds.Items.Add(RoundCounts.R40);
                    cbRounds.Items.Add(RoundCounts.R48);
                    cbRounds.Items.Add(RoundCounts.R56);
                    cbRounds.Items.Add(RoundCounts.R64);
                    ComboEnumHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case Engines.SPX:
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K512);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 1);
                    cbRounds.Items.Add(RoundCounts.R32);
                    cbRounds.Items.Add(RoundCounts.R40);
                    cbRounds.Items.Add(RoundCounts.R48);
                    cbRounds.Items.Add(RoundCounts.R56);
                    cbRounds.Items.Add(RoundCounts.R64);
                    ComboEnumHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case Engines.TFX:
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K512);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 1);
                    ComboEnumHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboEnumHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case Engines.TSM:
                    ComboEnumHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 0);
                    cbRounds.Items.Add(RoundCounts.R16);
                    cbRounds.Items.Add(RoundCounts.R24);
                    cbRounds.Items.Add(RoundCounts.R32);
                    ComboEnumHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                default:
                    ComboEnumHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboEnumHelper.SetSelectedIndex(cbKeySize, 0);
                    ComboEnumHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboEnumHelper.SetSelectedIndex(cbRounds, 0);
                    break;
            }
        }
        #endregion

        #region Event Handlers
        #region Controls
        private void OnEngineChanged(object sender, EventArgs e)
        {
            Engines engine = Engines.RHX;
            Enum.TryParse<Engines>(((ComboBox)sender).Text, out engine);
            _engineType = engine;
            SetComboParams(engine);
        }

        private void OnCipherModeChanged(object sender, EventArgs e)
        {
            CipherModes cmode = CipherModes.CTR;
            Enum.TryParse<CipherModes>(((ComboBox)sender).Text, out cmode);
            _cipherType = cmode;
        }

        private void OnKeyCreateClick(object sender, EventArgs e)
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

        private void OnEncryptClick(object sender, EventArgs e)
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

        private void OnKeySizeChanged(object sender, EventArgs e)
        {
            KeySizes ksize = KeySizes.K256;
            Enum.TryParse<KeySizes>(((ComboBox)sender).Text, out ksize);
            _keySize = ksize;
        }

        private void OnPaddingModeChanged(object sender, EventArgs e)
        {
            PaddingModes padding = PaddingModes.PKCS7;
            Enum.TryParse<PaddingModes>(((ComboBox)sender).Text, out padding);
            _paddingMode = padding;
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
            _roundCount = rcount;
        }

        private void OnSignCheckedChanged(object sender, EventArgs e)
        {
            _isSigned = ((CheckBox)sender).Checked;
        }

        private void OnVectorSizeChanged(object sender, EventArgs e)
        {
            IVSizes ivsize = IVSizes.V128;
            Enum.TryParse<IVSizes>(((ComboBox)sender).Text, out ivsize);
            _ivSize = ivsize;

            if (_engineType == Engines.ChaCha || _engineType == Engines.Salsa)
                _blockSize = BlockSizes.B1024;
            else
                _blockSize = (BlockSizes)_ivSize;
        }
        #endregion

        #region Dialog Processing
        private void OnInputFileClick(object sender, EventArgs e)
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

            if (string.IsNullOrEmpty(keyFile)) return;

            if (!KeyHeader.IsValid(new FileStream(keyFile, FileMode.Open, FileAccess.Read)))
            {
                _keyFilePath = string.Empty;
                txtKeyFile.Text = KEY_DEFN;
                btnEncrypt.Enabled = false;
                MessageBox.Show("The Key file has been corrupted! Choose a different key..");
                return;
            }

            if (!_isEncryption)
            {
                if (IsMatchingKey(_inputPath, keyFile))
                {
                    _keyFilePath = keyFile;
                    txtKeyFile.Text = keyFile;
                    btnEncrypt.Enabled = true;
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
            }

            if (!string.IsNullOrEmpty(_keyFilePath))
                _lastKeyPath = Path.GetDirectoryName(_keyFilePath);
        }

        private void OnOutputFileClick(object sender, EventArgs e)
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
            LoadSettings();
            SetComboParams(_engineType);
        }

        private void OnMenuAboutSubClick(object sender, EventArgs e)
        {
            new FormAbout().ShowDialog(this);
        }

        private void OnMenuHelpSubClick(object sender, EventArgs e)
        {
            OpenInBrowser(@"http://www.vtdev.com/CEX/Help/index.html");
        }

        private void OnMenuSpeedTestClick(object sender, EventArgs e)
        {
            new FormSpeedTest().ShowDialog(this);
        }
        #endregion
        #endregion

        #region Settings
        private void LoadDefaults()
        {
            _engineType = Engines.RHX;
            _blockSize = BlockSizes.B128;
            _keySize = KeySizes.K1536;
            _paddingMode = PaddingModes.PKCS7;
            cbEngines.SelectedIndex = 3;
            cbCipherMode.SelectedIndex = 2;
            cbKeySize.SelectedIndex = 0;
            cbVectorSize.SelectedIndex = 0;
            cbPaddingMode.SelectedIndex = 2;
        }

        private void LoadSettings()
        {
            if (Properties.Settings.Default.SettingFirstRun == true)
            {
                Properties.Settings.Default.SettingFirstRun = false;
                LoadDefaults();

                return;
            }

            cbEngines.SelectedIndex = Properties.Settings.Default.SettingAlgorithm;
            cbCipherMode.SelectedIndex = Properties.Settings.Default.SettingCipherMode;
            cbKeySize.SelectedIndex = Properties.Settings.Default.SettingKeySize;
            _lastKeyPath = Properties.Settings.Default.SettingLastKeyPath;
            _lastInputPath = Properties.Settings.Default.SettingLastInputPath;
            _lastOutputPath = Properties.Settings.Default.SettingLastOutputPath;
            cbPaddingMode.SelectedIndex = Properties.Settings.Default.SettingPaddingMode;
            cbVectorSize.SelectedIndex = Properties.Settings.Default.SettingVectorSize;
            cbRounds.SelectedIndex = Properties.Settings.Default.SettingRounds;
            chkSign.Checked = Properties.Settings.Default.SettingSignFile;
        }

        private void SaveSettings()
        {
            Properties.Settings.Default.SettingAlgorithm = cbEngines.SelectedIndex;
            Properties.Settings.Default.SettingCipherMode = cbCipherMode.SelectedIndex;
            Properties.Settings.Default.SettingKeySize = cbKeySize.SelectedIndex;
            Properties.Settings.Default.SettingLastKeyPath = _lastKeyPath;
            Properties.Settings.Default.SettingLastInputPath = _lastInputPath;
            Properties.Settings.Default.SettingLastOutputPath = _lastOutputPath;
            Properties.Settings.Default.SettingPaddingMode = cbPaddingMode.SelectedIndex;
            Properties.Settings.Default.SettingVectorSize = cbVectorSize.SelectedIndex;
            Properties.Settings.Default.SettingRounds = cbRounds.SelectedIndex;
            Properties.Settings.Default.SettingSignFile = chkSign.Checked;

            Properties.Settings.Default.Save();
        }
        #endregion

        #region Saved
        private void TestKeySchedule()
        {
            byte[] data = new SecureRandom().GetBytes(1600);
            byte[] exp1 = new byte[1600];
            byte[] exp2 = new byte[1600];
            KeyParams kp = new KeyGenerator().GetKeyParams(64, 16);

            // test the ciphers
            using (ICipherMode cipher = new CTR(new RHX(10, 16, Digests.Blake256)))
            {
                cipher.Initialize(true, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(data, i, exp1, i);

                cipher.Initialize(false, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(exp1, i, exp2, i);
            }

            if (Compare.AreEqual(exp2, data) == false)
                throw new Exception("Failed!");

            kp = new KeyGenerator().GetKeyParams(128, 16);
            using (ICipherMode cipher = new CTR(new RHX(10, 16, Digests.Blake512)))
            {
                cipher.Initialize(true, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(data, i, exp1, i);

                cipher.Initialize(false, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(exp1, i, exp2, i);
            }

            if (Compare.AreEqual(exp2, data) == false)
                throw new Exception("Failed!");

            kp = new KeyGenerator().GetKeyParams(136, 16);
            using (ICipherMode cipher = new CTR(new RHX(10, 16, Digests.Keccak)))
            {
                cipher.Initialize(true, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(data, i, exp1, i);

                cipher.Initialize(false, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(exp1, i, exp2, i);
            }

            if (Compare.AreEqual(exp2, data) == false)
                throw new Exception("Failed!");

            kp = new KeyGenerator().GetKeyParams(96, 16);
            using (ICipherMode cipher = new CTR(new RHX(10, 16, Digests.SHA256)))
            {
                cipher.Initialize(true, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(data, i, exp1, i);

                cipher.Initialize(false, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(exp1, i, exp2, i);
            }

            if (Compare.AreEqual(exp2, data) == false)
                throw new Exception("Failed!");

            kp = new KeyGenerator().GetKeyParams(192, 16);
            using (ICipherMode cipher = new CTR(new RHX(10, 16, Digests.SHA512)))
            {
                cipher.Initialize(true, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(data, i, exp1, i);

                cipher.Initialize(false, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(exp1, i, exp2, i);
            }

            if (Compare.AreEqual(exp2, data) == false)
                throw new Exception("Failed!");

            kp = new KeyGenerator().GetKeyParams(256, 16);
            using (ICipherMode cipher = new CTR(new RHX(10, 16, Digests.Skein1024)))
            {
                cipher.Initialize(true, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(data, i, exp1, i);

                cipher.Initialize(false, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(exp1, i, exp2, i);
            }

            if (Compare.AreEqual(exp2, data) == false)
                throw new Exception("Failed!");

            kp = new KeyGenerator().GetKeyParams(64, 16);
            using (ICipherMode cipher = new CTR(new RHX(10, 16, Digests.Skein256)))
            {
                cipher.Initialize(true, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(data, i, exp1, i);

                cipher.Initialize(false, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(exp1, i, exp2, i);
            }

            if (Compare.AreEqual(exp2, data) == false)
                throw new Exception("Failed!");

            kp = new KeyGenerator().GetKeyParams(128, 16);
            using (ICipherMode cipher = new CTR(new RHX(10, 16, Digests.Skein512)))
            {
                cipher.Initialize(true, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(data, i, exp1, i);

                cipher.Initialize(false, kp);
                for (int i = 0; i < 1600; i += 16)
                    cipher.Transform(exp1, i, exp2, i);
            }

            if (Compare.AreEqual(exp2, data) == false)
                throw new Exception("Failed!");
        }

        private void TestCipherStream()
        {
            const string TESTFILE = @"c:\Tests\small.txt";
            const string TESTDIR = @"c:\Tests\";

            // just as simple as .
            KeyParams kp;
            using (KeyGenerator kg = new KeyGenerator())
                kp = kg.GetKeyParams(32, 16);

            /**/// ctr mode test //
            using (ICipherMode cipher = new CTR(new RDX()))
            {
                 // initialize the cipher for encryption
                cipher.Initialize(true, kp);
                
                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    // returns progress as a percent
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    // assign the input and output streams, set to dispose them
                    cstrm.Initialize(new FileStream(TESTFILE, FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "ctrenc.txt", FileMode.Create, FileAccess.Write), true);
                    // encrypt/decrypt write to the output stream
                    cstrm.Write();
                }
            }

            // ctr decrypt test
            using (ICipherMode cipher = new CTR(new RDX()))
            {
                // decrypt
                cipher.Initialize(false, kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.Initialize(new FileStream(TESTDIR + "ctrenc.txt", FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "ctrdec.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            /**/// cbc mode test //
            using (ICipherMode cipher = new CBC(new RDX()))
            {
                // encrypt
                cipher.Initialize(true, kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTFILE, FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "cbcenc.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            // cbc decrypt test
            using (ICipherMode cipher = new CBC(new RDX()))
            {
                // decrypt
                cipher.Initialize(false, kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTDIR + "cbcenc.txt", FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "cbcdec.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            /**/// cfb mode test
            using (ICipherMode cipher = new CFB(new RDX()))
            {
                // encrypt
                cipher.Initialize(true, kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTFILE, FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "cfbenc.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            // cfb decrypt test
            using (ICipherMode cipher = new CFB(new RDX()))
            {
                // decrypt
                cipher.Initialize(false, kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTDIR + "cfbenc.txt", FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "cfbdec.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            /**/// ofb mode test
            using (ICipherMode cipher = new OFB(new RDX()))
            {
                // encrypt
                cipher.Initialize(true, kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTFILE, FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "ofbenc.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            // ofb decrypt test
            using (ICipherMode cipher = new OFB(new RDX()))
            {
                // decrypt
                cipher.Initialize(false, kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTDIR + "ofbenc.txt", FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "ofbdec.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            /**/
            // stream 1 test.. 
            using (KeyGenerator kg = new KeyGenerator())
                kp = kg.GetKeyParams(192, 16);

            // massive encryption using just 7 lines of code, is that cool or what?
            using (IStreamCipher cipher = new Fusion())
            {
                // encrypt
                cipher.Initialize(kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTFILE, FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "fusenc.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            // decrypt test
            using (IStreamCipher cipher = new Fusion())
            {
                // encrypt
                cipher.Initialize(kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTDIR + "fusenc.txt", FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "fusdec.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            /**/// stream 2 test
            using (KeyGenerator kg = new KeyGenerator())
                kp = kg.GetKeyParams(96);

            using (IStreamCipher cipher = new DCS())
            {
                // encrypt
                cipher.Initialize(kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTFILE, FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "dcsenc.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }

            // decrypt test
            using (IStreamCipher cipher = new DCS())
            {
                // encrypt
                cipher.Initialize(kp);

                using (CipherStream cstrm = new CipherStream(cipher))
                {
                    cstrm.ProgressPercent += new CipherStream.ProgressDelegate(TestProgressPercent);
                    cstrm.Initialize(new FileStream(TESTDIR + "dcsenc.txt", FileMode.Open, FileAccess.Read), new FileStream(TESTDIR + "dcsdec.txt", FileMode.Create, FileAccess.Write), true);
                    cstrm.Write();
                }
            }
        }

        private void TestProgressPercent(object sender, ProgressChangedEventArgs e)
        {
            Console.WriteLine("TestProgressPercent: " + e.ProgressPercentage);
        }

        void TestProgressCounter(object sender, ProgressChangedEventArgs e)
        {
            Console.WriteLine("TestProgressCounter: " + e.ProgressPercentage);
        }

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

        private void BBSTest()
        {
            BBSG bbs = new BBSG();
            byte[] op = new byte[1024];
            bbs.GetBytes(op);

            for (int i = 0; i < op.Length; i++)
                Console.WriteLine(op[i]);
        }

        private void FormatAVSFile(string InputPath, string OutputPath)
        {
            using (FileStream reader = new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                int blockSize = (int)reader.Length;
                byte[] inputBuffer = new byte[blockSize];
                reader.Read(inputBuffer, 0, blockSize);
                var str = System.Text.Encoding.Default.GetString(inputBuffer);
                str = str.Replace(" ", "");
                str = str.Replace(Environment.NewLine, "");

                using (FileStream writer = new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    byte[] buffer = System.Text.Encoding.ASCII.GetBytes(str);
                    writer.Write(buffer, 0, buffer.Length);
                }
            }
        }

        private void FormatCounterpane(string InputPath, string OutputPath, int KeyLength, string Term, string Start, string Finish)
        {
            //ex. FormatCounterpane(@"C:\Tests\Saved\twofishkeymaster.txt", @"C:\Tests\twofishkey-192.txt", 48, "KEY=", "KEYSIZE=192", "KEYSIZE=256");
            string line = "";
            bool started = false;

            using (StreamReader reader = new StreamReader(InputPath))
            {
                using (StreamWriter writer = new StreamWriter(OutputPath))
                {
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (!started && line.Contains(Start))
                            started = true;
                        if (started && line.Contains(Finish)) 
                            break;
                        if (line.Contains(Term) && started)
                        {
                            line = line.Substring(line.IndexOf('=', 0) + 1, KeyLength);
                            writer.Write(line);
                        }
                    }
                }
            }
        }

        private void FormatNessieFile(string InputPath, string OutputPath, int KeyLength, string Term)
        {
            //ex. FormatCounterpane(@"C:\Tests\Saved\twofishkeymaster.txt", @"C:\Tests\twofishkey-128.txt", 32, "KEY=", "KEY=192");
            string line = "";

            using (StreamReader reader = new StreamReader(InputPath))
            {
                using (StreamWriter writer = new StreamWriter(OutputPath))
                {
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.Contains(Term))
                        {
                            if (KeyLength == 64)
                            {
                                line = line.Substring(line.IndexOf('=', 0) + 1, KeyLength / 2);
                                string nline = reader.ReadLine();
                                nline = nline.Replace(" ", "");
                                nline = nline.Replace(Environment.NewLine, "");
                                line += nline;
                            }
                            else
                            {
                                line = line.Substring(line.IndexOf('=', 0) + 1, KeyLength);

                            }
                            writer.Write(line);
                        }
                    }
                }
            }
        }

        private void GetQueueTime()
        {
            byte[] input = new byte[16];
            byte[] output = new byte[16];
            KeyParams keyParam = new KeyGenerator().GetKeyParams(32, 16);

            // get a time sample; queue size, constant time (not used)
            WaitQueue.SampleQueue squeue = new WaitQueue.SampleQueue(14400, 4);
            squeue.Initialize();

            using (CTR enc = new CTR(new RDX()))
            {
                enc.Initialize(true, keyParam);

                // sample 10 packets
                for (int i = 0; i < 900; i++)
                {
                    enc.Transform(input, output);
                    squeue.SQueue(output);
                }

                // example of a constant time value
                double ctime = Math.Ceiling(squeue.Samples.High * 2);
            }
        }

        private void ParallelCBCTest()
        {
            byte[] input = new byte[1024];
            byte[] cipher = new byte[1024];
            byte[] output = new byte[1024];
            KeyParams key = new KeyGenerator().GetKeyParams(32, 16);

            using (CBC mode = new CBC(new RDX()))
            {
                mode.Initialize(true, key);

                for (int i = 0; i < 1024; i += 16)
                    mode.EncryptBlock(input, i, cipher, i);
            }

            using (CBC mode = new CBC(new RDX()))
            {
                mode.Initialize(false, key);
                mode.DecryptBlock(cipher, output);
            }

            if (Compare.AreEqual(input, output) == false)
                throw new Exception("ModeVectors: CBC encrypted arrays are not equal!");
        }

        private void QueueTest()
        {
            // constant time example using a waitqueue
            // 1 rdx block
            byte[] input = new byte[16];
            byte[] output = new byte[16];
            byte[] buffer;
            KeyParams keyParam = new KeyGenerator().GetKeyParams(32, 16);

            for (int i = 0; i < 16; i++)
                input[i] = (byte)i;

            // 10 packet queue (1440 * 10 bytes), 4 millisecond constant time
            WaitQueue packetQueue = new WaitQueue(14400, 4);
            // initialize queue
            packetQueue.Initialize();

            using (CTR enc = new CTR(new RDX()))
            {
                enc.Initialize(true, keyParam);

                // process 1 packet
                for (int i = 0; i < 90; i++)
                {
                    enc.Transform(input, output);
                    if (packetQueue.Queue(output))
                    {
                        buffer = packetQueue.DeQueue();
                        // create packet and transmit //
                    }
                }
            }
        }

        private void TestCipher()
        {
            KeyParams keyParam = new KeyGenerator().GetKeyParams(320, 16);
            int sz = 64;
            byte[] inData = new byte[sz];
            byte[] outData = new byte[sz];
            byte[] retData = new byte[sz];

            using (Fusion cipher = new Fusion())
            {
                cipher.Initialize(keyParam);
                cipher.Transform(inData, outData);
            }

            using (Fusion cipher = new Fusion())
            {
                cipher.Initialize(keyParam);
                cipher.Transform(outData, retData);
            }
        }

        private void TestDelete()
        {
            using (VTDev.Libraries.CEXEngine.Security.SecureDelete sd = new VTDev.Libraries.CEXEngine.Security.SecureDelete())
                sd.Delete(@"C:\Tests\Saved\test.avi");
        }

        private void TestKeyGen()
        {
            byte[] data = new byte[33];

            KeyGenerator keyGen = new KeyGenerator();
            keyGen.GetBytes(data);
            data = keyGen.GetBytes(44);
            KeyParams key = new KeyParams(keyGen.GetBytes(197));
            key = new KeyParams(keyGen.GetBytes(133), keyGen.GetBytes(4));
        }
        #endregion
    }
}
