using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using System.Windows.Forms;
using Speed.SpeedTest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;

#region Speed Benchmarks
/// Speed tests on an AMD ASD-3600 Quad-Core, 4GB RAM, compiled Release/Any CPU.
/// Test is a transform of a byte array in a Monte Carlo method.
/// Sizes are in MBs (1000000 bytes). Time format sec.ms, key sizes in bits. Rate is MB per minute.
/// HX series will have similar times, as they use the same diffusion engines.
/// CTR mode and CBC decrypt are run in parallel mode. CBC encrypt is in single processor mode.
/// Highest rate so far is RDX with a 128 bit key: 7.85 GB per minute!
/// 
/// **Block Ciphers**
/// 
/// RDX (Rijndael): 256 Key, 14 Rounds, 100 MB
/// Mode    State   Size    Time    Rate
/// ----    -----   ----    ----    ----
/// CTR     ENC     100     0.88    6818
/// CTR     DEC     100     0.89    6741
/// CBC     ENC     100     2.95    2033
/// CBC     DEC     100     1.39    4316 
/// 
/// RSM (Rijndael/Serpent Merged): 1536 Key, 18 Rounds, 100 MB
/// Mode    State   Size    Time    Rate
/// ----    -----   ----    ----    ----
/// CTR     ENC     100     2.20    2727  
/// CTR     DEC     100     2.22    2702
/// CBC     ENC     100     7.99    750
/// CBC     DEC     100     2.62    2290
/// 
/// SPX (Serpent): 256 Key, 32 Rounds, 100 MB
/// Mode    State   Size    Time    Rate
/// ----    -----   ----    ----    ----
/// CTR     ENC     100     1.77    3389
/// CTR     DEC     100     1.75    3428
/// CBC     ENC     100     6.16    974
/// CBC     DEC     100     1.98    3030
/// 
/// TFX (Twofish): 256 Key, 16 Rounds, 100 MB
/// Mode    State   Size    Time    Rate
/// ----    -----   ----    ----    ----
/// CTR     ENC     100     1.00    6000
/// CTR     DEC     100     0.99    6060
/// CBC     ENC     100     3.43    1749
/// CBC     DEC     100     1.45    4137
/// 
/// 
/// **Stream Ciphers**
/// 
/// ChaCha: 256 Key, 20 Rounds, 100 MB
/// Size    Time    Rate
/// ----    ----    ----
/// 100     2.63    2281
/// 
/// DCS: 768 Key
/// Size    Time    Rate
/// ----    ----    ----
/// 100     2.12    2830
/// 
/// Fusion: 2560 Key, 18 Rounds, 100 MB
/// Size    Time    Rate
/// ----    ----    ----
/// 100     1.75    3428   
/// 
/// Salsa20: 256 Key, 20 Rounds, 100 MB
/// Size    Time    Rate
/// ----    ----    ----
/// 100     2.68    2238

#endregion

namespace Speed
{
    public partial class FormSpeedTest : Form
    {
        #region Constants
        private const int MB1 = 1000000;
        private const int MINUTE = 60000;
        #endregion

        #region Fields
        private CipherModes _cipherType;
        private SymmetricEngines _engineType;
        private KeySizes _keySize;
        private bool _isEncryption;
        private bool _isParallel;
        private RoundCounts _roundCount;
        private static int _sampleSize = 1;
        private EngineSpeedTest.TestTypes _testType;
        private static readonly Dictionary<string, SymmetricEngines> _engineDescriptions = new Dictionary<string, SymmetricEngines>() 
        {  
            {"ChaCha+: The ChaCha stream cipher", SymmetricEngines.ChaCha},
            {"Fusion: The Twofish and Rijndael Merged ciphers", SymmetricEngines.Fusion},
            {"RDX: An extended implementation of Rijndael", SymmetricEngines.RDX},
            {"RHX: Rijndael with an HKDF Key Schedule", SymmetricEngines.RHX},
            {"RSM: Rijndael and Serpent Merged block ciphers", SymmetricEngines.RSM},
            {"Salsa20+: The Salsa20 stream cipher", SymmetricEngines.Salsa},
            {"SHX: Serpent extended with an HKDF Key Schedule", SymmetricEngines.SHX},
            {"SPX: An extended implementation of Serpent", SymmetricEngines.SPX},
            {"TFX: An extended implementation of Twofish", SymmetricEngines.TFX},
            {"THX: Twofish extended with an HKDF Key Schedule", SymmetricEngines.THX},
            {"TSM: Twofish and Serpent Merged ciphers", SymmetricEngines.TSM}
        };
        #endregion

        #region Constructor
        public FormSpeedTest()
        {
            InitializeComponent();
            _isParallel = true;
        }
        #endregion

        #region Event Handlers
        private void OnEncryptChanged(object sender, EventArgs e)
        {
            if (((RadioButton)sender).Checked == false) return;
            _isEncryption = (((RadioButton)sender).Name.Equals("Encrypt"));
        }

        private void OnEngineChanged(object sender, EventArgs e)
        {
            SymmetricEngines engine = _engineDescriptions[((ComboBox)sender).Text];
            SetComboParams(engine);
            this._engineType = engine;
        }

        private void OnFormLoad(object sender, EventArgs e)
        {
            LoadComboParams();

            _isParallel = (Environment.ProcessorCount > 1);
            Parallelize.Checked = Parallelize.Enabled = this._isParallel;
            _isEncryption = true;
            _testType = EngineSpeedTest.TestTypes.ByteIO;
            txtSizeMB.LostFocus += new EventHandler(OnTextBoxLostFocus);
        }

        private void OnKeySizeChanged(object sender, EventArgs e)
        {
            KeySizes ksize = KeySizes.K256;
            Enum.TryParse<KeySizes>(((ComboBox)sender).Text, out ksize);
            _keySize = ksize;
        }

        private void OnModeChanged(object sender, EventArgs e)
        {
            CipherModes cmode = CipherModes.CTR;
            Enum.TryParse<CipherModes>(((ComboBox)sender).Text, out cmode);
            _cipherType = cmode;
        }

        private void OnParallelChanged(object sender, EventArgs e)
        {
            _isParallel = ((CheckBox)sender).Checked;
        }

        private void OnRoundsCountChanged(object sender, EventArgs e)
        {
            RoundCounts rcount = RoundCounts.R10;
            Enum.TryParse<RoundCounts>(((ComboBox)sender).Text, out rcount);
            _roundCount = rcount;
        }

        private void OnSpeedTestClick(object sender, EventArgs e)
        {
            RunSpeedTest();
        }

        private void OnTestTypeCheckChanged(object sender, EventArgs e)
        {
            if (((RadioButton)sender).Checked == false) return;

            if (((RadioButton)sender).Name.Equals("FileIo"))
                this._testType = EngineSpeedTest.TestTypes.FileIO;
            else
                this._testType = EngineSpeedTest.TestTypes.ByteIO;
        }

        private void OnTextChanged(object sender, EventArgs e)
        {
            TextBox tbox = sender as TextBox;
            int size = 10;

            int.TryParse(tbox.Text, out size);

            if (size > 1000)
                tbox.Text = "1000";
        }

        private void OnTextBoxKeyPress(object sender, KeyPressEventArgs e)
        {
            if (Char.IsDigit(e.KeyChar) || e.KeyChar == '\b')
                e.Handled = false;
            else
                e.Handled = true;
        }

        private void OnTextBoxLostFocus(object sender, EventArgs e)
        {
            TextBox tbox = sender as TextBox;

            if (string.IsNullOrEmpty(tbox.Text))
            {
                tbox.Text = "10";
            }
            else
            {
                int size = 10;
                int.TryParse(tbox.Text, out size);

                if (size == 0)
                    tbox.Text = "10";
                else if (size > 1000)
                    tbox.Text = "1000";
            }
        }
        #endregion

        #region Speed Test
        private void DoTest()
        {
            try
            {
                EngineSpeedTest esp = new EngineSpeedTest(_engineType, _cipherType, _sampleSize, (int)_keySize, (int)_roundCount, _isEncryption, _isParallel, _testType);
                esp.SpeedResult += new EngineSpeedTest.SpeedDelegate(OnSpeedResult);
                esp.Test();
            }
            catch (Exception ex)
            {
                string message = ex.Message == null ? "" : ex.Message;
                MessageBox.Show("An error occured, the test was aborted! " + message);
            }
            finally
            {
                Invoke(new MethodInvoker(() => { IsEnabled(true); }));
            }
        }

        private void OnSpeedResult(string Result)
        {
            TimeSpan tspan = new TimeSpan();
            TimeSpan.TryParseExact(Result, @"m\:ss\.ff", CultureInfo.CurrentCulture, out tspan);

            if (tspan.TotalMilliseconds > 0)
                Result += "; " + Math.Round(((double)MINUTE / tspan.TotalMilliseconds) * (_sampleSize / MB1), 3) + " MB per minute";

            lblEngineTime.Invoke(new MethodInvoker(delegate { lblEngineTime.Text = Result; }));
        }

        private void RunSpeedTest()
        {
            IsEnabled(false);

            int.TryParse(txtSizeMB.Text, out _sampleSize);
            if (_sampleSize == 0)
            {
                MessageBox.Show("Size can not be 0!");
                return;
            }

            _sampleSize = _sampleSize * MB1;

            Task testTask = Task.Factory.StartNew(() => 
            { 
                DoTest(); 
            });
        }
        #endregion

        #region Helpers
        private void IsEnabled(bool State)
        {
            grpSpeed.Enabled = State;
            grpParameters.Enabled = State;
            grpProcess.Enabled = State;
            grpTestType.Enabled = State;
            btnSpeedTest.Enabled = State;
        }

        private void LoadComboParams()
        {
            foreach (var desc in _engineDescriptions.Keys)
                cbEngines.Items.Add(desc);

            ComboHelper.LoadEnumValues(cbCipherMode, typeof(CipherModes));
            cbCipherMode.SelectedIndex = 2;
            SetComboParams(SymmetricEngines.RHX);
        }

        private void SetComboParams(SymmetricEngines Engine)
        {
            cbCipherMode.Enabled = true;
            cbKeySize.Enabled = true;
            cbKeySize.Items.Clear();
            cbRounds.Enabled = true;
            cbRounds.Items.Clear();

            switch (Engine)
            {
                case SymmetricEngines.ChaCha:
                case SymmetricEngines.Salsa:
                    cbCipherMode.Enabled = false;
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K384);
                    cbKeySize.Items.Add(KeySizes.K448);
                    ComboHelper.SetSelectedIndex(cbKeySize, 1);
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 8, 30);
                    ComboHelper.SetSelectedIndex(cbRounds, 6);
                    break;
                case SymmetricEngines.RDX:
                    cbRounds.Enabled = false;
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K512);
                    ComboHelper.SetSelectedIndex(cbKeySize, 1);
                    break;
                case SymmetricEngines.RHX:
                    ComboHelper.SetSelectedIndex(cbEngines, 3);
                    ComboHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboHelper.SetSelectedIndex(cbKeySize, 0);
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 10, 38);
                    ComboHelper.SetSelectedIndex(cbRounds, 2);
                    break;
                case SymmetricEngines.RSM:
                    ComboHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboHelper.SetSelectedIndex(cbKeySize, 0);
                    cbRounds.Items.Add(RoundCounts.R10);
                    cbRounds.Items.Add(RoundCounts.R18);
                    cbRounds.Items.Add(RoundCounts.R26);
                    cbRounds.Items.Add(RoundCounts.R34);
                    cbRounds.Items.Add(RoundCounts.R42);
                    ComboHelper.SetSelectedIndex(cbRounds, 1);
                    break;
                case SymmetricEngines.SHX:
                    ComboHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboHelper.SetSelectedIndex(cbKeySize, 0);
                    cbRounds.Items.Add(RoundCounts.R32);
                    cbRounds.Items.Add(RoundCounts.R40);
                    cbRounds.Items.Add(RoundCounts.R48);
                    cbRounds.Items.Add(RoundCounts.R56);
                    cbRounds.Items.Add(RoundCounts.R64);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case SymmetricEngines.SPX:
                    ComboHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 16, 64);
                    ComboHelper.SetSelectedIndex(cbKeySize, 2);
                    cbRounds.Items.Add(RoundCounts.R32);
                    cbRounds.Items.Add(RoundCounts.R40);
                    cbRounds.Items.Add(RoundCounts.R48);
                    cbRounds.Items.Add(RoundCounts.R56);
                    cbRounds.Items.Add(RoundCounts.R64);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case SymmetricEngines.TFX:
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K512);
                    ComboHelper.SetSelectedIndex(cbKeySize, 1);
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                default:
                    ComboHelper.AddEnumRange(cbKeySize, typeof(KeySizes), 192, 576);
                    ComboHelper.SetSelectedIndex(cbKeySize, 0);
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
            }
        }
        #endregion
    }
}
