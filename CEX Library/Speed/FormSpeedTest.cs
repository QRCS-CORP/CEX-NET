using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using System.Windows.Forms;
using Speed.SpeedTest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;

#region Speed Benchmarks
/// Speed tests on an HP all-in-one with a I7-6700T processor, 12GB DDR3 RAM, compiled Release/Any CPU.
/// Test is a transform of a byte array in a Monte Carlo method.
/// Sizes are in MBs (1000000 bytes). Time format sec.ms, key sizes in bits. Rate is MB per minute.
/// CTR mode and CBC decrypt are run in parallel mode. CBC encrypt is in single processor mode.
/// Highest rate so far is RDX with a 128 bit key: 18.18 GB per minute!
/// 
/// Tip: Compile as release/any cpu, and run the executable bin\release\speed.exe; times are much faster without the ide..
/// 
/// **Block Ciphers**
/// 
/// RHX (Rijndael): 256 Key, 14 Rounds, 100 MB
/// Mode    State   Size    Time    Rate
/// ----    -----   ----    ----    ----
/// CTR     ENC     100     0.42    14285
/// CTR     DEC     100     0.43    13953
/// CBC     ENC     100     1.80    3333
/// CBC     DEC     100     0.52    11538 
/// 
/// SHX (Serpent): 256 Key, 32 Rounds, 100 MB
/// Mode    State   Size    Time    Rate
/// ----    -----   ----    ----    ----
/// CTR     ENC     100     1.07    5607
/// CTR     DEC     100     1.07    5607
/// CBC     ENC     100     4.49    1336
/// CBC     DEC     100     1.22    4918
/// 
/// THX (Twofish): 256 Key, 16 Rounds, 100 MB
/// Mode    State   Size    Time    Rate
/// ----    -----   ----    ----    ----
/// CTR     ENC     100     0.30    20000
/// CTR     DEC     100     0.30    20000
/// CBC     ENC     100     3.08    4651
/// CBC     DEC     100     0.39    15384
/// 
/// 
/// **Stream Ciphers**
/// 
/// ChaCha: 256 Key, 20 Rounds, 100 MB
/// Size    Time    Rate
/// ----    ----    ----
/// 100     0.14    42857
/// 
/// Salsa20: 256 Key, 20 Rounds, 100 MB
/// Size    Time    Rate
/// ----    ----    ----
/// 100     0.13    46153
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
            {"RHX: An extended implementation of the Rijndael cipher", SymmetricEngines.RHX},
            {"SHX: An extended implementation of the Serpent cipher", SymmetricEngines.SHX},
            {"THX: An extended implementation of the Twofish cipher", SymmetricEngines.THX},
            {"ChaCha: The ChaCha stream cipher", SymmetricEngines.ChaCha},
            {"Salsa20: The Salsa20 stream cipher", SymmetricEngines.Salsa}
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
            int bsze = (int)ksize;
            cbRounds.Enabled = (bsze > 64);
            SetRounds();
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
            cbCipherMode.SelectedIndex = 3;
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
                    ComboHelper.SetSelectedIndex(cbKeySize, 1);
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 8, 30);
                    ComboHelper.SetSelectedIndex(cbRounds, 6);
                    break;
                case SymmetricEngines.RHX:
                    ComboHelper.SetSelectedIndex(cbEngines, 0);
                    cbKeySize.Items.Clear();
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K192);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K512);
                    ComboHelper.SetSelectedIndex(cbKeySize, 2);
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 10, 38);
                    ComboHelper.SetSelectedIndex(cbRounds, 2);
                    break;
                case SymmetricEngines.SHX:
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K192);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K512);
                    ComboHelper.SetSelectedIndex(cbKeySize, 2);
                    cbRounds.Items.Add(RoundCounts.R32);
                    cbRounds.Items.Add(RoundCounts.R40);
                    cbRounds.Items.Add(RoundCounts.R48);
                    cbRounds.Items.Add(RoundCounts.R56);
                    cbRounds.Items.Add(RoundCounts.R64);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                case SymmetricEngines.THX:
                    cbKeySize.Items.Add(KeySizes.K128);
                    cbKeySize.Items.Add(KeySizes.K192);
                    cbKeySize.Items.Add(KeySizes.K256);
                    cbKeySize.Items.Add(KeySizes.K512);
                    ComboHelper.SetSelectedIndex(cbKeySize, 2);
                    ComboHelper.AddEnumRange(cbRounds, typeof(RoundCounts), 16, 32);
                    ComboHelper.SetSelectedIndex(cbRounds, 0);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            SetRounds();
        }

        private void SetRounds()
        {
            KeySizes ksize = KeySizes.K256;
            Enum.TryParse<KeySizes>(((ComboBox)cbKeySize).Text, out ksize);
            int bsze = (int)ksize;

            if (cbEngines.SelectedIndex == 0)
            {
                if (bsze == 16)
                    cbRounds.SelectedIndex = 0;
                else if (bsze == 24)
                    cbRounds.SelectedIndex = 1;
                else if (bsze == 32)
                    cbRounds.SelectedIndex = 2;
                else
                    cbRounds.SelectedIndex = 6;
            }
            else
            {
                cbRounds.SelectedIndex = 0;
            }
        }
        #endregion
    }
}
