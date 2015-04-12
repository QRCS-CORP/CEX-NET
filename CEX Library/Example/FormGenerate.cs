using System;
using System.Windows.Forms;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using System.Text;

namespace VTDev.Projects.CEX
{
    public partial class FormGenerate : Form
    {
        internal byte[] Passphrase { get; private set; }
        internal bool IsSession { get; private set; }

        public FormGenerate()
        {
            InitializeComponent();
        }

        private void OnGenCheckChanged(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(txtPassphrase.Text))
                btnGenerate.Enabled = txtPassphrase.Text.Length > 15;
        }

        private void OnPhraseTextChanged(object sender, EventArgs e)
        {
            TextBox tx = sender as TextBox;
            btnGenerate.Enabled = tx.Text.Length > 15;
        }

        private void OnGenerateButtonClick(object sender, EventArgs e)
        {
            byte[] data = Encoding.UTF8.GetBytes(txtPassphrase.Text);

            using (Keccak256 digest = new Keccak256())
                Passphrase = digest.ComputeHash(data);

            this.Hide();
        }

        private void OnCancelButtonClick(object sender, EventArgs e)
        {
            this.Close();
        }

        internal void Destroy()
        {
            if (Passphrase != null)
            {
                Array.Clear(Passphrase, 0, Passphrase.Length);
                Passphrase = null;
            }
            this.Close();
        }

        private void OnSessionCheckedChanged(object sender, EventArgs e)
        {
            CheckBox chk = sender as CheckBox;
            IsSession = chk.Checked;
        }
    }
}
