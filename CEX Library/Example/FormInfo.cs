using System;
using System.Windows.Forms;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;

namespace VTDev.Projects.CEX
{
    public partial class FormInfo : Form
    {
        public FormInfo()
        {
            InitializeComponent();
        }

        public void SetInfo(PackageInfo Info)
        {
            lstInfo.Items.Clear();
            lstInfo.Items.Add("Creation and Origin");
            lstInfo.Items.Add("Created: " + Info.Created.ToString());
            lstInfo.Items.Add("Expires: " + Info.Expiration.ToString());
            lstInfo.Items.Add("Origin:" + Info.Origin.ToString());
            lstInfo.Items.Add("");
            lstInfo.Items.Add("Key Settings");
            lstInfo.Items.Add("Sub Keys:" + Info.SubKeyCount);
            lstInfo.Items.Add("Cipher: " + MemberToString((SymmetricEngines)Info.Description.EngineType));
            lstInfo.Items.Add("Mode: " + MemberToString((CipherModes)Info.Description.CipherType));
            lstInfo.Items.Add("Rounds: " + MemberToString((RoundCounts)Info.Description.RoundCount));
            lstInfo.Items.Add("KDF Engine: " + MemberToString((Digests)Info.Description.KdfEngine));
            lstInfo.Items.Add("Padding: " + MemberToString((PaddingModes)Info.Description.PaddingType));
            lstInfo.Items.Add("HMAC Digest:" + (Info.Description.MacSize > 0 ? MemberToString((Digests)Info.Description.MacEngine) : "None"));
            if (!string.IsNullOrEmpty(Info.Tag))
                lstInfo.Items.Add("Description: " + Info.Tag);

            lstInfo.Items.Add("");
            lstInfo.Items.Add("Key Policies");
            foreach (var item in Info.Policies)
                    lstInfo.Items.Add(MemberToString((KeyPolicies)item));
        }

        public static String MemberToString(Enum Field)
        {
            return Enum.GetName(Field.GetType(), Field);
        }

        private void OnCloseButtonClick(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}
