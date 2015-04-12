using System;
using System.Windows.Forms;

namespace VTDev.Projects.CEX
{
    public partial class FormAbout : Form
    {
        public FormAbout()
        {
            InitializeComponent();
        }

        private void OnFormLoad(object sender, EventArgs e)
        {
            
        }

        private void OnCloseClick(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}
