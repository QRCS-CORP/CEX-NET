namespace VTDev.Projects.CEX
{
    partial class FormMain
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(FormMain));
            this.ssStatus = new System.Windows.Forms.StatusStrip();
            this.lblStatus = new System.Windows.Forms.Label();
            this.pbStatus = new System.Windows.Forms.ProgressBar();
            this.tsMain = new System.Windows.Forms.ToolStrip();
            this.tsbKey = new System.Windows.Forms.ToolStripButton();
            this.tsbEncrypt = new System.Windows.Forms.ToolStripButton();
            this.tsbOptions = new System.Windows.Forms.ToolStripButton();
            this.tsbAbout = new System.Windows.Forms.ToolStripButton();
            this.btnEncrypt = new System.Windows.Forms.Button();
            this.txtInputFile = new System.Windows.Forms.TextBox();
            this.btnInputFile = new System.Windows.Forms.Button();
            this.txtKeyFile = new System.Windows.Forms.TextBox();
            this.btnKeyFile = new System.Windows.Forms.Button();
            this.txtOutputFile = new System.Windows.Forms.TextBox();
            this.btnOutputFile = new System.Windows.Forms.Button();
            this.pnlEncrypt = new System.Windows.Forms.Panel();
            this.btnInfo = new System.Windows.Forms.Button();
            this.label13 = new System.Windows.Forms.Label();
            this.pnlKey = new System.Windows.Forms.Panel();
            this.label19 = new System.Windows.Forms.Label();
            this.btnPolicies = new System.Windows.Forms.Button();
            this.label14 = new System.Windows.Forms.Label();
            this.txtSubKeyCount = new System.Windows.Forms.TextBox();
            this.label12 = new System.Windows.Forms.Label();
            this.cbHmac = new System.Windows.Forms.ComboBox();
            this.cbHkdf = new System.Windows.Forms.ComboBox();
            this.label10 = new System.Windows.Forms.Label();
            this.label8 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.chkSign = new System.Windows.Forms.CheckBox();
            this.cbRounds = new System.Windows.Forms.ComboBox();
            this.label6 = new System.Windows.Forms.Label();
            this.cbPaddingMode = new System.Windows.Forms.ComboBox();
            this.label5 = new System.Windows.Forms.Label();
            this.cbVectorSize = new System.Windows.Forms.ComboBox();
            this.cbKeySize = new System.Windows.Forms.ComboBox();
            this.cbCipherMode = new System.Windows.Forms.ComboBox();
            this.btnCreateKey = new System.Windows.Forms.Button();
            this.cbEngines = new System.Windows.Forms.ComboBox();
            this.label4 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.pnlOptions = new System.Windows.Forms.Panel();
            this.dtVolatileTime = new System.Windows.Forms.DateTimePicker();
            this.chkNoExport = new System.Windows.Forms.CheckBox();
            this.chkDomainRestrict = new System.Windows.Forms.CheckBox();
            this.label9 = new System.Windows.Forms.Label();
            this.chkVolatile = new System.Windows.Forms.CheckBox();
            this.chkSingleUse = new System.Windows.Forms.CheckBox();
            this.label11 = new System.Windows.Forms.Label();
            this.chkPostOverwrite = new System.Windows.Forms.CheckBox();
            this.btnGenerate = new System.Windows.Forms.Button();
            this.chkPackageAuth = new System.Windows.Forms.CheckBox();
            this.txtKeyDescription = new System.Windows.Forms.TextBox();
            this.chkNoNarrative = new System.Windows.Forms.CheckBox();
            this.ttInfo = new System.Windows.Forms.ToolTip(this.components);
            this.pnlAbout = new System.Windows.Forms.Panel();
            this.lnkGithub = new System.Windows.Forms.LinkLabel();
            this.lnkVtdev = new System.Windows.Forms.LinkLabel();
            this.lnkDocumentation = new System.Windows.Forms.LinkLabel();
            this.lnkHome = new System.Windows.Forms.LinkLabel();
            this.label15 = new System.Windows.Forms.Label();
            this.label16 = new System.Windows.Forms.Label();
            this.label17 = new System.Windows.Forms.Label();
            this.label18 = new System.Windows.Forms.Label();
            this.lblTest = new System.Windows.Forms.Label();
            this.tsMain.SuspendLayout();
            this.pnlEncrypt.SuspendLayout();
            this.pnlKey.SuspendLayout();
            this.pnlOptions.SuspendLayout();
            this.pnlAbout.SuspendLayout();
            this.SuspendLayout();
            // 
            // ssStatus
            // 
            this.ssStatus.Location = new System.Drawing.Point(0, 333);
            this.ssStatus.Name = "ssStatus";
            this.ssStatus.Size = new System.Drawing.Size(434, 22);
            this.ssStatus.SizingGrip = false;
            this.ssStatus.TabIndex = 16;
            // 
            // lblStatus
            // 
            this.lblStatus.AutoSize = true;
            this.lblStatus.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblStatus.Location = new System.Drawing.Point(13, 337);
            this.lblStatus.Name = "lblStatus";
            this.lblStatus.Size = new System.Drawing.Size(51, 14);
            this.lblStatus.TabIndex = 18;
            this.lblStatus.Text = "Waiting...";
            // 
            // pbStatus
            // 
            this.pbStatus.Location = new System.Drawing.Point(259, 336);
            this.pbStatus.Name = "pbStatus";
            this.pbStatus.Size = new System.Drawing.Size(160, 17);
            this.pbStatus.TabIndex = 17;
            this.pbStatus.Visible = false;
            // 
            // tsMain
            // 
            this.tsMain.AutoSize = false;
            this.tsMain.GripStyle = System.Windows.Forms.ToolStripGripStyle.Hidden;
            this.tsMain.ImageScalingSize = new System.Drawing.Size(36, 36);
            this.tsMain.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.tsbKey,
            this.tsbEncrypt,
            this.tsbOptions,
            this.tsbAbout});
            this.tsMain.Location = new System.Drawing.Point(0, 0);
            this.tsMain.Name = "tsMain";
            this.tsMain.Padding = new System.Windows.Forms.Padding(10, 2, 1, 1);
            this.tsMain.RenderMode = System.Windows.Forms.ToolStripRenderMode.System;
            this.tsMain.Size = new System.Drawing.Size(434, 47);
            this.tsMain.TabIndex = 24;
            this.tsMain.Text = "toolStrip1";
            // 
            // tsbKey
            // 
            this.tsbKey.AutoSize = false;
            this.tsbKey.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tsbKey.Image = ((System.Drawing.Image)(resources.GetObject("tsbKey.Image")));
            this.tsbKey.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.tsbKey.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tsbKey.Name = "tsbKey";
            this.tsbKey.Size = new System.Drawing.Size(35, 37);
            this.tsbKey.ToolTipText = "Create a Key File";
            this.tsbKey.Click += new System.EventHandler(this.OnToolButtonClick);
            // 
            // tsbEncrypt
            // 
            this.tsbEncrypt.AutoSize = false;
            this.tsbEncrypt.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tsbEncrypt.Image = ((System.Drawing.Image)(resources.GetObject("tsbEncrypt.Image")));
            this.tsbEncrypt.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.tsbEncrypt.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tsbEncrypt.Name = "tsbEncrypt";
            this.tsbEncrypt.Size = new System.Drawing.Size(35, 37);
            this.tsbEncrypt.ToolTipText = "Encrypt or Decrypt a File";
            this.tsbEncrypt.Click += new System.EventHandler(this.OnToolButtonClick);
            // 
            // tsbOptions
            // 
            this.tsbOptions.AutoSize = false;
            this.tsbOptions.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tsbOptions.Image = ((System.Drawing.Image)(resources.GetObject("tsbOptions.Image")));
            this.tsbOptions.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.tsbOptions.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tsbOptions.Name = "tsbOptions";
            this.tsbOptions.Size = new System.Drawing.Size(35, 37);
            this.tsbOptions.ToolTipText = "Set Key Attribute Options";
            this.tsbOptions.Click += new System.EventHandler(this.OnToolButtonClick);
            // 
            // tsbAbout
            // 
            this.tsbAbout.AutoSize = false;
            this.tsbAbout.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tsbAbout.Image = ((System.Drawing.Image)(resources.GetObject("tsbAbout.Image")));
            this.tsbAbout.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.tsbAbout.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tsbAbout.Name = "tsbAbout";
            this.tsbAbout.Size = new System.Drawing.Size(35, 37);
            this.tsbAbout.ToolTipText = "About CEX";
            this.tsbAbout.Click += new System.EventHandler(this.OnToolButtonClick);
            // 
            // btnEncrypt
            // 
            this.btnEncrypt.Enabled = false;
            this.btnEncrypt.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnEncrypt.Location = new System.Drawing.Point(347, 231);
            this.btnEncrypt.Name = "btnEncrypt";
            this.btnEncrypt.Size = new System.Drawing.Size(72, 38);
            this.btnEncrypt.TabIndex = 15;
            this.btnEncrypt.Text = "Encrypt";
            this.btnEncrypt.UseVisualStyleBackColor = true;
            this.btnEncrypt.Click += new System.EventHandler(this.OnEncryptFileClick);
            // 
            // txtInputFile
            // 
            this.txtInputFile.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtInputFile.Location = new System.Drawing.Point(15, 37);
            this.txtInputFile.Name = "txtInputFile";
            this.txtInputFile.ReadOnly = true;
            this.txtInputFile.Size = new System.Drawing.Size(368, 20);
            this.txtInputFile.TabIndex = 17;
            this.txtInputFile.Text = "[Select a File to Encrypt or Decrypt]";
            // 
            // btnInputFile
            // 
            this.btnInputFile.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnInputFile.Location = new System.Drawing.Point(389, 30);
            this.btnInputFile.Name = "btnInputFile";
            this.btnInputFile.Size = new System.Drawing.Size(30, 32);
            this.btnInputFile.TabIndex = 16;
            this.btnInputFile.Text = "...";
            this.ttInfo.SetToolTip(this.btnInputFile, "Select a File");
            this.btnInputFile.UseVisualStyleBackColor = true;
            this.btnInputFile.Click += new System.EventHandler(this.OnSelectInputClick);
            // 
            // txtKeyFile
            // 
            this.txtKeyFile.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtKeyFile.Location = new System.Drawing.Point(16, 127);
            this.txtKeyFile.Name = "txtKeyFile";
            this.txtKeyFile.ReadOnly = true;
            this.txtKeyFile.Size = new System.Drawing.Size(367, 20);
            this.txtKeyFile.TabIndex = 19;
            this.txtKeyFile.Text = "[Select a Key File]";
            this.txtKeyFile.TextChanged += new System.EventHandler(this.OnKeyFileTextChanged);
            // 
            // btnKeyFile
            // 
            this.btnKeyFile.Enabled = false;
            this.btnKeyFile.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnKeyFile.Location = new System.Drawing.Point(389, 122);
            this.btnKeyFile.Name = "btnKeyFile";
            this.btnKeyFile.Size = new System.Drawing.Size(30, 32);
            this.btnKeyFile.TabIndex = 18;
            this.btnKeyFile.Text = "...";
            this.ttInfo.SetToolTip(this.btnKeyFile, "Select the Key file");
            this.btnKeyFile.UseVisualStyleBackColor = true;
            this.btnKeyFile.Click += new System.EventHandler(this.OnSelectKeyClick);
            // 
            // txtOutputFile
            // 
            this.txtOutputFile.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtOutputFile.Location = new System.Drawing.Point(16, 83);
            this.txtOutputFile.Name = "txtOutputFile";
            this.txtOutputFile.ReadOnly = true;
            this.txtOutputFile.Size = new System.Drawing.Size(367, 20);
            this.txtOutputFile.TabIndex = 21;
            this.txtOutputFile.Text = "[Output File Destination]";
            // 
            // btnOutputFile
            // 
            this.btnOutputFile.Enabled = false;
            this.btnOutputFile.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnOutputFile.Location = new System.Drawing.Point(389, 77);
            this.btnOutputFile.Name = "btnOutputFile";
            this.btnOutputFile.Size = new System.Drawing.Size(30, 32);
            this.btnOutputFile.TabIndex = 20;
            this.btnOutputFile.Text = "...";
            this.ttInfo.SetToolTip(this.btnOutputFile, "Destintion and File Name of output");
            this.btnOutputFile.UseVisualStyleBackColor = true;
            this.btnOutputFile.Click += new System.EventHandler(this.OnSelectOutputClick);
            // 
            // pnlEncrypt
            // 
            this.pnlEncrypt.Controls.Add(this.btnInfo);
            this.pnlEncrypt.Controls.Add(this.label13);
            this.pnlEncrypt.Controls.Add(this.btnOutputFile);
            this.pnlEncrypt.Controls.Add(this.txtOutputFile);
            this.pnlEncrypt.Controls.Add(this.btnKeyFile);
            this.pnlEncrypt.Controls.Add(this.txtKeyFile);
            this.pnlEncrypt.Controls.Add(this.btnInputFile);
            this.pnlEncrypt.Controls.Add(this.txtInputFile);
            this.pnlEncrypt.Controls.Add(this.btnEncrypt);
            this.pnlEncrypt.Location = new System.Drawing.Point(0, 50);
            this.pnlEncrypt.Margin = new System.Windows.Forms.Padding(1, 3, 3, 3);
            this.pnlEncrypt.Name = "pnlEncrypt";
            this.pnlEncrypt.Size = new System.Drawing.Size(433, 284);
            this.pnlEncrypt.TabIndex = 32;
            // 
            // btnInfo
            // 
            this.btnInfo.Enabled = false;
            this.btnInfo.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnInfo.Location = new System.Drawing.Point(16, 153);
            this.btnInfo.Name = "btnInfo";
            this.btnInfo.Size = new System.Drawing.Size(75, 29);
            this.btnInfo.TabIndex = 54;
            this.btnInfo.Text = "Key Info";
            this.btnInfo.UseVisualStyleBackColor = true;
            this.btnInfo.Click += new System.EventHandler(this.OnInfoButtonClick);
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Font = new System.Drawing.Font("Arial", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label13.Location = new System.Drawing.Point(12, 9);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(164, 16);
            this.label13.TabIndex = 53;
            this.label13.Text = "Encrypt or Decrypt a File";
            // 
            // pnlKey
            // 
            this.pnlKey.AutoSize = true;
            this.pnlKey.Controls.Add(this.label19);
            this.pnlKey.Controls.Add(this.btnPolicies);
            this.pnlKey.Controls.Add(this.label14);
            this.pnlKey.Controls.Add(this.txtSubKeyCount);
            this.pnlKey.Controls.Add(this.label12);
            this.pnlKey.Controls.Add(this.cbHmac);
            this.pnlKey.Controls.Add(this.cbHkdf);
            this.pnlKey.Controls.Add(this.label10);
            this.pnlKey.Controls.Add(this.label8);
            this.pnlKey.Controls.Add(this.label7);
            this.pnlKey.Controls.Add(this.chkSign);
            this.pnlKey.Controls.Add(this.cbRounds);
            this.pnlKey.Controls.Add(this.label6);
            this.pnlKey.Controls.Add(this.cbPaddingMode);
            this.pnlKey.Controls.Add(this.label5);
            this.pnlKey.Controls.Add(this.cbVectorSize);
            this.pnlKey.Controls.Add(this.cbKeySize);
            this.pnlKey.Controls.Add(this.cbCipherMode);
            this.pnlKey.Controls.Add(this.btnCreateKey);
            this.pnlKey.Controls.Add(this.cbEngines);
            this.pnlKey.Controls.Add(this.label4);
            this.pnlKey.Controls.Add(this.label1);
            this.pnlKey.Controls.Add(this.label2);
            this.pnlKey.Controls.Add(this.label3);
            this.pnlKey.Location = new System.Drawing.Point(1, 50);
            this.pnlKey.Margin = new System.Windows.Forms.Padding(0, 3, 0, 3);
            this.pnlKey.Name = "pnlKey";
            this.pnlKey.Size = new System.Drawing.Size(433, 284);
            this.pnlKey.TabIndex = 30;
            // 
            // label19
            // 
            this.label19.AutoSize = true;
            this.label19.Font = new System.Drawing.Font("Arial", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label19.Location = new System.Drawing.Point(12, 9);
            this.label19.Name = "label19";
            this.label19.Size = new System.Drawing.Size(136, 16);
            this.label19.TabIndex = 70;
            this.label19.Text = "Create a Cipher Key";
            // 
            // btnPolicies
            // 
            this.btnPolicies.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnPolicies.Location = new System.Drawing.Point(15, 234);
            this.btnPolicies.Name = "btnPolicies";
            this.btnPolicies.Size = new System.Drawing.Size(130, 28);
            this.btnPolicies.TabIndex = 69;
            this.btnPolicies.Text = "Modify Key Policies";
            this.ttInfo.SetToolTip(this.btnPolicies, "Create and Modify Policies that determine how a key is processed and authenticate" +
        "d");
            this.btnPolicies.UseVisualStyleBackColor = true;
            this.btnPolicies.Click += new System.EventHandler(this.OnModifyPoliciesClick);
            // 
            // label14
            // 
            this.label14.AutoSize = true;
            this.label14.Font = new System.Drawing.Font("Arial", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label14.Location = new System.Drawing.Point(12, 175);
            this.label14.Name = "label14";
            this.label14.Size = new System.Drawing.Size(144, 15);
            this.label14.TabIndex = 68;
            this.label14.Text = "Message Authentication";
            // 
            // txtSubKeyCount
            // 
            this.txtSubKeyCount.Location = new System.Drawing.Point(337, 141);
            this.txtSubKeyCount.MaxLength = 5;
            this.txtSubKeyCount.Name = "txtSubKeyCount";
            this.txtSubKeyCount.ShortcutsEnabled = false;
            this.txtSubKeyCount.Size = new System.Drawing.Size(48, 20);
            this.txtSubKeyCount.TabIndex = 67;
            this.txtSubKeyCount.Text = "10";
            this.ttInfo.SetToolTip(this.txtSubKeyCount, "This is the number of subkeys, or unique key/iv sets in the package; determines h" +
        "ow many files can be encrypted with this key package");
            this.txtSubKeyCount.TextChanged += new System.EventHandler(this.OnSubKeyCountTextChanged);
            this.txtSubKeyCount.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.OnSubKeyCountKeyPress);
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Location = new System.Drawing.Point(13, 144);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(325, 14);
            this.label12.TabIndex = 66;
            this.label12.Text = "Select the Number of Sub Keys contained in the Key Package File:";
            // 
            // cbHmac
            // 
            this.cbHmac.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbHmac.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbHmac.FormattingEnabled = true;
            this.cbHmac.Location = new System.Drawing.Point(291, 197);
            this.cbHmac.Name = "cbHmac";
            this.cbHmac.Size = new System.Drawing.Size(93, 22);
            this.cbHmac.TabIndex = 51;
            this.ttInfo.SetToolTip(this.cbHmac, "The Digest Engine used to sign a file");
            this.cbHmac.SelectedIndexChanged += new System.EventHandler(this.OnHmacChanged);
            // 
            // cbHkdf
            // 
            this.cbHkdf.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbHkdf.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbHkdf.FormattingEnabled = true;
            this.cbHkdf.Location = new System.Drawing.Point(326, 71);
            this.cbHkdf.Name = "cbHkdf";
            this.cbHkdf.Size = new System.Drawing.Size(93, 22);
            this.cbHkdf.TabIndex = 55;
            this.ttInfo.SetToolTip(this.cbHkdf, "The digest engine used in an HX or M series cipher Key Schedule");
            this.cbHkdf.SelectedIndexChanged += new System.EventHandler(this.OnHkdfChanged);
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label10.Location = new System.Drawing.Point(323, 56);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(72, 14);
            this.label10.TabIndex = 54;
            this.label10.Text = "HKDF Engine:";
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Font = new System.Drawing.Font("Arial", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label8.Location = new System.Drawing.Point(12, 33);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(94, 15);
            this.label8.TabIndex = 52;
            this.label8.Text = "Cipher Settings";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Font = new System.Drawing.Font("Arial", 7F);
            this.label7.Location = new System.Drawing.Point(290, 183);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(77, 13);
            this.label7.TabIndex = 50;
            this.label7.Text = "HMAC Engine:";
            // 
            // chkSign
            // 
            this.chkSign.AutoSize = true;
            this.chkSign.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkSign.Location = new System.Drawing.Point(16, 201);
            this.chkSign.Name = "chkSign";
            this.chkSign.Size = new System.Drawing.Size(274, 18);
            this.chkSign.TabIndex = 36;
            this.chkSign.Text = "Sign and Verify Messages encrypted with this Key:";
            this.ttInfo.SetToolTip(this.chkSign, "Signing a message file is a way of testing the file for authenticity.");
            this.chkSign.UseVisualStyleBackColor = true;
            this.chkSign.CheckedChanged += new System.EventHandler(this.OnSigningChanged);
            // 
            // cbRounds
            // 
            this.cbRounds.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRounds.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbRounds.FormattingEnabled = true;
            this.cbRounds.Items.AddRange(new object[] {
            "R8",
            "R12",
            "R20",
            "R24"});
            this.cbRounds.Location = new System.Drawing.Point(223, 114);
            this.cbRounds.Name = "cbRounds";
            this.cbRounds.Size = new System.Drawing.Size(93, 22);
            this.cbRounds.TabIndex = 48;
            this.ttInfo.SetToolTip(this.cbRounds, "The number of Diffusion Rounds used by the Cipher Engine");
            this.cbRounds.SelectedIndexChanged += new System.EventHandler(this.OnRoundsChanged);
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label6.Location = new System.Drawing.Point(220, 99);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(47, 14);
            this.label6.TabIndex = 47;
            this.label6.Text = "Rounds:";
            // 
            // cbPaddingMode
            // 
            this.cbPaddingMode.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPaddingMode.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbPaddingMode.FormattingEnabled = true;
            this.cbPaddingMode.Items.AddRange(new object[] {
            "PKCS7",
            "X923"});
            this.cbPaddingMode.Location = new System.Drawing.Point(119, 114);
            this.cbPaddingMode.Name = "cbPaddingMode";
            this.cbPaddingMode.Size = new System.Drawing.Size(93, 22);
            this.cbPaddingMode.TabIndex = 46;
            this.ttInfo.SetToolTip(this.cbPaddingMode, "The type of Padding Mode used when encrypting with a Block Cipher");
            this.cbPaddingMode.SelectedIndexChanged += new System.EventHandler(this.OnPaddingModeChanged);
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label5.Location = new System.Drawing.Point(116, 99);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(48, 14);
            this.label5.TabIndex = 45;
            this.label5.Text = "Padding:";
            // 
            // cbVectorSize
            // 
            this.cbVectorSize.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbVectorSize.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbVectorSize.FormattingEnabled = true;
            this.cbVectorSize.Items.AddRange(new object[] {
            "B128",
            "B256",
            "B512"});
            this.cbVectorSize.Location = new System.Drawing.Point(223, 71);
            this.cbVectorSize.Name = "cbVectorSize";
            this.cbVectorSize.Size = new System.Drawing.Size(93, 22);
            this.cbVectorSize.TabIndex = 44;
            this.ttInfo.SetToolTip(this.cbVectorSize, "The size of the Initilization Vector in bits");
            this.cbVectorSize.SelectedIndexChanged += new System.EventHandler(this.OnVectorSizeChanged);
            // 
            // cbKeySize
            // 
            this.cbKeySize.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbKeySize.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbKeySize.FormattingEnabled = true;
            this.cbKeySize.Items.AddRange(new object[] {
            "K512",
            "K256",
            "K128"});
            this.cbKeySize.Location = new System.Drawing.Point(119, 71);
            this.cbKeySize.Name = "cbKeySize";
            this.cbKeySize.Size = new System.Drawing.Size(93, 22);
            this.cbKeySize.TabIndex = 43;
            this.ttInfo.SetToolTip(this.cbKeySize, "The size of the key in bits");
            this.cbKeySize.SelectedIndexChanged += new System.EventHandler(this.OnKeySizeChanged);
            // 
            // cbCipherMode
            // 
            this.cbCipherMode.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbCipherMode.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbCipherMode.FormattingEnabled = true;
            this.cbCipherMode.Items.AddRange(new object[] {
            "CBC",
            "CTR"});
            this.cbCipherMode.Location = new System.Drawing.Point(15, 114);
            this.cbCipherMode.Name = "cbCipherMode";
            this.cbCipherMode.Size = new System.Drawing.Size(93, 22);
            this.cbCipherMode.TabIndex = 42;
            this.ttInfo.SetToolTip(this.cbCipherMode, "The Cipher Mode used when encrypting with a Block Cipher");
            this.cbCipherMode.SelectedIndexChanged += new System.EventHandler(this.OnCipherModeChanged);
            // 
            // btnCreateKey
            // 
            this.btnCreateKey.Font = new System.Drawing.Font("Arial", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnCreateKey.Location = new System.Drawing.Point(347, 231);
            this.btnCreateKey.Name = "btnCreateKey";
            this.btnCreateKey.Size = new System.Drawing.Size(72, 38);
            this.btnCreateKey.TabIndex = 39;
            this.btnCreateKey.Text = "Save As";
            this.ttInfo.SetToolTip(this.btnCreateKey, "Save the Key Package File");
            this.btnCreateKey.UseVisualStyleBackColor = true;
            this.btnCreateKey.Click += new System.EventHandler(this.OnCreateKeyClick);
            // 
            // cbEngines
            // 
            this.cbEngines.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbEngines.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbEngines.FormattingEnabled = true;
            this.cbEngines.Items.AddRange(new object[] {
            "ChaCha",
            "RHX",
            "Salsa20",
            "SHX",
            "THX"});
            this.cbEngines.Location = new System.Drawing.Point(15, 71);
            this.cbEngines.Name = "cbEngines";
            this.cbEngines.Size = new System.Drawing.Size(93, 22);
            this.cbEngines.TabIndex = 37;
            this.ttInfo.SetToolTip(this.cbEngines, "The Encryption engine used to process a file");
            this.cbEngines.SelectedIndexChanged += new System.EventHandler(this.OnEngineChanged);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(220, 56);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(66, 14);
            this.label4.TabIndex = 41;
            this.label4.Text = "Vector Size:";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(116, 56);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(53, 14);
            this.label1.TabIndex = 40;
            this.label1.Text = "Key Size:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(12, 56);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(42, 14);
            this.label2.TabIndex = 38;
            this.label2.Text = "Engine:";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.Location = new System.Drawing.Point(13, 99);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(70, 14);
            this.label3.TabIndex = 35;
            this.label3.Text = "Cipher Mode:";
            // 
            // pnlOptions
            // 
            this.pnlOptions.Controls.Add(this.dtVolatileTime);
            this.pnlOptions.Controls.Add(this.chkNoExport);
            this.pnlOptions.Controls.Add(this.chkDomainRestrict);
            this.pnlOptions.Controls.Add(this.label9);
            this.pnlOptions.Controls.Add(this.chkVolatile);
            this.pnlOptions.Controls.Add(this.chkSingleUse);
            this.pnlOptions.Controls.Add(this.label11);
            this.pnlOptions.Controls.Add(this.chkPostOverwrite);
            this.pnlOptions.Controls.Add(this.btnGenerate);
            this.pnlOptions.Controls.Add(this.chkPackageAuth);
            this.pnlOptions.Controls.Add(this.txtKeyDescription);
            this.pnlOptions.Controls.Add(this.chkNoNarrative);
            this.pnlOptions.Location = new System.Drawing.Point(0, 50);
            this.pnlOptions.Name = "pnlOptions";
            this.pnlOptions.Size = new System.Drawing.Size(433, 281);
            this.pnlOptions.TabIndex = 35;
            // 
            // dtVolatileTime
            // 
            this.dtVolatileTime.CustomFormat = "yyyy/MM/dd  HH:mm:ss";
            this.dtVolatileTime.Format = System.Windows.Forms.DateTimePickerFormat.Custom;
            this.dtVolatileTime.Location = new System.Drawing.Point(185, 56);
            this.dtVolatileTime.Name = "dtVolatileTime";
            this.dtVolatileTime.Size = new System.Drawing.Size(200, 20);
            this.dtVolatileTime.TabIndex = 61;
            // 
            // chkNoExport
            // 
            this.chkNoExport.AutoSize = true;
            this.chkNoExport.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNoExport.Location = new System.Drawing.Point(15, 174);
            this.chkNoExport.Name = "chkNoExport";
            this.chkNoExport.Size = new System.Drawing.Size(352, 18);
            this.chkNoExport.TabIndex = 68;
            this.chkNoExport.Text = "Key can Not be Exported and is only available to current credentials";
            this.ttInfo.SetToolTip(this.chkNoExport, "The key package may only be used by its creator. ");
            this.chkNoExport.UseVisualStyleBackColor = true;
            this.chkNoExport.CheckStateChanged += new System.EventHandler(this.OnKeyPolicyChanged);
            // 
            // chkDomainRestrict
            // 
            this.chkDomainRestrict.AutoSize = true;
            this.chkDomainRestrict.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkDomainRestrict.Location = new System.Drawing.Point(15, 36);
            this.chkDomainRestrict.Name = "chkDomainRestrict";
            this.chkDomainRestrict.Size = new System.Drawing.Size(327, 18);
            this.chkDomainRestrict.TabIndex = 49;
            this.chkDomainRestrict.Text = "Users of this key must be on the same network as key creator";
            this.ttInfo.SetToolTip(this.chkDomainRestrict, "Only a member of the same Network Domain as the package Creator can use this Key");
            this.chkDomainRestrict.UseVisualStyleBackColor = true;
            this.chkDomainRestrict.CheckStateChanged += new System.EventHandler(this.OnKeyPolicyChanged);
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Font = new System.Drawing.Font("Arial", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label9.Location = new System.Drawing.Point(12, 9);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(86, 16);
            this.label9.TabIndex = 53;
            this.label9.Text = "Key Policies";
            // 
            // chkVolatile
            // 
            this.chkVolatile.AutoSize = true;
            this.chkVolatile.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkVolatile.Location = new System.Drawing.Point(15, 59);
            this.chkVolatile.Name = "chkVolatile";
            this.chkVolatile.Size = new System.Drawing.Size(171, 18);
            this.chkVolatile.TabIndex = 56;
            this.chkVolatile.Text = "Key is Volatile and Expires on:";
            this.ttInfo.SetToolTip(this.chkVolatile, "Key package is time sensitive. Once a Key has Expired it can no longer be used fo" +
        "r Decryption");
            this.chkVolatile.UseVisualStyleBackColor = true;
            this.chkVolatile.CheckStateChanged += new System.EventHandler(this.OnKeyPolicyChanged);
            // 
            // chkSingleUse
            // 
            this.chkSingleUse.AutoSize = true;
            this.chkSingleUse.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkSingleUse.Location = new System.Drawing.Point(15, 82);
            this.chkSingleUse.Name = "chkSingleUse";
            this.chkSingleUse.Size = new System.Drawing.Size(274, 18);
            this.chkSingleUse.TabIndex = 57;
            this.chkSingleUse.Text = "Sub Keys are only valid for one cycle of decryption";
            this.ttInfo.SetToolTip(this.chkSingleUse, "Key package subkeys are only valid for only one cycle of decryption, after which " +
        "the subkey is locked out");
            this.chkSingleUse.UseVisualStyleBackColor = true;
            this.chkSingleUse.CheckStateChanged += new System.EventHandler(this.OnKeyPolicyChanged);
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label11.Location = new System.Drawing.Point(14, 202);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(192, 14);
            this.label11.TabIndex = 65;
            this.label11.Text = "Key Description: (up to 32 characters)";
            // 
            // chkPostOverwrite
            // 
            this.chkPostOverwrite.AutoSize = true;
            this.chkPostOverwrite.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkPostOverwrite.Location = new System.Drawing.Point(15, 105);
            this.chkPostOverwrite.Name = "chkPostOverwrite";
            this.chkPostOverwrite.Size = new System.Drawing.Size(234, 18);
            this.chkPostOverwrite.TabIndex = 58;
            this.chkPostOverwrite.Text = "Erase Sub Key after each decryption cycle";
            this.ttInfo.SetToolTip(this.chkPostOverwrite, "Key package subkeys are valid for only one cycle of decryption, after which the s" +
        "ub-key set is erased in the key package file");
            this.chkPostOverwrite.UseVisualStyleBackColor = true;
            this.chkPostOverwrite.CheckStateChanged += new System.EventHandler(this.OnKeyPolicyChanged);
            // 
            // btnGenerate
            // 
            this.btnGenerate.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnGenerate.Location = new System.Drawing.Point(307, 119);
            this.btnGenerate.Name = "btnGenerate";
            this.btnGenerate.Size = new System.Drawing.Size(76, 28);
            this.btnGenerate.TabIndex = 64;
            this.btnGenerate.Text = "Generate";
            this.ttInfo.SetToolTip(this.btnGenerate, "Generate an Authentication string using a Passphrase. This Package Authentication" +
        " enables the option.");
            this.btnGenerate.UseVisualStyleBackColor = true;
            this.btnGenerate.Click += new System.EventHandler(this.OnGenerateHashClick);
            // 
            // chkPackageAuth
            // 
            this.chkPackageAuth.AutoSize = true;
            this.chkPackageAuth.Enabled = false;
            this.chkPackageAuth.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkPackageAuth.Location = new System.Drawing.Point(15, 128);
            this.chkPackageAuth.Name = "chkPackageAuth";
            this.chkPackageAuth.Size = new System.Drawing.Size(294, 18);
            this.chkPackageAuth.TabIndex = 59;
            this.chkPackageAuth.Text = "Use a hashed Key Package Authentication Passphrase:";
            this.ttInfo.SetToolTip(this.chkPackageAuth, "Uses a hashed user supplied Passphrase to uniquely identify and control access to" +
        "  a Key Package");
            this.chkPackageAuth.UseVisualStyleBackColor = true;
            this.chkPackageAuth.CheckStateChanged += new System.EventHandler(this.OnKeyPolicyChanged);
            // 
            // txtKeyDescription
            // 
            this.txtKeyDescription.Location = new System.Drawing.Point(15, 218);
            this.txtKeyDescription.MaxLength = 32;
            this.txtKeyDescription.Name = "txtKeyDescription";
            this.txtKeyDescription.Size = new System.Drawing.Size(368, 20);
            this.txtKeyDescription.TabIndex = 62;
            this.ttInfo.SetToolTip(this.txtKeyDescription, "Supply a Key Package description. Can be a friendly user name, or information abo" +
        "ut the Key Package");
            // 
            // chkNoNarrative
            // 
            this.chkNoNarrative.AutoSize = true;
            this.chkNoNarrative.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkNoNarrative.Location = new System.Drawing.Point(15, 151);
            this.chkNoNarrative.Name = "chkNoNarrative";
            this.chkNoNarrative.Size = new System.Drawing.Size(263, 18);
            this.chkNoNarrative.TabIndex = 60;
            this.chkNoNarrative.Text = "Restrict Key Header details to Creator of this Key";
            this.ttInfo.SetToolTip(this.chkNoNarrative, "An operator may be able to decrypt a file with this key, but information within t" +
        "he key package header is restricted");
            this.chkNoNarrative.UseVisualStyleBackColor = true;
            this.chkNoNarrative.CheckStateChanged += new System.EventHandler(this.OnKeyPolicyChanged);
            // 
            // ttInfo
            // 
            this.ttInfo.AutomaticDelay = 0;
            this.ttInfo.AutoPopDelay = 2000;
            this.ttInfo.InitialDelay = 2000;
            this.ttInfo.ReshowDelay = 500;
            // 
            // pnlAbout
            // 
            this.pnlAbout.Controls.Add(this.lnkGithub);
            this.pnlAbout.Controls.Add(this.lnkVtdev);
            this.pnlAbout.Controls.Add(this.lnkDocumentation);
            this.pnlAbout.Controls.Add(this.lnkHome);
            this.pnlAbout.Controls.Add(this.label15);
            this.pnlAbout.Controls.Add(this.label16);
            this.pnlAbout.Controls.Add(this.label17);
            this.pnlAbout.Controls.Add(this.label18);
            this.pnlAbout.Location = new System.Drawing.Point(0, 50);
            this.pnlAbout.Name = "pnlAbout";
            this.pnlAbout.Size = new System.Drawing.Size(433, 281);
            this.pnlAbout.TabIndex = 70;
            // 
            // lnkGithub
            // 
            this.lnkGithub.AutoSize = true;
            this.lnkGithub.LinkColor = System.Drawing.Color.DodgerBlue;
            this.lnkGithub.Location = new System.Drawing.Point(14, 134);
            this.lnkGithub.Name = "lnkGithub";
            this.lnkGithub.Size = new System.Drawing.Size(77, 14);
            this.lnkGithub.TabIndex = 16;
            this.lnkGithub.TabStop = true;
            this.lnkGithub.Text = "CEX on GitHub";
            this.lnkGithub.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.OnLinkClicked);
            // 
            // lnkVtdev
            // 
            this.lnkVtdev.AutoSize = true;
            this.lnkVtdev.LinkColor = System.Drawing.Color.DodgerBlue;
            this.lnkVtdev.Location = new System.Drawing.Point(14, 160);
            this.lnkVtdev.Name = "lnkVtdev";
            this.lnkVtdev.Size = new System.Drawing.Size(70, 14);
            this.lnkVtdev.TabIndex = 15;
            this.lnkVtdev.TabStop = true;
            this.lnkVtdev.Text = "VTDev Home";
            this.lnkVtdev.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.OnLinkClicked);
            // 
            // lnkDocumentation
            // 
            this.lnkDocumentation.AutoSize = true;
            this.lnkDocumentation.LinkColor = System.Drawing.Color.DodgerBlue;
            this.lnkDocumentation.Location = new System.Drawing.Point(14, 111);
            this.lnkDocumentation.Name = "lnkDocumentation";
            this.lnkDocumentation.Size = new System.Drawing.Size(83, 14);
            this.lnkDocumentation.TabIndex = 13;
            this.lnkDocumentation.TabStop = true;
            this.lnkDocumentation.Text = "Library API Help";
            this.lnkDocumentation.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.OnLinkClicked);
            // 
            // lnkHome
            // 
            this.lnkHome.AutoSize = true;
            this.lnkHome.LinkColor = System.Drawing.Color.DodgerBlue;
            this.lnkHome.Location = new System.Drawing.Point(14, 87);
            this.lnkHome.Name = "lnkHome";
            this.lnkHome.Size = new System.Drawing.Size(119, 14);
            this.lnkHome.TabIndex = 12;
            this.lnkHome.TabStop = true;
            this.lnkHome.Text = "CEX Project Index Page";
            this.lnkHome.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.OnLinkClicked);
            // 
            // label15
            // 
            this.label15.AutoSize = true;
            this.label15.Font = new System.Drawing.Font("Microsoft Sans Serif", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label15.ForeColor = System.Drawing.Color.Black;
            this.label15.Location = new System.Drawing.Point(160, 13);
            this.label15.Name = "label15";
            this.label15.Size = new System.Drawing.Size(63, 15);
            this.label15.TabIndex = 9;
            this.label15.Text = "V 1.5.6.0";
            // 
            // label16
            // 
            this.label16.AutoSize = true;
            this.label16.Font = new System.Drawing.Font("Segoe UI", 24F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label16.ForeColor = System.Drawing.Color.Black;
            this.label16.Location = new System.Drawing.Point(7, 5);
            this.label16.Name = "label16";
            this.label16.Size = new System.Drawing.Size(162, 45);
            this.label16.TabIndex = 8;
            this.label16.Text = "Cipher Ex";
            // 
            // label17
            // 
            this.label17.AutoSize = true;
            this.label17.ForeColor = System.Drawing.Color.Black;
            this.label17.Location = new System.Drawing.Point(80, 57);
            this.label17.Name = "label17";
            this.label17.Size = new System.Drawing.Size(72, 14);
            this.label17.TabIndex = 11;
            this.label17.Text = "May 27, 2016";
            // 
            // label18
            // 
            this.label18.AutoSize = true;
            this.label18.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label18.ForeColor = System.Drawing.Color.Black;
            this.label18.Location = new System.Drawing.Point(14, 57);
            this.label18.Name = "label18";
            this.label18.Size = new System.Drawing.Size(64, 13);
            this.label18.TabIndex = 10;
            this.label18.Text = "Released:";
            // 
            // lblTest
            // 
            this.lblTest.AutoSize = true;
            this.lblTest.Location = new System.Drawing.Point(146, 337);
            this.lblTest.Name = "lblTest";
            this.lblTest.Size = new System.Drawing.Size(16, 14);
            this.lblTest.TabIndex = 71;
            this.lblTest.Text = "...";
            // 
            // FormMain
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 14F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(434, 355);
            this.Controls.Add(this.lblTest);
            this.Controls.Add(this.tsMain);
            this.Controls.Add(this.lblStatus);
            this.Controls.Add(this.pbStatus);
            this.Controls.Add(this.ssStatus);
            this.Controls.Add(this.pnlKey);
            this.Controls.Add(this.pnlEncrypt);
            this.Controls.Add(this.pnlAbout);
            this.Controls.Add(this.pnlOptions);
            this.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "FormMain";
            this.SizeGripStyle = System.Windows.Forms.SizeGripStyle.Hide;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "CEX - Create a New Key Package";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.OnFormClose);
            this.Load += new System.EventHandler(this.OnFormLoad);
            this.tsMain.ResumeLayout(false);
            this.tsMain.PerformLayout();
            this.pnlEncrypt.ResumeLayout(false);
            this.pnlEncrypt.PerformLayout();
            this.pnlKey.ResumeLayout(false);
            this.pnlKey.PerformLayout();
            this.pnlOptions.ResumeLayout(false);
            this.pnlOptions.PerformLayout();
            this.pnlAbout.ResumeLayout(false);
            this.pnlAbout.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.StatusStrip ssStatus;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.ProgressBar pbStatus;
        private System.Windows.Forms.ToolStrip tsMain;
        private System.Windows.Forms.ToolStripButton tsbKey;
        private System.Windows.Forms.ToolStripButton tsbEncrypt;
        private System.Windows.Forms.ToolStripButton tsbOptions;
        private System.Windows.Forms.Button btnEncrypt;
        private System.Windows.Forms.TextBox txtInputFile;
        private System.Windows.Forms.Button btnInputFile;
        private System.Windows.Forms.TextBox txtKeyFile;
        private System.Windows.Forms.Button btnKeyFile;
        private System.Windows.Forms.TextBox txtOutputFile;
        private System.Windows.Forms.Button btnOutputFile;
        private System.Windows.Forms.Panel pnlEncrypt;
        private System.Windows.Forms.Label label13;
        private System.Windows.Forms.ToolStripButton tsbAbout;
        private System.Windows.Forms.Panel pnlOptions;
        private System.Windows.Forms.CheckBox chkNoExport;
        private System.Windows.Forms.CheckBox chkDomainRestrict;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.CheckBox chkVolatile;
        private System.Windows.Forms.DateTimePicker dtVolatileTime;
        private System.Windows.Forms.CheckBox chkSingleUse;
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.CheckBox chkPostOverwrite;
        private System.Windows.Forms.Button btnGenerate;
        private System.Windows.Forms.CheckBox chkPackageAuth;
        private System.Windows.Forms.TextBox txtKeyDescription;
        private System.Windows.Forms.CheckBox chkNoNarrative;
        private System.Windows.Forms.ToolTip ttInfo;
        private System.Windows.Forms.Panel pnlAbout;
        private System.Windows.Forms.LinkLabel lnkVtdev;
        private System.Windows.Forms.LinkLabel lnkDocumentation;
        private System.Windows.Forms.LinkLabel lnkHome;
        private System.Windows.Forms.Label label15;
        private System.Windows.Forms.Label label16;
        private System.Windows.Forms.Label label17;
        private System.Windows.Forms.Label label18;
        private System.Windows.Forms.LinkLabel lnkGithub;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.ComboBox cbEngines;
        private System.Windows.Forms.Button btnCreateKey;
        private System.Windows.Forms.ComboBox cbCipherMode;
        private System.Windows.Forms.ComboBox cbKeySize;
        private System.Windows.Forms.ComboBox cbVectorSize;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.ComboBox cbPaddingMode;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.ComboBox cbRounds;
        private System.Windows.Forms.CheckBox chkSign;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.ComboBox cbHkdf;
        private System.Windows.Forms.ComboBox cbHmac;
        private System.Windows.Forms.Label label12;
        private System.Windows.Forms.TextBox txtSubKeyCount;
        private System.Windows.Forms.Label label14;
        private System.Windows.Forms.Panel pnlKey;
        private System.Windows.Forms.Button btnInfo;
        private System.Windows.Forms.Button btnPolicies;
        private System.Windows.Forms.Label lblTest;
        private System.Windows.Forms.Label label19;

        public System.EventHandler mniAboutSubClick { get; set; }

        public System.EventHandler OnAboutSubClick { get; set; }
    }
}

