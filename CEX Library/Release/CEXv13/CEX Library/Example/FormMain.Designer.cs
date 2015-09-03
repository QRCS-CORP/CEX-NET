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
            this.btnEncrypt = new System.Windows.Forms.Button();
            this.grpOutput = new System.Windows.Forms.GroupBox();
            this.btnOutputFile = new System.Windows.Forms.Button();
            this.txtOutputFile = new System.Windows.Forms.TextBox();
            this.btnKeyFile = new System.Windows.Forms.Button();
            this.txtKeyFile = new System.Windows.Forms.TextBox();
            this.btnInputFile = new System.Windows.Forms.Button();
            this.txtInputFile = new System.Windows.Forms.TextBox();
            this.chkSign = new System.Windows.Forms.CheckBox();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.lblStatus = new System.Windows.Forms.Label();
            this.pbStatus = new System.Windows.Forms.ProgressBar();
            this.label2 = new System.Windows.Forms.Label();
            this.cbEngines = new System.Windows.Forms.ComboBox();
            this.grpKey = new System.Windows.Forms.GroupBox();
            this.cbRounds = new System.Windows.Forms.ComboBox();
            this.label6 = new System.Windows.Forms.Label();
            this.cbPaddingMode = new System.Windows.Forms.ComboBox();
            this.label5 = new System.Windows.Forms.Label();
            this.cbVectorSize = new System.Windows.Forms.ComboBox();
            this.cbKeySize = new System.Windows.Forms.ComboBox();
            this.cbCipherMode = new System.Windows.Forms.ComboBox();
            this.btnCreateKey = new System.Windows.Forms.Button();
            this.label4 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.mnuMain = new System.Windows.Forms.MenuStrip();
            this.mniHelp = new System.Windows.Forms.ToolStripMenuItem();
            this.mniTest = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.mniHelpSub = new System.Windows.Forms.ToolStripMenuItem();
            this.mniAboutSub = new System.Windows.Forms.ToolStripMenuItem();
            this.lblTest = new System.Windows.Forms.Label();
            this.grpOutput.SuspendLayout();
            this.grpKey.SuspendLayout();
            this.mnuMain.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnEncrypt
            // 
            this.btnEncrypt.Enabled = false;
            this.btnEncrypt.Font = new System.Drawing.Font("Arial", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnEncrypt.Location = new System.Drawing.Point(314, 156);
            this.btnEncrypt.Name = "btnEncrypt";
            this.btnEncrypt.Size = new System.Drawing.Size(72, 38);
            this.btnEncrypt.TabIndex = 0;
            this.btnEncrypt.Text = "Encrypt";
            this.btnEncrypt.UseVisualStyleBackColor = true;
            this.btnEncrypt.Click += new System.EventHandler(this.OnEncryptClick);
            // 
            // grpOutput
            // 
            this.grpOutput.Controls.Add(this.btnOutputFile);
            this.grpOutput.Controls.Add(this.txtOutputFile);
            this.grpOutput.Controls.Add(this.btnKeyFile);
            this.grpOutput.Controls.Add(this.txtKeyFile);
            this.grpOutput.Controls.Add(this.btnInputFile);
            this.grpOutput.Controls.Add(this.txtInputFile);
            this.grpOutput.Controls.Add(this.btnEncrypt);
            this.grpOutput.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.grpOutput.Location = new System.Drawing.Point(10, 184);
            this.grpOutput.Name = "grpOutput";
            this.grpOutput.Size = new System.Drawing.Size(396, 211);
            this.grpOutput.TabIndex = 7;
            this.grpOutput.TabStop = false;
            this.grpOutput.Text = "Encrypt/Decrypt";
            // 
            // btnOutputFile
            // 
            this.btnOutputFile.Enabled = false;
            this.btnOutputFile.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnOutputFile.Location = new System.Drawing.Point(356, 66);
            this.btnOutputFile.Name = "btnOutputFile";
            this.btnOutputFile.Size = new System.Drawing.Size(30, 32);
            this.btnOutputFile.TabIndex = 13;
            this.btnOutputFile.Text = "...";
            this.btnOutputFile.UseVisualStyleBackColor = true;
            this.btnOutputFile.Click += new System.EventHandler(this.OnOutputFileClick);
            // 
            // txtOutputFile
            // 
            this.txtOutputFile.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtOutputFile.Location = new System.Drawing.Point(7, 70);
            this.txtOutputFile.Name = "txtOutputFile";
            this.txtOutputFile.ReadOnly = true;
            this.txtOutputFile.Size = new System.Drawing.Size(343, 20);
            this.txtOutputFile.TabIndex = 14;
            this.txtOutputFile.Text = "[Output File Destination]";
            // 
            // btnKeyFile
            // 
            this.btnKeyFile.Enabled = false;
            this.btnKeyFile.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnKeyFile.Location = new System.Drawing.Point(356, 107);
            this.btnKeyFile.Name = "btnKeyFile";
            this.btnKeyFile.Size = new System.Drawing.Size(30, 32);
            this.btnKeyFile.TabIndex = 11;
            this.btnKeyFile.Text = "...";
            this.btnKeyFile.UseVisualStyleBackColor = true;
            this.btnKeyFile.Click += new System.EventHandler(this.OnSelectKeyClick);
            // 
            // txtKeyFile
            // 
            this.txtKeyFile.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtKeyFile.Location = new System.Drawing.Point(7, 110);
            this.txtKeyFile.Name = "txtKeyFile";
            this.txtKeyFile.ReadOnly = true;
            this.txtKeyFile.Size = new System.Drawing.Size(343, 20);
            this.txtKeyFile.TabIndex = 12;
            this.txtKeyFile.Text = "[Select a Key File]";
            // 
            // btnInputFile
            // 
            this.btnInputFile.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnInputFile.Location = new System.Drawing.Point(356, 23);
            this.btnInputFile.Name = "btnInputFile";
            this.btnInputFile.Size = new System.Drawing.Size(30, 32);
            this.btnInputFile.TabIndex = 1;
            this.btnInputFile.Text = "...";
            this.btnInputFile.UseVisualStyleBackColor = true;
            this.btnInputFile.Click += new System.EventHandler(this.OnInputFileClick);
            // 
            // txtInputFile
            // 
            this.txtInputFile.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtInputFile.Location = new System.Drawing.Point(6, 28);
            this.txtInputFile.Name = "txtInputFile";
            this.txtInputFile.ReadOnly = true;
            this.txtInputFile.Size = new System.Drawing.Size(344, 20);
            this.txtInputFile.TabIndex = 2;
            this.txtInputFile.Text = "[Select a File to Encrypt or Decrypt]";
            // 
            // chkSign
            // 
            this.chkSign.AutoSize = true;
            this.chkSign.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.chkSign.Location = new System.Drawing.Point(7, 114);
            this.chkSign.Name = "chkSign";
            this.chkSign.Size = new System.Drawing.Size(271, 19);
            this.chkSign.TabIndex = 15;
            this.chkSign.Text = "Sign and Verify Messages encrypted with this Key";
            this.chkSign.UseVisualStyleBackColor = true;
            this.chkSign.CheckedChanged += new System.EventHandler(this.OnSignCheckedChanged);
            // 
            // statusStrip1
            // 
            this.statusStrip1.Location = new System.Drawing.Point(0, 410);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(416, 22);
            this.statusStrip1.SizingGrip = false;
            this.statusStrip1.TabIndex = 16;
            // 
            // lblStatus
            // 
            this.lblStatus.AutoSize = true;
            this.lblStatus.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblStatus.Location = new System.Drawing.Point(122, 414);
            this.lblStatus.Name = "lblStatus";
            this.lblStatus.Size = new System.Drawing.Size(51, 14);
            this.lblStatus.TabIndex = 18;
            this.lblStatus.Text = "Waiting...";
            // 
            // pbStatus
            // 
            this.pbStatus.Location = new System.Drawing.Point(9, 413);
            this.pbStatus.Name = "pbStatus";
            this.pbStatus.Size = new System.Drawing.Size(108, 17);
            this.pbStatus.TabIndex = 17;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(3, 23);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(42, 14);
            this.label2.TabIndex = 18;
            this.label2.Text = "Engine:";
            // 
            // cbEngines
            // 
            this.cbEngines.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbEngines.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbEngines.FormattingEnabled = true;
            this.cbEngines.Items.AddRange(new object[] {
            "ChaCha",
            "DCS",
            "RDX",
            "RHX",
            "RSM",
            "RSX",
            "Salsa20",
            "SPX",
            "SHX",
            "TFX",
            "THX",
            "TSM",
            "Fusion"});
            this.cbEngines.Location = new System.Drawing.Point(6, 38);
            this.cbEngines.Name = "cbEngines";
            this.cbEngines.Size = new System.Drawing.Size(93, 22);
            this.cbEngines.TabIndex = 17;
            this.cbEngines.SelectedValueChanged += new System.EventHandler(this.OnEngineChanged);
            // 
            // grpKey
            // 
            this.grpKey.Controls.Add(this.chkSign);
            this.grpKey.Controls.Add(this.cbRounds);
            this.grpKey.Controls.Add(this.label6);
            this.grpKey.Controls.Add(this.cbPaddingMode);
            this.grpKey.Controls.Add(this.label5);
            this.grpKey.Controls.Add(this.cbVectorSize);
            this.grpKey.Controls.Add(this.cbKeySize);
            this.grpKey.Controls.Add(this.cbCipherMode);
            this.grpKey.Controls.Add(this.btnCreateKey);
            this.grpKey.Controls.Add(this.cbEngines);
            this.grpKey.Controls.Add(this.label4);
            this.grpKey.Controls.Add(this.label1);
            this.grpKey.Controls.Add(this.label2);
            this.grpKey.Controls.Add(this.label3);
            this.grpKey.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.grpKey.Location = new System.Drawing.Point(10, 36);
            this.grpKey.Name = "grpKey";
            this.grpKey.Size = new System.Drawing.Size(396, 142);
            this.grpKey.TabIndex = 21;
            this.grpKey.TabStop = false;
            this.grpKey.Text = "Create a Key";
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
            this.cbRounds.Location = new System.Drawing.Point(214, 81);
            this.cbRounds.Name = "cbRounds";
            this.cbRounds.Size = new System.Drawing.Size(93, 22);
            this.cbRounds.TabIndex = 31;
            this.cbRounds.SelectedIndexChanged += new System.EventHandler(this.OnRoundsChanged);
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label6.Location = new System.Drawing.Point(211, 66);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(47, 14);
            this.label6.TabIndex = 30;
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
            this.cbPaddingMode.Location = new System.Drawing.Point(110, 81);
            this.cbPaddingMode.Name = "cbPaddingMode";
            this.cbPaddingMode.Size = new System.Drawing.Size(93, 22);
            this.cbPaddingMode.TabIndex = 29;
            this.cbPaddingMode.SelectedValueChanged += new System.EventHandler(this.OnPaddingModeChanged);
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label5.Location = new System.Drawing.Point(107, 66);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(48, 14);
            this.label5.TabIndex = 28;
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
            this.cbVectorSize.Location = new System.Drawing.Point(214, 38);
            this.cbVectorSize.Name = "cbVectorSize";
            this.cbVectorSize.Size = new System.Drawing.Size(93, 22);
            this.cbVectorSize.TabIndex = 27;
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
            this.cbKeySize.Location = new System.Drawing.Point(110, 38);
            this.cbKeySize.Name = "cbKeySize";
            this.cbKeySize.Size = new System.Drawing.Size(93, 22);
            this.cbKeySize.TabIndex = 26;
            this.cbKeySize.SelectedValueChanged += new System.EventHandler(this.OnKeySizeChanged);
            // 
            // cbCipherMode
            // 
            this.cbCipherMode.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbCipherMode.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbCipherMode.FormattingEnabled = true;
            this.cbCipherMode.Items.AddRange(new object[] {
            "CBC",
            "CTR"});
            this.cbCipherMode.Location = new System.Drawing.Point(6, 81);
            this.cbCipherMode.Name = "cbCipherMode";
            this.cbCipherMode.Size = new System.Drawing.Size(93, 22);
            this.cbCipherMode.TabIndex = 25;
            this.cbCipherMode.SelectedValueChanged += new System.EventHandler(this.OnCipherModeChanged);
            // 
            // btnCreateKey
            // 
            this.btnCreateKey.Font = new System.Drawing.Font("Arial", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnCreateKey.Location = new System.Drawing.Point(314, 81);
            this.btnCreateKey.Name = "btnCreateKey";
            this.btnCreateKey.Size = new System.Drawing.Size(72, 38);
            this.btnCreateKey.TabIndex = 19;
            this.btnCreateKey.Text = "Save As";
            this.btnCreateKey.UseVisualStyleBackColor = true;
            this.btnCreateKey.Click += new System.EventHandler(this.OnKeyCreateClick);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(211, 23);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(66, 14);
            this.label4.TabIndex = 24;
            this.label4.Text = "Vector Size:";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(107, 23);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(53, 14);
            this.label1.TabIndex = 21;
            this.label1.Text = "Key Size:";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.Location = new System.Drawing.Point(4, 66);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(70, 14);
            this.label3.TabIndex = 14;
            this.label3.Text = "Cipher Mode:";
            // 
            // mnuMain
            // 
            this.mnuMain.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.mnuMain.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mniHelp});
            this.mnuMain.Location = new System.Drawing.Point(0, 0);
            this.mnuMain.Name = "mnuMain";
            this.mnuMain.Size = new System.Drawing.Size(416, 24);
            this.mnuMain.TabIndex = 22;
            this.mnuMain.Text = "menuStrip1";
            // 
            // mniHelp
            // 
            this.mniHelp.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mniTest,
            this.toolStripSeparator1,
            this.mniHelpSub,
            this.mniAboutSub});
            this.mniHelp.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.mniHelp.Name = "mniHelp";
            this.mniHelp.Size = new System.Drawing.Size(59, 20);
            this.mniHelp.Text = "Program";
            // 
            // mniTest
            // 
            this.mniTest.Name = "mniTest";
            this.mniTest.Size = new System.Drawing.Size(152, 22);
            this.mniTest.Text = "Speed Test";
            this.mniTest.Click += new System.EventHandler(this.OnMenuSpeedTestClick);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(149, 6);
            // 
            // mniHelpSub
            // 
            this.mniHelpSub.Name = "mniHelpSub";
            this.mniHelpSub.Size = new System.Drawing.Size(152, 22);
            this.mniHelpSub.Text = "Help";
            this.mniHelpSub.Click += new System.EventHandler(this.OnMenuHelpSubClick);
            // 
            // mniAboutSub
            // 
            this.mniAboutSub.Name = "mniAboutSub";
            this.mniAboutSub.Size = new System.Drawing.Size(152, 22);
            this.mniAboutSub.Text = "About";
            this.mniAboutSub.Click += new System.EventHandler(this.OnMenuAboutSubClick);
            // 
            // lblTest
            // 
            this.lblTest.AutoSize = true;
            this.lblTest.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblTest.Location = new System.Drawing.Point(260, 412);
            this.lblTest.Name = "lblTest";
            this.lblTest.Size = new System.Drawing.Size(16, 14);
            this.lblTest.TabIndex = 23;
            this.lblTest.Text = "...";
            // 
            // FormMain
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 14F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(416, 432);
            this.Controls.Add(this.lblStatus);
            this.Controls.Add(this.lblTest);
            this.Controls.Add(this.grpKey);
            this.Controls.Add(this.pbStatus);
            this.Controls.Add(this.statusStrip1);
            this.Controls.Add(this.mnuMain);
            this.Controls.Add(this.grpOutput);
            this.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.MainMenuStrip = this.mnuMain;
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(432, 479);
            this.MinimizeBox = false;
            this.MinimumSize = new System.Drawing.Size(432, 479);
            this.Name = "FormMain";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "VTDev - CEX";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.OnFormClose);
            this.Load += new System.EventHandler(this.OnFormLoad);
            this.grpOutput.ResumeLayout(false);
            this.grpOutput.PerformLayout();
            this.grpKey.ResumeLayout(false);
            this.grpKey.PerformLayout();
            this.mnuMain.ResumeLayout(false);
            this.mnuMain.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button btnEncrypt;
        private System.Windows.Forms.GroupBox grpOutput;
        private System.Windows.Forms.Button btnInputFile;
        private System.Windows.Forms.TextBox txtInputFile;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.ProgressBar pbStatus;
        private System.Windows.Forms.Button btnKeyFile;
        private System.Windows.Forms.TextBox txtKeyFile;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.ComboBox cbEngines;
        private System.Windows.Forms.GroupBox grpKey;
        private System.Windows.Forms.ComboBox cbVectorSize;
        private System.Windows.Forms.ComboBox cbKeySize;
        private System.Windows.Forms.ComboBox cbCipherMode;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button btnCreateKey;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Button btnOutputFile;
        private System.Windows.Forms.TextBox txtOutputFile;
        private System.Windows.Forms.ComboBox cbPaddingMode;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.MenuStrip mnuMain;
        private System.Windows.Forms.ToolStripMenuItem mniHelp;
        private System.Windows.Forms.CheckBox chkSign;
        private System.Windows.Forms.ComboBox cbRounds;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label lblTest;
        private System.Windows.Forms.ToolStripMenuItem mniHelpSub;
        private System.Windows.Forms.ToolStripMenuItem mniAboutSub;
        private System.Windows.Forms.ToolStripMenuItem mniTest;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;

        public System.EventHandler mniAboutSubClick { get; set; }

        public System.EventHandler OnAboutSubClick { get; set; }
    }
}

