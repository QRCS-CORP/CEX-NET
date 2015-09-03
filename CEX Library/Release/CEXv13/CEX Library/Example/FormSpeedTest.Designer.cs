namespace VTDev.Projects.CEX
{
    partial class FormSpeedTest
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
            this.grpSpeed = new System.Windows.Forms.GroupBox();
            this.cbEngines = new System.Windows.Forms.ComboBox();
            this.btnSpeedTest = new System.Windows.Forms.Button();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.lblEngineTime = new System.Windows.Forms.Label();
            this.label13 = new System.Windows.Forms.Label();
            this.grpProcess = new System.Windows.Forms.GroupBox();
            this.panel2 = new System.Windows.Forms.Panel();
            this.Parallelize = new System.Windows.Forms.CheckBox();
            this.Decrypt = new System.Windows.Forms.RadioButton();
            this.Encrypt = new System.Windows.Forms.RadioButton();
            this.grpParameters = new System.Windows.Forms.GroupBox();
            this.cbCipherMode = new System.Windows.Forms.ComboBox();
            this.label7 = new System.Windows.Forms.Label();
            this.cbRounds = new System.Windows.Forms.ComboBox();
            this.cbKeySize = new System.Windows.Forms.ComboBox();
            this.label6 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.grpTestType = new System.Windows.Forms.GroupBox();
            this.panel1 = new System.Windows.Forms.Panel();
            this.ByteIo = new System.Windows.Forms.RadioButton();
            this.FileIo = new System.Windows.Forms.RadioButton();
            this.txtSizeMB = new System.Windows.Forms.TextBox();
            this.lblSize = new System.Windows.Forms.Label();
            this.grpSpeed.SuspendLayout();
            this.grpProcess.SuspendLayout();
            this.panel2.SuspendLayout();
            this.grpParameters.SuspendLayout();
            this.grpTestType.SuspendLayout();
            this.panel1.SuspendLayout();
            this.SuspendLayout();
            // 
            // grpSpeed
            // 
            this.grpSpeed.Controls.Add(this.cbEngines);
            this.grpSpeed.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.grpSpeed.Location = new System.Drawing.Point(10, 9);
            this.grpSpeed.Name = "grpSpeed";
            this.grpSpeed.Size = new System.Drawing.Size(337, 56);
            this.grpSpeed.TabIndex = 27;
            this.grpSpeed.TabStop = false;
            this.grpSpeed.Text = "Engines:";
            // 
            // cbEngines
            // 
            this.cbEngines.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbEngines.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbEngines.FormattingEnabled = true;
            this.cbEngines.Location = new System.Drawing.Point(13, 20);
            this.cbEngines.Name = "cbEngines";
            this.cbEngines.Size = new System.Drawing.Size(310, 22);
            this.cbEngines.TabIndex = 112;
            this.cbEngines.SelectedValueChanged += new System.EventHandler(this.OnEngineChanged);
            // 
            // btnSpeedTest
            // 
            this.btnSpeedTest.Font = new System.Drawing.Font("Arial", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnSpeedTest.Location = new System.Drawing.Point(275, 299);
            this.btnSpeedTest.Name = "btnSpeedTest";
            this.btnSpeedTest.Size = new System.Drawing.Size(72, 38);
            this.btnSpeedTest.TabIndex = 43;
            this.btnSpeedTest.Text = "Test";
            this.btnSpeedTest.UseVisualStyleBackColor = true;
            this.btnSpeedTest.Click += new System.EventHandler(this.OnSpeedTestClick);
            // 
            // statusStrip1
            // 
            this.statusStrip1.Location = new System.Drawing.Point(0, 355);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(360, 22);
            this.statusStrip1.SizingGrip = false;
            this.statusStrip1.TabIndex = 28;
            // 
            // lblEngineTime
            // 
            this.lblEngineTime.AutoSize = true;
            this.lblEngineTime.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblEngineTime.Location = new System.Drawing.Point(101, 360);
            this.lblEngineTime.Name = "lblEngineTime";
            this.lblEngineTime.Size = new System.Drawing.Size(22, 14);
            this.lblEngineTime.TabIndex = 36;
            this.lblEngineTime.Text = "0.0";
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label13.Location = new System.Drawing.Point(12, 360);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(94, 14);
            this.label13.TabIndex = 37;
            this.label13.Text = "Time (m:s.ms): ";
            // 
            // grpProcess
            // 
            this.grpProcess.Controls.Add(this.panel2);
            this.grpProcess.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.grpProcess.Location = new System.Drawing.Point(12, 136);
            this.grpProcess.Name = "grpProcess";
            this.grpProcess.Size = new System.Drawing.Size(336, 56);
            this.grpProcess.TabIndex = 38;
            this.grpProcess.TabStop = false;
            this.grpProcess.Text = "Process:";
            // 
            // panel2
            // 
            this.panel2.Controls.Add(this.Parallelize);
            this.panel2.Controls.Add(this.Decrypt);
            this.panel2.Controls.Add(this.Encrypt);
            this.panel2.Location = new System.Drawing.Point(6, 20);
            this.panel2.Name = "panel2";
            this.panel2.Size = new System.Drawing.Size(324, 25);
            this.panel2.TabIndex = 110;
            // 
            // Parallelize
            // 
            this.Parallelize.AutoSize = true;
            this.Parallelize.Checked = true;
            this.Parallelize.CheckState = System.Windows.Forms.CheckState.Checked;
            this.Parallelize.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Parallelize.Location = new System.Drawing.Point(231, 3);
            this.Parallelize.Name = "Parallelize";
            this.Parallelize.Size = new System.Drawing.Size(74, 18);
            this.Parallelize.TabIndex = 104;
            this.Parallelize.Text = "Parallelize";
            this.Parallelize.UseVisualStyleBackColor = true;
            this.Parallelize.CheckedChanged += new System.EventHandler(this.OnParallelChanged);
            // 
            // Decrypt
            // 
            this.Decrypt.AutoSize = true;
            this.Decrypt.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Decrypt.Location = new System.Drawing.Point(74, 3);
            this.Decrypt.Name = "Decrypt";
            this.Decrypt.Size = new System.Drawing.Size(63, 18);
            this.Decrypt.TabIndex = 103;
            this.Decrypt.Text = "Decrypt";
            this.Decrypt.UseVisualStyleBackColor = true;
            this.Decrypt.CheckedChanged += new System.EventHandler(this.OnEncryptChanged);
            // 
            // Encrypt
            // 
            this.Encrypt.AutoSize = true;
            this.Encrypt.Checked = true;
            this.Encrypt.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Encrypt.Location = new System.Drawing.Point(8, 3);
            this.Encrypt.Name = "Encrypt";
            this.Encrypt.Size = new System.Drawing.Size(62, 18);
            this.Encrypt.TabIndex = 102;
            this.Encrypt.TabStop = true;
            this.Encrypt.Text = "Encrypt";
            this.Encrypt.UseVisualStyleBackColor = true;
            this.Encrypt.CheckedChanged += new System.EventHandler(this.OnEncryptChanged);
            // 
            // grpParameters
            // 
            this.grpParameters.Controls.Add(this.cbCipherMode);
            this.grpParameters.Controls.Add(this.label7);
            this.grpParameters.Controls.Add(this.cbRounds);
            this.grpParameters.Controls.Add(this.cbKeySize);
            this.grpParameters.Controls.Add(this.label6);
            this.grpParameters.Controls.Add(this.label5);
            this.grpParameters.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.grpParameters.Location = new System.Drawing.Point(11, 71);
            this.grpParameters.Name = "grpParameters";
            this.grpParameters.Size = new System.Drawing.Size(336, 56);
            this.grpParameters.TabIndex = 39;
            this.grpParameters.TabStop = false;
            this.grpParameters.Text = "Parameters";
            // 
            // cbCipherMode
            // 
            this.cbCipherMode.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbCipherMode.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbCipherMode.FormattingEnabled = true;
            this.cbCipherMode.Location = new System.Drawing.Point(148, 20);
            this.cbCipherMode.Name = "cbCipherMode";
            this.cbCipherMode.Size = new System.Drawing.Size(56, 22);
            this.cbCipherMode.TabIndex = 113;
            this.cbCipherMode.SelectedValueChanged += new System.EventHandler(this.OnModeChanged);
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label7.Location = new System.Drawing.Point(110, 25);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(36, 14);
            this.label7.TabIndex = 114;
            this.label7.Text = "Mode:";
            // 
            // cbRounds
            // 
            this.cbRounds.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRounds.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbRounds.FormattingEnabled = true;
            this.cbRounds.Location = new System.Drawing.Point(266, 22);
            this.cbRounds.Name = "cbRounds";
            this.cbRounds.Size = new System.Drawing.Size(56, 22);
            this.cbRounds.TabIndex = 111;
            this.cbRounds.SelectedValueChanged += new System.EventHandler(this.OnRoundsCountChanged);
            // 
            // cbKeySize
            // 
            this.cbKeySize.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbKeySize.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbKeySize.FormattingEnabled = true;
            this.cbKeySize.Location = new System.Drawing.Point(40, 22);
            this.cbKeySize.Name = "cbKeySize";
            this.cbKeySize.Size = new System.Drawing.Size(56, 22);
            this.cbKeySize.TabIndex = 109;
            this.cbKeySize.SelectedValueChanged += new System.EventHandler(this.OnKeySizeChanged);
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label6.Location = new System.Drawing.Point(216, 25);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(47, 14);
            this.label6.TabIndex = 112;
            this.label6.Text = "Rounds:";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label5.Location = new System.Drawing.Point(9, 26);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(29, 14);
            this.label5.TabIndex = 110;
            this.label5.Text = "Key:";
            // 
            // grpTestType
            // 
            this.grpTestType.Controls.Add(this.panel1);
            this.grpTestType.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.grpTestType.Location = new System.Drawing.Point(12, 206);
            this.grpTestType.Name = "grpTestType";
            this.grpTestType.Size = new System.Drawing.Size(335, 71);
            this.grpTestType.TabIndex = 40;
            this.grpTestType.TabStop = false;
            this.grpTestType.Text = "Test Type:";
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.ByteIo);
            this.panel1.Controls.Add(this.FileIo);
            this.panel1.Controls.Add(this.txtSizeMB);
            this.panel1.Controls.Add(this.lblSize);
            this.panel1.Location = new System.Drawing.Point(7, 18);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(324, 48);
            this.panel1.TabIndex = 102;
            // 
            // ByteIo
            // 
            this.ByteIo.AutoSize = true;
            this.ByteIo.Checked = true;
            this.ByteIo.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ByteIo.Location = new System.Drawing.Point(7, 24);
            this.ByteIo.Name = "ByteIo";
            this.ByteIo.Size = new System.Drawing.Size(139, 18);
            this.ByteIo.TabIndex = 102;
            this.ByteIo.TabStop = true;
            this.ByteIo.Text = "Transform a Byte Array";
            this.ByteIo.UseVisualStyleBackColor = true;
            this.ByteIo.CheckedChanged += new System.EventHandler(this.OnTestTypeCheckChanged);
            // 
            // FileIo
            // 
            this.FileIo.AutoSize = true;
            this.FileIo.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.FileIo.Location = new System.Drawing.Point(7, 3);
            this.FileIo.Name = "FileIo";
            this.FileIo.Size = new System.Drawing.Size(157, 18);
            this.FileIo.TabIndex = 101;
            this.FileIo.Text = "Transform a Temporary File";
            this.FileIo.UseVisualStyleBackColor = true;
            this.FileIo.CheckedChanged += new System.EventHandler(this.OnTestTypeCheckChanged);
            // 
            // txtSizeMB
            // 
            this.txtSizeMB.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtSizeMB.Location = new System.Drawing.Point(279, 17);
            this.txtSizeMB.MaxLength = 4;
            this.txtSizeMB.Name = "txtSizeMB";
            this.txtSizeMB.Size = new System.Drawing.Size(32, 20);
            this.txtSizeMB.TabIndex = 38;
            this.txtSizeMB.Text = "10";
            // 
            // lblSize
            // 
            this.lblSize.AutoSize = true;
            this.lblSize.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblSize.Location = new System.Drawing.Point(227, 22);
            this.lblSize.Name = "lblSize";
            this.lblSize.Size = new System.Drawing.Size(49, 14);
            this.lblSize.TabIndex = 40;
            this.lblSize.Text = "Size MB:";
            // 
            // FormSpeedTest
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 14F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(360, 377);
            this.Controls.Add(this.lblEngineTime);
            this.Controls.Add(this.grpTestType);
            this.Controls.Add(this.btnSpeedTest);
            this.Controls.Add(this.grpParameters);
            this.Controls.Add(this.grpProcess);
            this.Controls.Add(this.label13);
            this.Controls.Add(this.statusStrip1);
            this.Controls.Add(this.grpSpeed);
            this.Font = new System.Drawing.Font("Arial", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "FormSpeedTest";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "CEX Speed Tests: (Compile as Release to Test!)";
            this.Load += new System.EventHandler(this.OnFormLoad);
            this.grpSpeed.ResumeLayout(false);
            this.grpProcess.ResumeLayout(false);
            this.panel2.ResumeLayout(false);
            this.panel2.PerformLayout();
            this.grpParameters.ResumeLayout(false);
            this.grpParameters.PerformLayout();
            this.grpTestType.ResumeLayout(false);
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.GroupBox grpSpeed;
        private System.Windows.Forms.Button btnSpeedTest;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.Label lblEngineTime;
        private System.Windows.Forms.Label label13;
        private System.Windows.Forms.ComboBox cbEngines;
        private System.Windows.Forms.GroupBox grpProcess;
        private System.Windows.Forms.Panel panel2;
        private System.Windows.Forms.CheckBox Parallelize;
        private System.Windows.Forms.RadioButton Decrypt;
        private System.Windows.Forms.RadioButton Encrypt;
        private System.Windows.Forms.GroupBox grpParameters;
        private System.Windows.Forms.ComboBox cbCipherMode;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.ComboBox cbRounds;
        private System.Windows.Forms.ComboBox cbKeySize;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.GroupBox grpTestType;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.RadioButton ByteIo;
        private System.Windows.Forms.RadioButton FileIo;
        private System.Windows.Forms.TextBox txtSizeMB;
        private System.Windows.Forms.Label lblSize;
    }
}