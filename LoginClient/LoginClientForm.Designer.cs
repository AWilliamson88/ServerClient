
namespace LoginClient
{
    partial class LoginClientForm
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
            this.AdminPasswordLabel = new System.Windows.Forms.Label();
            this.AdminUsernameLabel = new System.Windows.Forms.Label();
            this.AdminUsernameTB = new System.Windows.Forms.TextBox();
            this.AdminPasswordTB = new System.Windows.Forms.TextBox();
            this.MessageLogTB = new System.Windows.Forms.TextBox();
            this.SendMessageLabel = new System.Windows.Forms.Label();
            this.PipeNameLabel = new System.Windows.Forms.Label();
            this.PipeNameTB = new System.Windows.Forms.TextBox();
            this.ClearBtn = new System.Windows.Forms.Button();
            this.SendBtn = new System.Windows.Forms.Button();
            this.SendMessageTB = new System.Windows.Forms.TextBox();
            this.MessageLogLabel = new System.Windows.Forms.Label();
            this.ConnectBtn = new System.Windows.Forms.Button();
            this.DisconnectBtn = new System.Windows.Forms.Button();
            this.LoginBtn = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // AdminPasswordLabel
            // 
            this.AdminPasswordLabel.AutoSize = true;
            this.AdminPasswordLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AdminPasswordLabel.Location = new System.Drawing.Point(400, 127);
            this.AdminPasswordLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.AdminPasswordLabel.Name = "AdminPasswordLabel";
            this.AdminPasswordLabel.Size = new System.Drawing.Size(82, 20);
            this.AdminPasswordLabel.TabIndex = 12;
            this.AdminPasswordLabel.Text = "Password:";
            // 
            // AdminUsernameLabel
            // 
            this.AdminUsernameLabel.AutoSize = true;
            this.AdminUsernameLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AdminUsernameLabel.Location = new System.Drawing.Point(259, 127);
            this.AdminUsernameLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.AdminUsernameLabel.Name = "AdminUsernameLabel";
            this.AdminUsernameLabel.Size = new System.Drawing.Size(87, 20);
            this.AdminUsernameLabel.TabIndex = 11;
            this.AdminUsernameLabel.Text = "Username:";
            // 
            // AdminUsernameTB
            // 
            this.AdminUsernameTB.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AdminUsernameTB.Location = new System.Drawing.Point(259, 150);
            this.AdminUsernameTB.Margin = new System.Windows.Forms.Padding(4);
            this.AdminUsernameTB.Name = "AdminUsernameTB";
            this.AdminUsernameTB.Size = new System.Drawing.Size(132, 26);
            this.AdminUsernameTB.TabIndex = 9;
            // 
            // AdminPasswordTB
            // 
            this.AdminPasswordTB.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AdminPasswordTB.Location = new System.Drawing.Point(400, 150);
            this.AdminPasswordTB.Margin = new System.Windows.Forms.Padding(4);
            this.AdminPasswordTB.Name = "AdminPasswordTB";
            this.AdminPasswordTB.Size = new System.Drawing.Size(132, 26);
            this.AdminPasswordTB.TabIndex = 10;
            // 
            // MessageLogTB
            // 
            this.MessageLogTB.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.MessageLogTB.Location = new System.Drawing.Point(13, 198);
            this.MessageLogTB.Margin = new System.Windows.Forms.Padding(4);
            this.MessageLogTB.Multiline = true;
            this.MessageLogTB.Name = "MessageLogTB";
            this.MessageLogTB.ReadOnly = true;
            this.MessageLogTB.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.MessageLogTB.Size = new System.Drawing.Size(520, 201);
            this.MessageLogTB.TabIndex = 5;
            // 
            // SendMessageLabel
            // 
            this.SendMessageLabel.AutoSize = true;
            this.SendMessageLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SendMessageLabel.Location = new System.Drawing.Point(13, 451);
            this.SendMessageLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.SendMessageLabel.Name = "SendMessageLabel";
            this.SendMessageLabel.Size = new System.Drawing.Size(106, 17);
            this.SendMessageLabel.TabIndex = 17;
            this.SendMessageLabel.Text = "Send Message:";
            // 
            // PipeNameLabel
            // 
            this.PipeNameLabel.AutoSize = true;
            this.PipeNameLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.PipeNameLabel.Location = new System.Drawing.Point(10, 20);
            this.PipeNameLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.PipeNameLabel.Name = "PipeNameLabel";
            this.PipeNameLabel.Size = new System.Drawing.Size(77, 17);
            this.PipeNameLabel.TabIndex = 16;
            this.PipeNameLabel.Text = "PipeName:";
            // 
            // PipeNameTB
            // 
            this.PipeNameTB.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.PipeNameTB.Location = new System.Drawing.Point(95, 17);
            this.PipeNameTB.Margin = new System.Windows.Forms.Padding(4);
            this.PipeNameTB.Name = "PipeNameTB";
            this.PipeNameTB.Size = new System.Drawing.Size(438, 23);
            this.PipeNameTB.TabIndex = 15;
            this.PipeNameTB.Text = "\\\\.\\pipe\\myNamedPipe";
            // 
            // ClearBtn
            // 
            this.ClearBtn.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ClearBtn.Location = new System.Drawing.Point(403, 407);
            this.ClearBtn.Margin = new System.Windows.Forms.Padding(4);
            this.ClearBtn.Name = "ClearBtn";
            this.ClearBtn.Size = new System.Drawing.Size(130, 36);
            this.ClearBtn.TabIndex = 14;
            this.ClearBtn.Text = "Clear";
            this.ClearBtn.UseVisualStyleBackColor = true;
            this.ClearBtn.Click += new System.EventHandler(this.ClearBtn_Click);
            // 
            // SendBtn
            // 
            this.SendBtn.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SendBtn.Location = new System.Drawing.Point(400, 627);
            this.SendBtn.Margin = new System.Windows.Forms.Padding(4);
            this.SendBtn.Name = "SendBtn";
            this.SendBtn.Size = new System.Drawing.Size(133, 36);
            this.SendBtn.TabIndex = 13;
            this.SendBtn.Text = "Send";
            this.SendBtn.UseVisualStyleBackColor = true;
            this.SendBtn.Click += new System.EventHandler(this.SendBtn_Click);
            // 
            // SendMessageTB
            // 
            this.SendMessageTB.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SendMessageTB.Location = new System.Drawing.Point(13, 472);
            this.SendMessageTB.Margin = new System.Windows.Forms.Padding(4);
            this.SendMessageTB.Multiline = true;
            this.SendMessageTB.Name = "SendMessageTB";
            this.SendMessageTB.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.SendMessageTB.Size = new System.Drawing.Size(520, 147);
            this.SendMessageTB.TabIndex = 12;
            // 
            // MessageLogLabel
            // 
            this.MessageLogLabel.AutoSize = true;
            this.MessageLogLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.MessageLogLabel.Location = new System.Drawing.Point(10, 173);
            this.MessageLogLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.MessageLogLabel.Name = "MessageLogLabel";
            this.MessageLogLabel.Size = new System.Drawing.Size(97, 17);
            this.MessageLogLabel.TabIndex = 19;
            this.MessageLogLabel.Text = "Message Log:";
            // 
            // ConnectBtn
            // 
            this.ConnectBtn.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ConnectBtn.Location = new System.Drawing.Point(13, 59);
            this.ConnectBtn.Name = "ConnectBtn";
            this.ConnectBtn.Size = new System.Drawing.Size(91, 26);
            this.ConnectBtn.TabIndex = 20;
            this.ConnectBtn.Text = "Connect";
            this.ConnectBtn.UseVisualStyleBackColor = true;
            this.ConnectBtn.Click += new System.EventHandler(this.ConnectBtn_Click);
            // 
            // DisconnectBtn
            // 
            this.DisconnectBtn.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.DisconnectBtn.Location = new System.Drawing.Point(241, 59);
            this.DisconnectBtn.Name = "DisconnectBtn";
            this.DisconnectBtn.Size = new System.Drawing.Size(91, 26);
            this.DisconnectBtn.TabIndex = 21;
            this.DisconnectBtn.Text = "Disconnect";
            this.DisconnectBtn.UseVisualStyleBackColor = true;
            this.DisconnectBtn.Click += new System.EventHandler(this.DisconnectBtn_Click);
            // 
            // LoginBtn
            // 
            this.LoginBtn.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.LoginBtn.Location = new System.Drawing.Point(120, 59);
            this.LoginBtn.Name = "LoginBtn";
            this.LoginBtn.Size = new System.Drawing.Size(91, 26);
            this.LoginBtn.TabIndex = 22;
            this.LoginBtn.Text = "Login";
            this.LoginBtn.UseVisualStyleBackColor = true;
            this.LoginBtn.Click += new System.EventHandler(this.LoginBtn_Click);
            // 
            // LoginClientForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(548, 676);
            this.Controls.Add(this.AdminPasswordLabel);
            this.Controls.Add(this.AdminUsernameLabel);
            this.Controls.Add(this.LoginBtn);
            this.Controls.Add(this.AdminUsernameTB);
            this.Controls.Add(this.DisconnectBtn);
            this.Controls.Add(this.AdminPasswordTB);
            this.Controls.Add(this.ConnectBtn);
            this.Controls.Add(this.MessageLogLabel);
            this.Controls.Add(this.SendMessageLabel);
            this.Controls.Add(this.PipeNameLabel);
            this.Controls.Add(this.PipeNameTB);
            this.Controls.Add(this.ClearBtn);
            this.Controls.Add(this.SendBtn);
            this.Controls.Add(this.SendMessageTB);
            this.Controls.Add(this.MessageLogTB);
            this.Name = "LoginClientForm";
            this.Text = "Client";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.LoginClientForm_FormClosing);
            this.Load += new System.EventHandler(this.LoginClientForm_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox MessageLogTB;
        private System.Windows.Forms.Label AdminPasswordLabel;
        private System.Windows.Forms.Label AdminUsernameLabel;
        private System.Windows.Forms.TextBox AdminUsernameTB;
        private System.Windows.Forms.TextBox AdminPasswordTB;
        private System.Windows.Forms.Label SendMessageLabel;
        private System.Windows.Forms.Label PipeNameLabel;
        private System.Windows.Forms.TextBox PipeNameTB;
        private System.Windows.Forms.Button ClearBtn;
        private System.Windows.Forms.Button SendBtn;
        private System.Windows.Forms.TextBox SendMessageTB;
        private System.Windows.Forms.Label MessageLogLabel;
        private System.Windows.Forms.Button ConnectBtn;
        private System.Windows.Forms.Button DisconnectBtn;
        private System.Windows.Forms.Button LoginBtn;
    }
}

