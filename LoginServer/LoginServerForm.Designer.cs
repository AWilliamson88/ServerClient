
namespace LoginServer
{
    partial class LoginServerForm
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
            System.Windows.Forms.GroupBox AdminDetailsGP;
            this.AdminPasswordLabel = new System.Windows.Forms.Label();
            this.AdminUsernameLabel = new System.Windows.Forms.Label();
            this.AdminUsernameTB = new System.Windows.Forms.TextBox();
            this.AdminPasswordTB = new System.Windows.Forms.TextBox();
            this.StartBtn = new System.Windows.Forms.Button();
            this.SendMessageTB = new System.Windows.Forms.TextBox();
            this.SendBtn = new System.Windows.Forms.Button();
            this.ClearBtn = new System.Windows.Forms.Button();
            this.MessageLogTB = new System.Windows.Forms.TextBox();
            this.PipeNameTB = new System.Windows.Forms.TextBox();
            this.PipeNameLabel = new System.Windows.Forms.Label();
            this.MessageLogLabel = new System.Windows.Forms.Label();
            this.SendMessageLabel = new System.Windows.Forms.Label();
            AdminDetailsGP = new System.Windows.Forms.GroupBox();
            AdminDetailsGP.SuspendLayout();
            this.SuspendLayout();
            // 
            // AdminDetailsGP
            // 
            AdminDetailsGP.Controls.Add(this.AdminPasswordLabel);
            AdminDetailsGP.Controls.Add(this.AdminUsernameLabel);
            AdminDetailsGP.Controls.Add(this.AdminUsernameTB);
            AdminDetailsGP.Controls.Add(this.AdminPasswordTB);
            AdminDetailsGP.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            AdminDetailsGP.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            AdminDetailsGP.Location = new System.Drawing.Point(218, 84);
            AdminDetailsGP.Margin = new System.Windows.Forms.Padding(4);
            AdminDetailsGP.Name = "AdminDetailsGP";
            AdminDetailsGP.Padding = new System.Windows.Forms.Padding(4);
            AdminDetailsGP.Size = new System.Drawing.Size(315, 98);
            AdminDetailsGP.TabIndex = 11;
            AdminDetailsGP.TabStop = false;
            AdminDetailsGP.Text = "Admin Account";
            // 
            // AdminPasswordLabel
            // 
            this.AdminPasswordLabel.AutoSize = true;
            this.AdminPasswordLabel.Location = new System.Drawing.Point(161, 28);
            this.AdminPasswordLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.AdminPasswordLabel.Name = "AdminPasswordLabel";
            this.AdminPasswordLabel.Size = new System.Drawing.Size(73, 17);
            this.AdminPasswordLabel.TabIndex = 12;
            this.AdminPasswordLabel.Text = "Password:";
            // 
            // AdminUsernameLabel
            // 
            this.AdminUsernameLabel.AutoSize = true;
            this.AdminUsernameLabel.Location = new System.Drawing.Point(20, 28);
            this.AdminUsernameLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.AdminUsernameLabel.Name = "AdminUsernameLabel";
            this.AdminUsernameLabel.Size = new System.Drawing.Size(77, 17);
            this.AdminUsernameLabel.TabIndex = 11;
            this.AdminUsernameLabel.Text = "Username:";
            // 
            // AdminUsernameTB
            // 
            this.AdminUsernameTB.Location = new System.Drawing.Point(20, 51);
            this.AdminUsernameTB.Margin = new System.Windows.Forms.Padding(4);
            this.AdminUsernameTB.Name = "AdminUsernameTB";
            this.AdminUsernameTB.Size = new System.Drawing.Size(132, 23);
            this.AdminUsernameTB.TabIndex = 9;
            this.AdminUsernameTB.Text = "NotAdmin";
            // 
            // AdminPasswordTB
            // 
            this.AdminPasswordTB.Location = new System.Drawing.Point(161, 51);
            this.AdminPasswordTB.Margin = new System.Windows.Forms.Padding(4);
            this.AdminPasswordTB.Name = "AdminPasswordTB";
            this.AdminPasswordTB.Size = new System.Drawing.Size(132, 23);
            this.AdminPasswordTB.TabIndex = 10;
            this.AdminPasswordTB.Text = "Vitamins";
            // 
            // StartBtn
            // 
            this.StartBtn.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.StartBtn.Location = new System.Drawing.Point(13, 56);
            this.StartBtn.Margin = new System.Windows.Forms.Padding(4);
            this.StartBtn.Name = "StartBtn";
            this.StartBtn.Size = new System.Drawing.Size(130, 36);
            this.StartBtn.TabIndex = 0;
            this.StartBtn.Text = "Start Server";
            this.StartBtn.UseVisualStyleBackColor = true;
            this.StartBtn.Click += new System.EventHandler(this.StartBtn_Click);
            // 
            // SendMessageTB
            // 
            this.SendMessageTB.Location = new System.Drawing.Point(13, 480);
            this.SendMessageTB.Margin = new System.Windows.Forms.Padding(4);
            this.SendMessageTB.Multiline = true;
            this.SendMessageTB.Name = "SendMessageTB";
            this.SendMessageTB.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.SendMessageTB.Size = new System.Drawing.Size(520, 147);
            this.SendMessageTB.TabIndex = 1;
            // 
            // SendBtn
            // 
            this.SendBtn.Location = new System.Drawing.Point(403, 636);
            this.SendBtn.Margin = new System.Windows.Forms.Padding(4);
            this.SendBtn.Name = "SendBtn";
            this.SendBtn.Size = new System.Drawing.Size(133, 36);
            this.SendBtn.TabIndex = 2;
            this.SendBtn.Text = "Send";
            this.SendBtn.UseVisualStyleBackColor = true;
            this.SendBtn.Click += new System.EventHandler(this.SendBtn_Click);
            // 
            // ClearBtn
            // 
            this.ClearBtn.Location = new System.Drawing.Point(406, 410);
            this.ClearBtn.Margin = new System.Windows.Forms.Padding(4);
            this.ClearBtn.Name = "ClearBtn";
            this.ClearBtn.Size = new System.Drawing.Size(130, 36);
            this.ClearBtn.TabIndex = 3;
            this.ClearBtn.Text = "Clear";
            this.ClearBtn.UseVisualStyleBackColor = true;
            this.ClearBtn.Click += new System.EventHandler(this.ClearBtn_Click);
            // 
            // MessageLogTB
            // 
            this.MessageLogTB.Location = new System.Drawing.Point(13, 200);
            this.MessageLogTB.Margin = new System.Windows.Forms.Padding(4);
            this.MessageLogTB.Multiline = true;
            this.MessageLogTB.Name = "MessageLogTB";
            this.MessageLogTB.ReadOnly = true;
            this.MessageLogTB.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.MessageLogTB.Size = new System.Drawing.Size(520, 202);
            this.MessageLogTB.TabIndex = 4;
            // 
            // PipeNameTB
            // 
            this.PipeNameTB.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.PipeNameTB.Location = new System.Drawing.Point(98, 25);
            this.PipeNameTB.Margin = new System.Windows.Forms.Padding(4);
            this.PipeNameTB.Name = "PipeNameTB";
            this.PipeNameTB.Size = new System.Drawing.Size(428, 23);
            this.PipeNameTB.TabIndex = 5;
            this.PipeNameTB.Text = "\\\\.\\pipe\\myNamedPipe";
            // 
            // PipeNameLabel
            // 
            this.PipeNameLabel.AutoSize = true;
            this.PipeNameLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.PipeNameLabel.Location = new System.Drawing.Point(13, 28);
            this.PipeNameLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.PipeNameLabel.Name = "PipeNameLabel";
            this.PipeNameLabel.Size = new System.Drawing.Size(77, 17);
            this.PipeNameLabel.TabIndex = 6;
            this.PipeNameLabel.Text = "PipeName:";
            // 
            // MessageLogLabel
            // 
            this.MessageLogLabel.AutoSize = true;
            this.MessageLogLabel.Location = new System.Drawing.Point(10, 179);
            this.MessageLogLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.MessageLogLabel.Name = "MessageLogLabel";
            this.MessageLogLabel.Size = new System.Drawing.Size(97, 17);
            this.MessageLogLabel.TabIndex = 7;
            this.MessageLogLabel.Text = "Message Log:";
            // 
            // SendMessageLabel
            // 
            this.SendMessageLabel.AutoSize = true;
            this.SendMessageLabel.Location = new System.Drawing.Point(10, 459);
            this.SendMessageLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.SendMessageLabel.Name = "SendMessageLabel";
            this.SendMessageLabel.Size = new System.Drawing.Size(106, 17);
            this.SendMessageLabel.TabIndex = 8;
            this.SendMessageLabel.Text = "Send Message:";
            // 
            // LoginServerForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(549, 687);
            this.Controls.Add(AdminDetailsGP);
            this.Controls.Add(this.SendMessageLabel);
            this.Controls.Add(this.MessageLogLabel);
            this.Controls.Add(this.PipeNameLabel);
            this.Controls.Add(this.PipeNameTB);
            this.Controls.Add(this.MessageLogTB);
            this.Controls.Add(this.ClearBtn);
            this.Controls.Add(this.SendBtn);
            this.Controls.Add(this.SendMessageTB);
            this.Controls.Add(this.StartBtn);
            this.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Margin = new System.Windows.Forms.Padding(4);
            this.Name = "LoginServerForm";
            this.Text = "Server";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.LoginServerForm_FormClosing);
            this.Load += new System.EventHandler(this.LoginServerForm_Load);
            AdminDetailsGP.ResumeLayout(false);
            AdminDetailsGP.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button StartBtn;
        private System.Windows.Forms.TextBox SendMessageTB;
        private System.Windows.Forms.Button SendBtn;
        private System.Windows.Forms.Button ClearBtn;
        private System.Windows.Forms.TextBox MessageLogTB;
        private System.Windows.Forms.TextBox PipeNameTB;
        private System.Windows.Forms.Label PipeNameLabel;
        private System.Windows.Forms.Label MessageLogLabel;
        private System.Windows.Forms.Label SendMessageLabel;
        private System.Windows.Forms.TextBox AdminUsernameTB;
        private System.Windows.Forms.TextBox AdminPasswordTB;
        private System.Windows.Forms.Label AdminPasswordLabel;
        private System.Windows.Forms.Label AdminUsernameLabel;
    }
}

