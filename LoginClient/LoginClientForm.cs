using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

/// <summary>
/// Author: Andrew Williamson
/// Student ID: P113357
/// 
/// AT 2 - Question 4 
/// 
/// JMC wishes to have a standard login functionality for all their 
/// terminals around the ship, this should be accomplished via logging 
/// into a central server to test user and password combinations 
/// (you must have at least one administrator password setup)
/// You must create a Server Client program it must use IPC to communicate.
/// Your program must have a login that uses standard hashing techniques.
/// 
/// </summary>
namespace LoginClient
{
    public partial class LoginClientForm : Form
    {
        private PipeClient pipeClient;

        public LoginClientForm()
        {
            InitializeComponent();
        }

        /// <summary>
        /// This method sets up the program when it first loads.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void LoginClientForm_Load(object sender, EventArgs e)
        {
            CreateNewPipeClient();
        }

        /// <summary>
        /// Create a new pipeClient and set all the handlers for the delegates.
        /// </summary>
        private void CreateNewPipeClient()
        {
            if (pipeClient != null)
            {
                pipeClient.Disconnect();
                pipeClient.MessageRecieved -= pipeClient_MessageRecieved;
                pipeClient.ServerDisconnected -= pipeClient_ServerDisconnected;
                pipeClient.UpdateTheForm -= pipeClient_UpdateTheForm;
                pipeClient = null;
            }

            pipeClient = new PipeClient();
            pipeClient.MessageRecieved += pipeClient_MessageRecieved;
            pipeClient.ServerDisconnected += pipeClient_ServerDisconnected;
            pipeClient.UpdateTheForm += pipeClient_UpdateTheForm;

            UpdateForm();
        }

        /// <summary>
        /// Methods to allow the pipeClient to use the methods on the form.
        /// </summary>
        #region HandlerMethods

        private void pipeClient_UpdateTheForm()
        {
            Invoke(new PipeClient.UpdateTheFormHandler(UpdateForm));
        }

        private void pipeClient_MessageRecieved(byte[] message)
        {
            Invoke(new PipeClient.MessageRecievedHandler(DisplayRecievedMessage),
                new object[] { message });
        }

        private void pipeClient_ServerDisconnected()
        {
            Invoke(new PipeClient.ServerDisconnectedHandler(UpdateForm));
        }
        #endregion

        /// <summary>
        /// Add the message onto a newline of the message log.
        /// </summary>
        /// <param name="message"></param>
        private void DisplayRecievedMessage(byte[] message)
        {
            Console.WriteLine(Thread.CurrentThread.ManagedThreadId + "in DisplayRecievedMessage");
            ASCIIEncoding encoder = new ASCIIEncoding();
            string str = encoder.GetString(message, 0, message.Length);

            if (str == "close")
            {
                //MessageLogTB.Text += str + "\r\n";
                pipeClient.Disconnect();
                CreateNewPipeClient();
            }
            MessageLogTB.Text += str + "\r\n";
        }

        /// <summary>
        /// Update the enabled property of the buttons on the form.
        /// Then resets the focus.
        /// </summary>
        private void UpdateForm()
        {
            bool connected = pipeClient.isConnected;
            bool loggedIn = pipeClient.isLoggedIn;

            ConnectBtn.Enabled = !connected;
            DisconnectBtn.Enabled = connected;

            
            SendBtn.Enabled = loggedIn;
            SendMessageTB.Enabled = loggedIn;
            ClearBtn.Enabled = loggedIn;

            if (connected == false)
            {
                ConnectBtn.Focus();
                LoginBtn.Enabled = connected;
            }
            else if (loggedIn == false)
            {
                AdminUsernameTB.Focus();
                LoginBtn.Enabled = !loggedIn;
            }
            else
            {
                SendMessageTB.Focus();
                LoginBtn.Enabled = !loggedIn;
            }
        }

        
        #region ButtonClickMethods

        /// <summary>
        /// Attempts to connect to the server.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ConnectBtn_Click(object sender, EventArgs e)
        {
            pipeClient.Connect(PipeNameTB.Text);

            UpdateForm();

        }

        /// <summary>
        /// Sends the user text to the server and clears the send message box.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SendBtn_Click(object sender, EventArgs e)
        {
            ASCIIEncoding encoder = new ASCIIEncoding();

            if (!String.IsNullOrWhiteSpace(SendMessageTB.Text))
            {
                pipeClient.SendMessage(encoder.GetBytes(SendMessageTB.Text));
                SendMessageTB.Clear();
            }
        }

        /// <summary>
        /// When the disconnect button is clicked the pipeclient is dicconected, 
        /// the form is updated and a new pipeclient is created.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void DisconnectBtn_Click(object sender, EventArgs e)
        {
            
            CreateNewPipeClient();
            MessageLogTB.Text += "Disconnected from the server." + "\r\n";
            UpdateForm();
        }

        /// <summary>
        /// Clears the Message log and focuses onto the send box.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ClearBtn_Click(object sender, EventArgs e)
        {
            MessageLogTB.Clear();
            SendMessageTB.Focus();
        }

        /// <summary>
        /// The method called when the Login button is called.
        /// If the username and password text boxes are filled out they are sent to the server.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void LoginBtn_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(AdminUsernameTB.Text) && !string.IsNullOrWhiteSpace(AdminPasswordTB.Text))
            {
                //pipeClient.Connect(PipeNameTB.Text);
                //ValidateAdminDetails(AdminUsernameTB.Text, AdminPasswordTB.Text);

                string adminDetails = AdminUsernameTB.Text + ',' + AdminPasswordTB.Text;
                ASCIIEncoding encoder = new ASCIIEncoding();

                pipeClient.SendMessage(encoder.GetBytes(adminDetails));
            }
            else
            {
                MessageBox.Show("Connection requires the both a username and password.", "Login Error");
            }
        }

        #endregion

        private void LoginClientForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            pipeClient.Disconnect();
        }
    }
}
