using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
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
    /// <summary>
    /// Allows communication between the client and server pipes.
    /// </summary>
    class PipeClient
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern SafeFileHandle CreateFile(
           String pipeName,
           uint dwDesiredAccess,
           uint dwShareMode,
           IntPtr lpSecurityAttributes,
           uint dwCreationDisposition,
           uint dwFlagsAndAttributes,
           IntPtr hTemplate);

        /// <summary>
        /// Handles the messages recieved from a server pipe.
        /// </summary>
        /// <param name="message">The byte message recieved</param>
        public delegate void MessageRecievedHandler(byte[] message);

        /// <summary>
        /// The event that is called whenever a message is recieved from the server pipe.
        /// </summary>
        public event MessageRecievedHandler MessageRecieved;

        /// <summary>
        /// Handles the server disconnected message.
        /// </summary>
        public delegate void ServerDisconnectedHandler();

        /// <summary>
        /// The Event that is called when the server pipe is severed.
        /// </summary>
        public event ServerDisconnectedHandler ServerDisconnected;

        /// <summary>
        /// Handles the client connected to the server message.
        /// </summary>
        public delegate void UpdateTheFormHandler();

        /// <summary>
        /// The event that is called when the client connects to the server.
        /// </summary>
        public event UpdateTheFormHandler UpdateTheForm;

        const int BUFFER_SIZE = 4096;

        static LinkedList<Thread> threads = new LinkedList<Thread>();
        FileStream stream;
        SafeFileHandle handle;
        Thread readThread;
        bool shouldDisconnect;

        /// <summary>
        /// Is the client connected to a server pipe.
        /// </summary>
        public bool isConnected { get; private set; }

        /// <summary>
        /// The name of the pipe connected to the server.
        /// </summary>
        public string pipeName { get; private set; }

        /// <summary>
        /// Is the client logged in as the admin.
        /// </summary>
        public bool isLoggedIn { get; private set; }

        /// <summary>
        /// The methods for accessing the 
        /// connected, pipename, and isLoggedOn properties.
        /// </summary>
        /// <returns></returns>
        #region Accessors

        //public bool isLoggedIn()
        //{
        //    return isLoggedIn;
        //}

        //private void isLoggedIn(bool isLoggedInOrNot)
        //{
        //    isLoggedIn = isLoggedInOrNot;

        //    if (isLoggedIn)
        //    {
        //        UpdateTheForm();
        //    }
        //}

        /// <summary>
        /// Returns true if client is connected to a server.
        /// </summary>
        /// <returns>Boolean</returns>
        //public bool isConnected()
        //{
        //    return isConnected;
        //}

        /// <summary>
        /// Set the value of the connected boolean.
        /// </summary>
        /// <param name="b">The new value of connected.</param>
        //private void isConnected(bool b)
        //{
        //    isConnected = b;
        //}

        /// <summary>
        /// Return the name of the pipe used to connect to the server.
        /// </summary>
        /// <returns>string</returns>
        //public string pipeName()
        //{
        //    return pipeName;
        //}

        /// <summary>
        /// Set the name of the pipe that connects to the server.
        /// </summary>
        /// <param name="newPipeName">The new pipe name.</param>
        //private void pipeName(string newPipeName)
        //{
        //    pipeName = newPipeName;
        //}

        #endregion


        #region Connection

        /// <summary>
        /// Disconnects the client from the server.
        /// </summary>
        public void Disconnect()
        {
            Console.Out.WriteLine("Connected: " + isConnected);
            //if(!isConnected)
            //{
            //    return;
            //}

            // We're no longer connected to the server.
            isConnected = false;
            pipeName = null;
            isLoggedIn = false;

            // Clean up the resources
            if (stream != null)
            {
                stream.Close();
            }

            if (handle != null)
            {
                handle.Close();
            }

            stream = null;
            handle = null;

            UpdateTheForm();

            if (readThread != null)
                    readThread.Abort();
        }

        /// <summary>
        /// Connects client to the server with the pipename.
        /// </summary>
        /// <param name="pipename">The name of the pipe to connect to.</param>
        public void Connect(string pipename)
        {
            if (isConnected)
            {
                throw new Exception("Already connected to server.");
            }

            pipeName = pipename;

            handle = CreateFile(
                pipeName,
                0xC0000000, // GENERIC_READ | GENERIC_WRITE = 0x80000000 | 0x40000000
                0,
                IntPtr.Zero,
                3,  // OPEN_EXISTING
                0x40000000, // FILE_FLAG_OVERLAPPED
                IntPtr.Zero);

            // Couldn't create a handle.
            // The server is probably not running.
            if (handle.IsInvalid)
            {
                MessageBox.Show(
                    "Unable to connect.\nTheServer may not be running.",
                    "Server connection Error.");
                return;
            }

            stream = new FileStream(handle, FileAccess.ReadWrite, BUFFER_SIZE, true);

            isConnected = true;

            // Start listening for messages.
            readThread = new Thread(Read)
            {
                IsBackground = true
            };
            shouldDisconnect = false;
            threads.AddLast(readThread);
            Console.Out.WriteLine("The number of read threads at connect: " + threads.Count);
            readThread.Start();
        }

        #endregion
        /// <summary>
        /// Takes the byte[] from the server and checks the login attempt was successful.
        /// </summary>
        /// <param name="message">Byte[] </param>
        private void ValidationResult(byte[] message)
        {
            ASCIIEncoding encoder = new ASCIIEncoding();
            string str = encoder.GetString(message, 0, message.Length);

            if (str.Equals("You are now logged in."))
            {
                isLoggedIn = true;
                UpdateTheForm();
            }
        }

        /// <summary>
        /// Read the message from the server.
        /// </summary>
        public void Read()
        {
            Console.Out.WriteLine();
            Console.Out.WriteLine("Client Read Method thread: " + Thread.CurrentThread.ManagedThreadId);
            byte[] readBuffer = new byte[BUFFER_SIZE];

            while (!shouldDisconnect)
            {
                Console.Out.WriteLine("Client Read while");
                Console.Out.WriteLine();
                Thread.Sleep(100);
                int bytesRead = 0;
                using (MemoryStream ms = new MemoryStream())
                {
                    try
                    {
                        // Read the total stream length.
                        int totalSize = stream.Read(readBuffer, 0, 4);

                        // client had disconnected.
                        if (totalSize == 0)
                        {
                            Console.Out.WriteLine("Client read break 1");
                            shouldDisconnect = true;
                            break;
                        }

                        totalSize = BitConverter.ToInt32(readBuffer, 0);

                        do
                        {
                            int numBytes = stream.Read(readBuffer, 0, Math.Min(totalSize - bytesRead, BUFFER_SIZE));

                            ms.Write(readBuffer, 0, numBytes);

                            bytesRead += numBytes;

                        } while (bytesRead < totalSize);
                        Console.Out.WriteLine("Client finished reading from server");
                        Console.Out.WriteLine();
                    }
                    catch
                    {
                        Console.Out.WriteLine("Client read break 2");
                        shouldDisconnect = true;
                        break;
                    }

                    // Client has disconnected.
                    if (bytesRead == 0)
                    {
                        Console.Out.WriteLine("Client read break 3");
                        shouldDisconnect = true;
                        break;
                    }

                    // Call message recieved event.
                    if(MessageRecieved != null)
                    {
                        Console.Out.WriteLine();
                        Console.Out.WriteLine("Client: 1 " + Thread.CurrentThread.ManagedThreadId);
                        MessageRecieved(ms.ToArray());
                        //Console.Out.WriteLine(ms.ToArray());
                        //Console.Out.WriteLine(Thread.CurrentThread.ManagedThreadId + " in read()");
                        Console.Out.WriteLine("Client: 1.5, Logged in: " + isLoggedIn + " Thread: " + Thread.CurrentThread.ManagedThreadId);
                        if (!isLoggedIn)
                        {
                            Console.Out.WriteLine("Client: 2 " + Thread.CurrentThread.ManagedThreadId);
                            //Console.Out.WriteLine();
                            //Console.Out.WriteLine("Begin validation.");
                            ValidationResult(ms.ToArray());
                            Console.Out.WriteLine("Client: 3 " + Thread.CurrentThread.ManagedThreadId);
                            Console.Out.WriteLine();
                        }
                    }
                }
            }



            // If disconnected then the disconnection was caused by the server
            // being terminated.
            //if (isConnected)
            //{
            //    // Clean up the resources.
            //    UpdateTheForm();

            //    //if (ServerDisconnected != null)
            //    //{
            //    //    ServerDisconnected();
            //    //}
            //}
            Console.Out.WriteLine();
            Console.Out.WriteLine("Calling the disconnect method");
            Disconnect();
            // 
            // Abort


        }


        /// <summary>
        /// Sends the message to the server.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public void SendMessage(byte[] message)
        {
            // Check what the two stream.write lines do.
            ASCIIEncoding encoder = new ASCIIEncoding();
            string str = encoder.GetString(message, 0, message.Length);
            
            Console.Out.WriteLine("The thread Sending the message is thread: " + Thread.CurrentThread.ManagedThreadId);
            Console.Out.WriteLine("The message sent to the Server is: " + str);

            try
            {
                // Write the entire stream length.
                stream.Write(BitConverter.GetBytes(message.Length), 0, 4);
                stream.Write(message, 0, message.Length);
                stream.Flush();
            }
            catch (Exception e)
            {
                MessageBox.Show("Failed to send the message.\n" + e, "Messaging Failure");
            }
        }
    }
}
