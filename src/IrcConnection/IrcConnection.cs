/*
 * $Id$
 * $URL$
 * $Rev$
 * $Author$
 * $Date$
 *
 * SmartIrc4net - the IRC library for .NET/C# <http://smartirc4net.sf.net>
 *
 * Copyright (c) 2003-2009 Mirco Bauer <meebey@meebey.net> <http://www.meebey.net>
 * Copyright (c) 2008-2009 Thomas Bruderer <apophis@apophis.ch>
 * 
 * Full LGPL License: <http://www.gnu.org/licenses/lgpl.txt>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Threading;
using Starksoft.Net.Proxy;

using Manos;
using Manos.IO;

namespace Meebey.SmartIrc4net
{
    public static class ManosExtensions
    {
        public static void Write(this Stream stream, byte[] data, Action action)
        {
            stream.Write(data, 0, data.Length, action);
        }

        public static void Write(this Stream stream, byte[] data, int start, Action action)
        {
            stream.Write(data, start, data.Length - start, action);
        }

        public static void Write(this Stream stream, byte[] data, int start, int count, Action action)
        {
            stream.Write(new ByteBuffer(data, start, count), action);
        }

        public static void Write(this Stream stream, ByteBuffer data, Action action)
        {
            CallbackCollection callbacks = new CallbackCollection();
            callbacks.Add(data, action);
            stream.Write(callbacks);
        }
    }

    public class CallbackCollection : IEnumerable<ByteBuffer>
    {
        protected List<Tuple<ByteBuffer, Action>> elements = new List<Tuple<ByteBuffer, Action>>();

        public CallbackCollection()
        {
        }

        public void Add(byte[] data, Action action)
        {
            Add(new ByteBuffer(data, 0, data.Length), action);
        }

        public void Add(ByteBuffer data, Action action)
        {
            elements.Add(Tuple.Create(data, action));
        }

        #region IEnumerable[ByteBuffer] implementation
        public IEnumerator<ByteBuffer> GetEnumerator()
        {
            foreach (var element in elements) {
                element.Item2();
                yield return element.Item1;
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return (IEnumerator)this.GetEnumerator();
        }
        #endregion
    }

    public class IrcConnection
    {
        public Socket Socket { get; protected set; }

        public Context Context { get; protected set; }

        private DateTime LastPingSent { get; set; }

        private DateTime LastPongReceived { get; set; }

        /// <summary>
        /// Encoding which is used for reading and writing to the socket
        /// Default: encoding of the system
        /// </summary>
        public Encoding Encoding { get; set; }

        public string Address { get; protected set; }

        public int Port { get; protected set; }

        public bool AutoReconnect { get; set; }

        /// <summary>
        /// On successful registration on the IRC network, this is set to true.
        /// </summary>
        public bool IsRegistered { get; protected set; }

        /// <summary>
        /// On successful connect to the IRC server, this is set to true.
        /// </summary>
        public bool IsConnected { get; protected set; }

        /// <summary>
        /// Gets the SmartIrc4net version number
        /// </summary>
        public string VersionNumber { get; protected set; }

        /// <summary>
        /// Gets the full SmartIrc4net version string
        /// </summary>
        public string VersionString { get; protected set; }

        public TimeSpan CurrentLag { get; protected set; }

        /// <summary>
        /// Latency between client and the server
        /// </summary>
        public TimeSpan Lag {
            get {
                if (LastPingSent > LastPongReceived) {
                    // there is an outstanding ping, thus we don't have a current lag value
                    return DateTime.Now - LastPingSent;
                }

                return CurrentLag;
            }
        }

        /// <event cref="OnReadLine">
        /// Raised when a \r\n terminated line is read from the socket
        /// </event>
        public event ReadLineEventHandler   OnReadLine;
        /// <event cref="OnWriteLine">
        /// Raised when a \r\n terminated line is written to the socket
        /// </event>
        public event WriteLineEventHandler  OnWriteLine;
        /// <event cref="OnConnect">
        /// Raised before the connect attempt
        /// </event>
        public event EventHandler           OnConnecting;
        /// <event cref="OnConnect">
        /// Raised on successful connect
        /// </event>
        public event EventHandler           OnConnected;
        /// <event cref="OnConnect">
        /// Raised before the connection is closed
        /// </event>
        public event EventHandler           OnDisconnecting;
        /// <event cref="OnConnect">
        /// Raised when the connection is closed
        /// </event>
        public event EventHandler           OnDisconnected;
        /// <event cref="OnConnectionError">
        /// Raised when the connection got into an error state
        /// </event>
        public event EventHandler           OnConnectionError;
        /// <event cref="AutoConnectErrorEventHandler">
        /// Raised when the connection got into an error state during auto connect loop
        /// </event>

        public IrcConnection(Context context, Socket socket)
        {
#if LOG4NET
            Logger.Init();
            Logger.Main.Debug("IrcConnection created");
#endif
            Context = context;
            Socket = socket;

            OnReadLine += SimpleParser;

            Encoding = Encoding.Default;
            IsRegistered = true;
            IsConnected = false;

            Assembly assembly = Assembly.GetAssembly(this.GetType());
            AssemblyName assemblyName = assembly.GetName(false);

            AssemblyProductAttribute pr = (AssemblyProductAttribute)assembly.GetCustomAttributes(typeof(AssemblyProductAttribute), false)[0];

            VersionNumber = assemblyName.Version.ToString();
            VersionString = pr.Product + " " + VersionNumber;
        }

#if LOG4NET
        ~IrcConnection()
        {
            Logger.Main.Debug("IrcConnection destroyed");
        }
#endif

        public void Connect(string host, int port, Action action)
        {
            Address = host;
            Port = port;

            if (OnConnecting != null) {
                OnConnecting(this, EventArgs.Empty);
            }

            Socket.Connect(host, port, delegate {

                IsConnected = true;

                if (OnConnected != null) {
                    OnConnected(this, EventArgs.Empty);
                }

                action();

                Socket.GetSocketStream().Read(OnRead, OnReadError, OnReadFinished);
            });
        }

        public void Disconnect()
        {

            if (!IsConnected) {
                throw new NotConnectedException("The connection could not be disconnected because there is no active connection");
            }

#if LOG4NET
            Logger.Connection.Info("disconnecting...");
#endif
            if (OnDisconnecting != null) {
                OnDisconnecting(this, EventArgs.Empty);
            }

            // TODO: Disconnect the socket.

            IsConnected = false;
            IsRegistered = false;

            if (OnDisconnected != null) {
                OnDisconnected(this, EventArgs.Empty);
            }

#if LOG4NET
            Logger.Connection.Info("disconnected");
#endif
        }

        public void Reconnect()
        {
            Reconnect(() => {});
        }
        public void Reconnect(Action action)
        {
            Disconnect();
            Connect(Address, Port, action);
        }

        private void OnRead(ByteBuffer buffer)
        {
            int line_start = buffer.Position;
            int line_end = line_start;
            while (true) {
                //Console.WriteLine("{0}:{1}", line_start, line_end);
                if (line_end + 1 >= buffer.Length) {
                    // Console.WriteLine("nesamone");
                    // Remember, carry on next line
                    return;
                } else if ((buffer.Bytes[line_end] == '\r') && (buffer.Bytes[line_end + 1] == '\n')) {

                    line_end += 2;

                    string line = Encoding.GetString(buffer.Bytes, line_start, line_end - line_start);

                    OnReadLineEvent(line);

                    line_start = line_end;
                } else {
                    line_end++;
                }
            }
        }

        protected void OnReadLineEvent(string line)
        {
            if (OnReadLine != null) {
                OnReadLine(this, new ReadLineEventArgs(line.TrimEnd()));
            }
        }

        private void OnReadError(Exception exception)
        {
            if (AutoReconnect) {
                Reconnect();
            } else {
                Disconnect();
            }
        }

        private void OnReadFinished()
        {
        }

        private void Write(string data)
        {
            Write(Encoding.GetBytes(data));
        }

        private void Write(string data, Action action)
        {
            Write(Encoding.GetBytes(data), action);
        }

        private void Write(byte[] data)
        {
            Socket.GetSocketStream().Write(data);
        }

        private void Write(byte[] data, Action action)
        {
            CallbackCollection callbacks = new CallbackCollection();
            callbacks.Add(data, action);
            Write(callbacks);
        }

        private void Write(ByteBuffer data)
        {
            Socket.GetSocketStream().Write(data);
        }

        private void Write(IEnumerable<ByteBuffer> data)
        {
            Socket.GetSocketStream().Write(data);
        }

        public void WriteLine(string data, Priority priority)
        {
            WriteLine(data);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="data"></param>
        public void WriteLine(string data)
        {
            BaseWriteLine(data);
        }

        private void BaseWriteLine(string data)
        {
            Write(data + "\r\n", delegate {
                if (OnWriteLine != null) {
                    OnWriteLine(this, new WriteLineEventArgs(data));
                }
            });
        }

        private void SimpleParser(object sender, ReadLineEventArgs args)
        {
            string   rawline = args.Line;
            string[] rawlineex = rawline.Split(new char[] {' '});
            string   messagecode = "";

            if (rawline[0] == ':') {
                messagecode = rawlineex[1];

                ReplyCode replycode = ReplyCode.Null;
                try {
                    replycode = (ReplyCode)int.Parse(messagecode);
                } catch (FormatException) {
                }

                if (replycode != ReplyCode.Null) {
                    switch (replycode) {
                        case ReplyCode.Welcome:
                        IsRegistered = true;
#if LOG4NET
                            Logger.Connection.Info("logged in");
#endif
                            break;
                    }
                } else {
                    switch (rawlineex[1]) {
                        case "PONG":
                            DateTime now = DateTime.Now;
                            LastPongReceived = now;
                            CurrentLag = now - LastPingSent;

#if LOG4NET
                            Logger.Connection.Debug("PONG received, took: " + _Lag.TotalMilliseconds + " ms");
#endif
                            break;
                    }
                }
            } else {
                messagecode = rawlineex[0];
                switch (messagecode) {
                    case "ERROR":
                        // FIXME: handle server errors differently than connection errors!
                        //IsConnectionError = true;
                        break;
                }
            }
        }
    }
}
