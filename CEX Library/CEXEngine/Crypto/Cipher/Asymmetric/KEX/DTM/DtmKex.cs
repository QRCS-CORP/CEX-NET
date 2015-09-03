#region Directives
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Support;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Networking;
using VTDev.Libraries.CEXEngine.Utility;
using System.Timers;
#endregion

#region License Information
// The GPL Version 3 License
// 
// Copyright (C) 2015 John Underhill
// This file is part of the CEX Cryptographic library.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 
// Written by John Underhill, August 21, 2015
// contact: develop@vtdev.com
#endregion

// add a delay timer to primary pke                         -done
// add MaxDelayMS, MinDelayMS to dmtparameters..            -done
// min random padding of pub key is half? max..             -done
// TcpAsyncClient, add tcp properties, timeouts etc..       -done
// timeout on GetStreamData                                 -done
// class level dtmpacket for resend                         -done
// compare session sequence numbers                         -done
// complete resend framework                                -done
// handle multiple packet queue on receive                  -done
// echo and transmission message flags                      -no:done
// wait for echo?                                           -no:done
// dos attacks?                                             -done
// change _prcPcket & _rqtPacket to packet buffer           -done
// send file struct?                                        -done
// add delay to sym key and messages                        -done
// add padding to symmetric key                             -done
// add padding to parameter set?                            -done
// encrypt primary sym key 2x, w/ 2nd asy, then 1st sym     -done
// keyparams clone and deepcopy                             -done
// handle file transmission                                 -bugs
// add paramsets class                                      -done
// align ctr parallel block with chunk size                 -done
// update example and expand notes                          -done
// test buffer, file, error, resend etc.                    -done
// keyparams changed to symmetrickey?                       -no:done
// seperate file transfer class?                            -done
// streamcipher, +salsa/cha and while loop optimizations    -no:done
// echo and pop packet sequence from buffer when received   -done
// dynamic throttle control                                 -done
// keep alive timer                                         -done
// adjustable buffer size and properties                    -done
// auto-reconnect option                                    -done
// complete error framework                                 -done?
// test all the param sets                                  -done?
// chacha is failing tests                                  -done
// mac with no keyparams or uses ikm field?                 -no:done
// asym oid -family, set, subset, id.. fix it               -no:done
// consolidate keypair w/id into one serializable class     -done
// look at gmss, using different signatutes?                -not sure, left note
// DTM documentation                                        -
// final round of checks for library                        -
// article update and release                               -
// rabbit jr                                                -

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM
{
    /// <summary>
    /// Performs an Asymmetric Key Exchange using the Deferred Trust Model KEX.
    /// <para>This work is preliminary, and subject to modification when the scheme is deployed. (eta is fall of 2015)</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Creating a DTM Server:</description>
    /// <code>
    /// // dtm server exchange parameters X11RNS1R2
    /// DtmParameters srvDtmParams = DtmParamSets.FromName(DtmParamSets.DtmParamNames.X42RNS1R1);       // preset contains all the settings required for the exchange
    ///
    /// // dtm server id
    /// DtmClient srvDmtId = new DtmClient(
    ///     new byte[] { 3, 3, 3, 3 },      // the clients public id, (should be at least 32 bytes, can be used as a contact lookup and initial auth)
    ///     new byte[] { 4, 4, 4, 4 });     // the clients secret id, (secret id can be anything.. a serialized structure, signed data, hash, etc)
    ///
    /// // create the server
    /// _dtmServer = new DtmKex(srvDtmParams, srvDmtId);
    /// _dtmServer.IdentityReceived += new DtmKex.IdentityReceivedDelegate(OnIdentityReceived);         // returns the client public and secret id fields, used to authenticate a host
    /// _dtmServer.PacketReceived += new DtmKex.PacketReceivedDelegate(OnPacketReceived);               // notify that a packet has been received (optional)
    /// _dtmServer.SessionEstablished += new DtmKex.SessionEstablishedDelegate(OnSessionEstablished);   // notify when the vpn state is up
    /// _dtmServer.PacketSent += new DtmKex.PacketReceivedDelegate(OnPacketSent);                       // notify when a packet has been sent to the remote host (optional)
    /// _dtmServer.DataReceived += new DtmKex.DataTransferredDelegate(OnDataReceived);                  // returns the decrypted message data
    /// _dtmServer.FileReceived += new DtmKex.FileTransferredDelegate(OnFileReceived);                  // notify that a file transfer has completed
    /// _dtmServer.FileRequest += new DtmKex.FileRequestDelegate(OnFileRequest);                        // notify that the remote host wants to send a file, can cancel or provide a path for the new file
    /// _dtmServer.SessionError += new DtmKex.SessionErrorDelegate(OnSessionError);                     // notify of any error conditions; includes the exception, and a severity code contained in the option flag
    ///
    /// // server starts listening
    /// _dtmServer.Listen(IPAddress.Any, Port);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM DtmParameters class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmClient">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmClient structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmIdentity">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmIdentity structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmPacket">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmPacket structure</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures.DtmSession">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structures DtmSession</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments.DtmErrorEventArgs">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments DtmErrorEventArgs class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments.DtmEstablishedEventArgs">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments DtmEstablishedEventArgs class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments.DtmPacketEventArgs">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Arguments DtmPacketEventArgs class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages.DtmErrorFlags">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages DtmErrorFlags enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages.DtmServiceFlags">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages DtmPacketFlag enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages.DtmPacketTypes">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Messages DtmPacketTypes enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Overview:</h4></description>
    /// <para>DTM is designed for maximum flexibility, for this reason authentication between hosts is 'deffered' to another layer of software, whereby the users actions and settings can at 
    /// least in part determine the level of security, authentication, repudiation, and how an exchange is transacted.</para>
    /// 
    /// <para>The protocol is directed at end to end data exchanges, (such as voice or video conferencing between nodes), and a means by which nodes may authenticate and execute a secure
    /// communications channel without the need for signing, certificates, or third party authenticators. 
    /// This is intended as a semi-closed system of authentication, whereby a node may choose to engage a session with an unknown actor, 
    /// with both nodes determining a local trust value (ex. adding a contact to a list during a call, banning a host, etc.). 
    /// Expansions of the system beyond a closed or semi-closed framework are considered as a layer above this implementation; i.e. a shared trust model based on a signature scheme, 
    /// or the movement of contacts within a trust model framework.</para>
    /// 
    /// <para>Tasks such as host Authentication and Repudiation are forwarded to an upper layer of software, which in turn can determine an appropriate action. 
    /// For example; the identity exchange notifies the client via events; the <see cref="IdentityReceived"/> forwards an id field, and the symmetric, and asymmetric cipher parameters. 
    /// If the parameter sets do not meet a minimum security context, or the conversation is otherwise refused, that layer of software can terminate the session 
    /// simply by setting the Cancel flag to true in the event arguments, and a packet can be sent back to the requesting host notifying them of the cause of failure. 
    /// This could in turn, trigger another exchange attempt with stronger parameters.</para>
    /// 
    /// <para>This model proposes using two post-quantum secure ciphers; the first cipher should be considered as the Authenticator, or <c>Auth-Stage</c>. 
    /// The authenticating asymmetric cipher is used to encrypt the first (symmetric) session key. This session key is in turn used to encrypt the asymmetric parameters and the Public key
    /// of the second <c>Primary-Stage</c> asymmetric cipher. The primary asymmetric cipher encrypts a second symmetric key; which is used as the primary session key in the VPN.</para>
    /// <para>Both channels (Send and Receive) are encrypted with seperate keys; data Bob sends to Alice is encrypted with the symmetric key that Bob generated and exchanged, and data Bob receives
    /// from Alice is decrypted with the symmetric key that Alice generated. In this way each actor defines the security context for the channel that they transmit data on.</para>
    /// 
    /// <description><h4>Exchange States:</h4></description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Stage</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description>Connect</description>
    ///         <description>The server and client exchange a DtmIdentity structure; containing just the public id field.</description>
    ///     </item>
    ///     <item>
    ///         <description>Init</description>
    ///         <description>The server and client exchange a full DtmIdentity structure; containing the public id field and the PKE Parameters Id, used to create the <c>Auth-Stage</c> Asymmetric keys.</description>
    ///     </item>
    ///     <item>
    ///         <description>PreAuth</description>
    ///         <description>The server and client exchange their <c>Auth-Stage</c> Asymmetric Public Keys.</description>
    ///     </item>
    ///     <item>
    ///         <description>AuthEx</description>
    ///         <description>The server and client exchange their <c>Auth-Stage</c> Symmetric KeysParams.</description>
    ///     </item>
    ///     <item>
    ///         <description>Auth</description>
    ///         <description>The server and client exchange their private identity fields, used to mutually authenticate.</description>
    ///     </item>
    ///     <item>
    ///         <description>Sync</description>
    ///         <description>The server and client exchange their <c>Primary-Stage</c> Asymmetric and Session Parameters.</description>
    ///     </item>
    ///     <item>
    ///         <description>PrimeEx</description>
    ///         <description>The server and client exchange their <c>Primary-Stage</c> Asymmetric Public Key.</description>
    ///     </item>
    ///     <item>
    ///         <description>Primary</description>
    ///         <description>The server and client exchange their <c>Primary-Stage</c> Symmetric KeyParams.</description>
    ///     </item>
    ///     <item>
    ///         <description>Establish</description>
    ///         <description>The server and client acknowledge their mutual trust; the VPN is UP.</description>
    ///     </item>
    /// </list>
    /// 
    /// <description><h4>Structures:</h4></description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Structure</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description><see cref="DtmPacket"/></description>
    ///         <description>The primary packet header used in a DTM key exchange; used to classify and describe the message content.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmIdentity"/></description>
    ///         <description>Storage for the active identity, symmetric session, and asymmetric parameters.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmMessage"/></description>
    ///         <description>A header that encapsulates encrypted messages; it contains describe the payload and padding.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmClient"/></description>
    ///         <description>Used to store data that uniquely identifies the host.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmParameters"/></description>
    ///         <description>Defines the working parameters used by the DTM Key Exchange using a DtmKex instance.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmSession"/></description>
    ///         <description>Contains a minimal description of the symmetric cipher.</description>
    ///     </item>
    /// </list>
    /// 
    /// <description><h4>Enumerations:</h4></description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Enumeration</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description><see cref="DtmErrorFlags"/> </description>
    ///         <description>This enum represents the error flags that can be applied to the DtmPacket Option flag.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmServiceFlags"/></description>
    ///         <description>Describes the state of the key exchange progress; used as a flag in a Request operation.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmPacketTypes"/></description>
    ///         <description>Contains the primary message types; used as the Message flag in a DtmPacket.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmTrustStates"/></description>
    ///         <description>This enum represents the requested trust relationship (for future use).</description>
    ///     </item>
    /// </list>
    /// 
    /// <description><h4>Events:</h4></description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Event</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description><see cref="PacketReceived"/></description>
    ///         <description>Event fires each time a valid packet has been received.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="PacketSent"/></description>
    ///         <description>Event fires each time a valid packet has been sent.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="IdentityReceived"/></description>
    ///         <description>Event fires when a packet containing identity data is received.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="SessionError"/></description>
    ///         <description>Event fires when an error has occured.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="SessionEstablished"/></description>
    ///         <description>Event fires when the vpn has been established.</description>
    ///     </item>
    /// </list>
    /// 
    /// <description><h4>Arguments:</h4></description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Argument</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description><see cref="DtmErrorFlags"/></description>
    ///         <description>Class contains the error state information.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmEstablishedEventArgs"/> </description>
    ///         <description>Class contains the final symmetric keys from a completed exchange.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmErrorEventArgs"/></description>
    ///         <description>Class contains the identity of a client.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmPacketEventArgs"/></description>
    ///         <description>Class contains the exchange state information.</description>
    ///     </item>
    /// </list>
    /// </remarks>
    public sealed class DtmKex : IDisposable
    {
        #region Constants
        /// <summary>
        /// The default buffer size used in the message exchange
        /// </summary>
        private const int CHUNKSIZE = 8192;
        /// <summary>
        /// The number of milliseconds to wait on a blocking call, default 4 minutes
        /// </summary>
        private const int EXCHTIMEOUT = 1000 * 240;
        /// <summary>
        /// The maximum size of a single message
        /// </summary>
        private const int MAXRCVBUFFER = 1024 * 1000 * 240;
        /// <summary>
        /// Maximum number of times the instance will accept a retransmission request
        /// </summary>
        private const int MAXSNDATTEMPT = 1024;
        /// <summary>
        /// The default connection timeout interval
        /// </summary>
        private const int DEFTIMEOUT = 10;
        #endregion

        #region Fields
        private IAsymmetricKeyPair _authKeyPair;                        // the auth stage asymmetric key pair
        private bool _autoReconnect = true;                             // attempt to reconnect if line dropped
        private int _bufferCount = 0;                                   // the number of buffer segments
        private long _bytesSent = 0;                                    // the number of encrypted bytes sent to the remote host on the primary channel
        private long _bytesReceived = 0;                                // the number of encrypted bytes received from the remote host on the primary channel
        private TcpSocket _clientSocket;                                // the client/server main socket instance
        private IAsymmetricParameters _cltAsmParams;                    // the clients asymmetric cipher parameters
        private DtmSession _cltAuthSession;                             // the clients auth-stage symmetric key params
        private DtmIdentity _cltIdentity;                               // the clients identity structure
        private KeyParams _cltKeyParams;                                // the clients symmetric keying material
        private IAsymmetricKey _cltPublicKey;                           // the clients asymmetric public key
        private ICipherMode _cltSymProcessor;                           // the clients symmetric cipher instance
        private int _connectionTimeOut = DEFTIMEOUT;                    // The number of contiguous missed keepalives before a connection is considered dropped
        private bool _disposeEngines = true;                            // dispose of crypto processors when class disposed
        private DtmClient _dtmHost;                                     // the servers client identity
        private DtmParameters _dtmParameters;                           // the dtm exchange parameters
        private ManualResetEvent _evtSendWait;                          // transmission delay event
        private DtmExchangeFlags _exchangeState;                        // current state of the exchange process
        private long _fileCounter = 0;                                  // the unique file id counter
        private DtmBufferSizes _fileBufferSize = DtmBufferSizes.KB32;   // the size of the tcp and file buffer elements
        private object _fileLock = new object();                        // locks file transfer container
        private bool _isDisconnecting = false;                          // dispose flag
        private bool _isDisposed = false;                               // dispose flag
        private bool _isEstablished = false;                            // session established
        private bool _isServer = false;                                 // server if we granted the session
        private int _maxSendCounter = 0;                                // the max resend iterator
        private int _maxSendAttempts = MAXSNDATTEMPT;                   // the max resend attempts
        private DtmBufferSizes _messageBufferSize = DtmBufferSizes.KB8; // the size of the tcp and message buffer elements
        private IAsymmetricKeyPair _primKeyPair;                        // the primary stage asymmetric key pair
        private System.Timers.Timer _pulseTimer;                        // the keep alive timer
        private long _pulseCounter = 0;                                 // the missed keep alives counter
        private PacketBuffer _rcvBuffer;                                // the processing packet buffer
        private long _rcvSequence = 0;                                  // the session receive sequence register
        private int _resendThreshold = 10;                              // the number of queued message packets before a resend is triggered
        private IRandom _rndGenerator;                                  // the random generator
        private object _sendLock = new object();                        // locks the transmission queue
        private long _seqCounter = 0;                                   // tracks high sequence
        private PacketBuffer _sndBuffer;                                // the send packet buffer
        private long _sndSequence = 0;                                  // the session send sequence register
        private IAsymmetricParameters _srvAsmParams;                    // the servers asymmetric cipher parameters
        private DtmIdentity _srvIdentity;                               // the servers identity structure
        private KeyParams _srvKeyParams;                                // the servers symmetric keying material
        private ICipherMode _srvSymProcessor;                           // the servers symmetric cipher instance
        private ConcurrentDictionary<long, DtmFileTransfer> _transQueue = new ConcurrentDictionary<long, DtmFileTransfer>(); // container holds the file transfer instances
        #endregion

        #region Delegates/Events
        /// <summary>
        /// The Packet Transferred delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmDataReceivedEventArgs"/> class</param>
        public delegate void DataTransferredDelegate(object owner, DtmDataReceivedEventArgs args);
        /// <summary>
        /// The Data Received event; fires each time data has been received through the post-exchange encrypted channel
        /// </summary>
        public event DataTransferredDelegate DataReceived;

        /// <summary>
        /// The File Transferred delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmPacketEventArgs"/> class</param>
        public delegate void FileTransferredDelegate(object owner, DtmPacketEventArgs args);
        /// <summary>
        /// The File Received event; fires when the file transfer operation has completed
        /// </summary>
        public event FileTransferredDelegate FileReceived;
        /// <summary>
        /// The File Received event; fires when the file transfer operation has completed
        /// </summary>
        public event FileTransferredDelegate FileSent;

        /// <summary>
        /// The File Request delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmFileRequestEventArgs"/> class</param>
        public delegate void FileRequestDelegate(object owner, DtmFileRequestEventArgs args);
        /// <summary>
        /// The File Request event; fires when the host receives notification of a pending file transfer.
        /// <para>The event is received with the file name in the FilePath field, and must return the full path to the local destination, including file name.
        /// To cancel the file transmission, set the <see cref="DtmFileRequestEventArgs"/> to <c>true</c></para>
        /// </summary>
        public event FileRequestDelegate FileRequest;

        /// <summary>
        /// The Identity Received delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmIdentityEventArgs"/> class</param>
        public delegate void IdentityReceivedDelegate(object owner, DtmIdentityEventArgs args);
        /// <summary>
        /// The Identity Received event; fires when a packet containing identity data is received
        /// </summary>
        public event IdentityReceivedDelegate IdentityReceived;

        /// <summary>
        /// The Packet Received delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmPacketEventArgs"/> class</param>
        public delegate void PacketReceivedDelegate(object owner, DtmPacketEventArgs args);
        /// <summary>
        /// The Packet Received event; fires each time a valid packet has been received
        /// </summary>
        public event PacketReceivedDelegate PacketReceived;

        /// <summary>
        /// The Packet Sent delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmPacketEventArgs"/> class</param>
        public delegate void PacketSentDelegate(object owner, DtmPacketEventArgs args);
        /// <summary>
        /// The Packet Sent event; fires each time a valid packet has been sent
        /// </summary>
        public event PacketReceivedDelegate PacketSent;

        /// <summary>
        /// Progress indicator delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="e">Progress event arguments containing percentage and bytes processed as the UserState param</param>
        public delegate void ProgressDelegate(object sender, System.ComponentModel.ProgressChangedEventArgs e);

        /// <summary>
        /// Progress Percent Event; returns bytes processed as an integer percentage
        /// </summary>
        public event ProgressDelegate ProgressPercent;

        /// <summary>
        /// The Session Error delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmErrorEventArgs"/> class</param>
        public delegate void SessionErrorDelegate(object owner, DtmErrorEventArgs args);
        /// <summary>
        /// The Session Error event; fires when an error has occured
        /// </summary>
        public event SessionErrorDelegate SessionError;

        /// <summary>
        /// The Session Established delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmEstablishedEventArgs"/> class</param>
        public delegate void SessionEstablishedDelegate(object owner, DtmEstablishedEventArgs args);
        /// <summary>
        /// The Session Established; fires when the vpn has been established
        /// </summary>
        public event SessionEstablishedDelegate SessionEstablished;
        #endregion

        #region Properties
        /// <summary>
        /// Attempts to reconnect to a host if the connection is dropped through an error or timeout
        /// </summary>
        public bool AutoReconnect
        {
            get { return _autoReconnect; }
            set { _autoReconnect = value; }
        }

        /// <summary>
        /// The number of contiguous missed keepalives (at one second intervals), before a connection is considered dropped.
        /// <para>This value is used by the AutoReconnect feature as the threshold before a reconnect operation is initiated.
        /// Adjust this interval based on the target devices reliability, processing power, and load;
        /// ex. a phone should wait 30 seconds or more, a computer 10 seconds or less.
        /// The default value is 10 seconds.</para>
        /// </summary>
        public int ConnectionTimeOut
        {
            get { return _connectionTimeOut; }
            set 
            {
                if (value < 1 || value > 1024)
                    throw new CryptoKeyExchangeException("DtmKex:ConnectionTimeOut", "The value must be a postive number between 1 and 1024!", new ArgumentException());

                _connectionTimeOut = value; 
            }
        }

        /// <summary>
        /// Get: The connection state
        /// </summary>
        public bool IsConnected
        {
            get { return _clientSocket == null ? false : _clientSocket.IsConnected; }
        }

        /// <summary>
        /// Get: The VPN is Established
        /// </summary>
        public bool IsEstablished
        {
            get { return _isEstablished; }
        }

        /// <summary>
        /// The size of the file Tcp and buffer queue elements.
        /// <para>Buffer size <c>must match</c> remote client, otherwise an excess of partial packets could break the queing mechanism.</para>
        /// </summary>
        public DtmBufferSizes FileBufferSize
        {
            get { return _fileBufferSize; }
            set { _fileBufferSize = value; }
        }

        /// <summary>
        /// Get/Set: The maximum number of times a packet can be resent; default is <c>1024</c>
        /// </summary>
        /// 
        /// <exception cref="CryptoKeyExchangeException">Thrown if the value is less than <c>0</c></exception>
        public int MaxResend
        {
            get { return _maxSendAttempts; }
            set 
            {
                if (value < 0)
                    throw new CryptoKeyExchangeException("DtmKex:MaxResend", "The value must be a postive number!", new ArgumentException());

                _maxSendAttempts =  value; 
            }
        }

        /// <summary>
        /// Get/Set: The size of the message Tcp and buffer queue elements.
        /// <para>Buffer size <c>must match</c> remote client, otherwise an excess of partial packets could break the queing mechanism.
        /// The size of the buffer should align with the implementation type, i.e. be as close to the expected output segment size as possible,
        /// while large enough to process every stream segment; ex. if the average output of a video processor frame is  6 KB, set the packet size to 8 KB. 
        /// </para>
        /// </summary>
        public DtmBufferSizes MessageBufferSize
        {
            get { return _messageBufferSize; }
            set { _messageBufferSize = value; }
        }

        /// <summary>
        /// Get/Set: The number of queued message packets before a resend is triggered
        /// </summary>
        public int ResendThreshold
        {
            get { return _resendThreshold; }
            set 
            {
                if (value < 1 || value > 1024)
                    throw new CryptoKeyExchangeException("DtmKex:ResendThreshold", "The value must be a postive number between 1 and 1024!", new ArgumentException());

                _resendThreshold = value; 
            }
        }

        /// <summary>
        /// Get: Returns the TcpSocket class instance
        /// </summary>
        public TcpSocket Socket
        {
            get { return _clientSocket; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Parameters">A populated <see cref="DtmParameters"/> class containing the session parameters</param>
        /// <param name="Host">A populated <see cref="DtmClient"/> class containing the servers identity data</param>
        /// <param name="BufferCount">The number of send/receive buffers, default is 1024</param>
        /// <param name="DisposeEngines">if set to true (default), the primary symmetric ciphers are disposed when this class is disposed</param>
        public DtmKex(DtmParameters Parameters, DtmClient Host, int BufferCount = 1024, bool DisposeEngines = true)
        {
            _disposeEngines = DisposeEngines;
            _dtmParameters = Parameters;
            _dtmHost = Host;
            _srvIdentity = new DtmIdentity(Host.PublicId, Parameters.AuthPkeId, Parameters.AuthSession, 0);
            _exchangeState = DtmExchangeFlags.Connect;
            _rcvBuffer = new PacketBuffer(BufferCount);
            _sndBuffer = new PacketBuffer(BufferCount);
            _rndGenerator = GetPrng(_dtmParameters.RandomEngine);
            _bufferCount = BufferCount;
        }

        /// <summary>
        /// Initialize this class with a random generator
        /// </summary>
        /// 
        /// <param name="Parameters">A populated <see cref="DtmParameters"/> class containing the session parameters</param>
        /// <param name="Host">A populated <see cref="DtmClient"/> class containing the servers identity data</param>
        /// <param name="Generator">The initialized <see cref="IRandom"/> Prng instance</param>
        /// <param name="BufferCount">The number of send/receive buffers, default is 1024</param>
        /// <param name="DisposeEngines">if set to true (default), the primary symmetric ciphers are disposed when this class is disposed</param>
        public DtmKex(DtmParameters Parameters, DtmClient Host, IRandom Generator, int BufferCount = 1024, bool DisposeEngines = true)
        {
            _disposeEngines = DisposeEngines;
            _dtmParameters = Parameters;
            _dtmHost = Host;
            _srvIdentity = new DtmIdentity(Host.PublicId, Parameters.AuthPkeId, Parameters.AuthSession, 0);
            _exchangeState = DtmExchangeFlags.Connect;
            _rcvBuffer = new PacketBuffer(BufferCount);
            _sndBuffer = new PacketBuffer(BufferCount);
            _rndGenerator = Generator;
            _bufferCount = BufferCount;
        }

        private DtmKex()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~DtmKex()
        {
            Dispose(false);
        }
        #endregion

        #region Connect
        /// <summary>
        /// Connect to a server and begin the key exchange
        /// </summary>
        /// 
        /// <param name="HostName">The servers Host Nam</param>
        /// <param name="Port">The servers Port number</param>
        /// <param name="Async">Connect on a non-blocking TCP channel</param>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a socket error is returned</exception>
        public void Connect(string HostName, int Port, bool Async = true)
        {
            // create the connection
            _clientSocket = new TcpSocket();
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnClientConnected);
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);

            try
            {
                if (Async)
                    _clientSocket.ConnectAsync(HostName, Port);
                else
                    _clientSocket.Connect(HostName, Port);
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorEventArgs(new CryptoSocketException("DtmKex:Connect", "The connection attempt has failed", ex), DtmErrorSeverity.Connection));

            }
        }

        /// <summary>
        /// Connect to a server and begin the key exchange
        /// </summary>
        /// 
        /// <param name="Address">The servers IP Address</param>
        /// <param name="Port">The servers Port number</param>
        /// <param name="Async">Connect on a non-blocking TCP channel</param>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a socket error is returned</exception>
        public void Connect(IPAddress Address, int Port, bool Async = true)
        {
            // create the connection
            _clientSocket = new TcpSocket();
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnClientConnected);
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);

            try
            {
                if (Async)
                    _clientSocket.ConnectAsync(Address, Port);
                else
                    _clientSocket.Connect(Address, Port);
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorEventArgs(new CryptoSocketException("DtmKex:Connect", "The connection attempt has failed", ex), DtmErrorSeverity.Connection));
            }
        }

        /// <summary>
        /// Server has accepted the connection from the Client
        /// </summary>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a processing or socket error is returned</exception>
        private void OnClientConnected(object owner, SocketAsyncEventArgs args)
        {
            _clientSocket.ReceiveBufferSize = (int)MessageBufferSize;
            _clientSocket.SendBufferSize = (int)MessageBufferSize;

            try
            {
                // start the exchange
                ClientExchange();
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorEventArgs(new CryptoKeyExchangeException("DtmKex:OnClientConnected", "The key exchange has failed!", ex), DtmErrorSeverity.Critical));

                return;
            }

            // listen for incoming data
            _clientSocket.ReceiveAsync();
        }

        /// <summary>
        /// Executes the client portion the key exchange
        /// </summary>
        private void ClientExchange()
        {
            // we are the client, entire exchange is blocking
            _isServer = false;

            // send connect request
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Connect, 0, CreateConnect(), true);
            // process connect response
            Process(BlockingReceive());
            // init
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Init, 0, CreateInit(), true);
            Process(BlockingReceive());
            // preauth
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.PreAuth, 0, CreatePreAuth(), true);
            Process(BlockingReceive());
            // authex
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.AuthEx, 0, CreateAuthEx(), true);
            Process(BlockingReceive());
            // auth
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Auth, 0, CreateAuth(), true);
            Process(BlockingReceive());
            // sync
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Sync, 0, CreateSync(), true);
            Process(BlockingReceive());
            // primex
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.PrimeEx, 0, CreatePrimeEx(), true);
            Process(BlockingReceive());
            // primary
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Primary, 0, CreatePrimary(), true);
            Process(BlockingReceive());
            // established
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Established, 0, CreateEstablish(), true);
            Process(BlockingReceive());

            // clear the buffers
            _rcvBuffer.Clear();
            _sndBuffer.Clear();
            // start keep alive timer
            StartPulse();
        }
        #endregion

        #region Listen
        /// <summary>
        /// Initialize the server and listen for incoming connections
        /// </summary>
        /// 
        /// <param name="HostName">The servers Host Name</param>
        /// <param name="Port">The servers Port number</param>
        /// <param name="Async">Listen on a non-blocking TCP connection</param>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a socket error is returned</exception>
        public void Listen(string HostName, int Port, bool Async = true)
        {
            _clientSocket = new TcpSocket();
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnServerConnected);
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);

            try
            {
                if (Async)
                    _clientSocket.ListenAsync(HostName, Port);
                else
                    _clientSocket.Listen(HostName, Port);
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorEventArgs(new CryptoSocketException("DtmKex:Listen", "The server experienced a socket error!", ex), DtmErrorSeverity.Connection));
            }
        }

        /// <summary>
        /// Initialize the server and listen for incoming connections
        /// </summary>
        /// 
        /// <param name="Address">The servers IP Address</param>
        /// <param name="Port">The servers Port number</param>
        /// <param name="Async">Listen on a non-blocking TCP connection</param>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a socket error is returned</exception>
        public void Listen(IPAddress Address, int Port, bool Async = true)
        {
            _clientSocket = new TcpSocket();
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnServerConnected);
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);

            try
            {
                if (Async)
                    _clientSocket.ListenAsync(Address, Port);
                else
                    _clientSocket.Listen(Address, Port);
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorEventArgs(new CryptoSocketException("DtmKex:Listen", "The server received a socket error!", ex), DtmErrorSeverity.Connection));
            }
        }

        /// <summary>
        /// Client has made a connection to the server
        /// </summary>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a processing or socket error is returned</exception>
        private void OnServerConnected(object owner, SocketAsyncEventArgs args)
        {
            // stop listening; create a new dtm class instance to listen for another client
            _clientSocket.ListenStop();
            _clientSocket.ReceiveBufferSize = (int)MessageBufferSize;
            _clientSocket.SendBufferSize = (int)MessageBufferSize;

            try
            {
                // run the exchange
                ServerExchange();
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorEventArgs(new CryptoKeyExchangeException("DtmKex:OnClientConnected", "The key exchange has failed!", ex), DtmErrorSeverity.Critical));

                return;
            }

            // listen for incoming data
            _clientSocket.ReceiveAsync();
        }

        /// <summary>
        /// Executes the server portion of the key exchange
        /// </summary>
        private void ServerExchange()
        {
            // a client has connected, we are the server
            _isServer = true;

            // process blocking connect
            Process(BlockingReceive());
            // send a connect response
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Connect, 0, CreateConnect(), true);
            // init
            Process(BlockingReceive());
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Init, 0, CreateInit(), true);
            // preauth
            Process(BlockingReceive());
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.PreAuth, 0, CreatePreAuth(), true);
            // authex
            Process(BlockingReceive());
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.AuthEx, 0, CreateAuthEx(), true);
            // auth
            Process(BlockingReceive());
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Auth, 0, CreateAuth(), true);
            // sync
            Process(BlockingReceive());
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Sync, 0, CreateSync(), true);
            // primex
            Process(BlockingReceive());
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.PrimeEx, 0, CreatePrimeEx(), true);
            // primary
            Process(BlockingReceive());
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Primary, 0, CreatePrimary(), true);
            // established
            Process(BlockingReceive());
            Transmit(DtmPacketTypes.Exchange, (short)DtmExchangeFlags.Established, 0, CreateEstablish(), true);

            // clear the buffers
            _rcvBuffer.Clear();
            _sndBuffer.Clear();
            // start keep alive timer
            StartPulse();
        }
        #endregion

        #region Data Received
        /// <summary>
        /// Entry point for post-exchange data received from the Tcp Socket
        /// </summary>
        private void OnDataReceived(DataReceivedEventArgs args)
        {
            if (args.Owner.Client.Equals(_clientSocket.Client))
            {
                // retrieve and buffer the packet
                ProcessAndPush(_rcvBuffer, args.Owner.Data);
                
                // check for sequenced packets in the queue
                if (_rcvBuffer.Count > 0)
                {
                    do
                    {
                        // process if in sequence or break
                        if (!_rcvBuffer.Exists(_rcvSequence))
                            break;
                        else
                            Process(_rcvBuffer.Pop(_rcvSequence));
                    }
                    while (true);
                }
            }
        }

        /// <summary>
        /// Processes and queues incoming packets
        /// </summary>
        private void ProcessAndPush(PacketBuffer Buffer, MemoryStream PacketStream)
        {
            int hdrLen = DtmPacket.GetHeaderSize();
            int pktLen = 0;
            // process the whole packet
            PacketStream.Seek(0, SeekOrigin.Begin);
            // get the header
            DtmPacket dtmPkt = new DtmPacket(PacketStream);
            PacketStream.Seek(0, SeekOrigin.Begin);

            // track high sequence number, filters corrupt packets
            if (dtmPkt.Sequence > _seqCounter && dtmPkt.PayloadLength < MAXRCVBUFFER && dtmPkt.OptionFlag < 1000)
                _seqCounter = dtmPkt.Sequence;

            // out of sync, possible packet loss
            if (_seqCounter - _rcvSequence > ResendThreshold)
            {
                // request a retransmission
                Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.Resend, _rcvSequence + 1);
            }

            if (dtmPkt.PayloadLength + hdrLen == PacketStream.Length)
            {
                // resend was already processed
                if (dtmPkt.Sequence < _rcvSequence)
                    return;

                // push onto buffer
                Buffer.Push(dtmPkt.Sequence, PacketStream);
            }
            // more than one packet
            else if (dtmPkt.PayloadLength + hdrLen < PacketStream.Length)
            {
                byte[] buffer;
                long pos = 0;

                do
                {
                    // get packet position and size
                    pos = PacketStream.Position;

                    if (PacketStream.Length - pos < DtmPacket.GetHeaderSize())
                    {
                        // next packet corrupted, request a retransmission and exit
                        Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.Resend, Buffer.GetHighKey() + 1);
                        return;
                    }

                    dtmPkt = new DtmPacket(PacketStream);
                    pktLen = (int)(hdrLen + dtmPkt.PayloadLength);

                    if (pktLen > MAXRCVBUFFER || pktLen < 0 || PacketStream.Length - pos < pktLen)
                    {
                        // packet corrupted, request a retransmission and exit
                        Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.Resend, Buffer.GetHighKey() + 1);
                        return;
                    }
                    else
                    {
                        // create the buffer
                        buffer = new byte[pktLen];
                        PacketStream.Seek(pos, SeekOrigin.Begin);
                        PacketStream.Read(buffer, 0, (int)pktLen);
                        // push onto buffer
                        Buffer.Push(dtmPkt.Sequence, new MemoryStream(buffer));
                    }

                } while (PacketStream.Position < PacketStream.Length);
            }
            // malformed packet, send retransmit request
            else if (dtmPkt.PayloadLength > MAXRCVBUFFER || dtmPkt.PayloadLength < 0 || dtmPkt.PayloadLength + hdrLen > PacketStream.Length)
            {
                // packet corrupted, request a retransmission of last in queue + 1
                Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.Resend, Buffer.GetHighKey() + 1);
            }
        }
        #endregion

        #region Channel Processors
        /// <summary>
        /// Disconnect from the remote host and teardown the connection
        /// </summary>
        public void Disconnect()
        {
            _isEstablished = false;
            _isDisconnecting = true;
            // stop sending keepalives
            StopPulse();

            try
            {
                if (_clientSocket.IsConnected)
                {
                    Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.Terminate, 0, null, true);
                    _clientSocket.TcpStream.Flush();
                    _clientSocket.Close();
                }
            }
            catch { }

            try
            {

                if (_clientSocket != null)
                {
                    _clientSocket.Dispose();
                    _clientSocket = null;
                }
                if (_evtSendWait != null)
                {
                    _evtSendWait.Dispose();
                    _evtSendWait = null;
                }
                if (_rcvBuffer != null)
                {
                    _rcvBuffer.Dispose();
                    _rcvBuffer = null;
                }
                if (_sndBuffer != null)
                {
                    _sndBuffer.Dispose();
                    _sndBuffer = null;
                }
            }
            catch { }

            try
            {
                TearDown();
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorEventArgs(new CryptoProcessingException("DtmKex:Disconnect", "The tear down operation experienced an error!", ex), DtmErrorSeverity.Warning));
            }
        }

        /// <summary>
        /// Process a message.
        /// <para>Use this method to process <see cref="DtmPacket"/> data sent to the server</para>
        /// </summary>
        private void Process(MemoryStream PacketStream)
        {
            try
            {
                // increment rcv sequence
                _rcvSequence++;
                // get the header
                DtmPacket pktHdr = new DtmPacket(PacketStream);
                PacketStream.Seek(0, SeekOrigin.Begin);

                switch (pktHdr.PacketType)
                {
                    // message stream
                    case DtmPacketTypes.Message:
                        {
                            // process message
                            switch ((DtmMessageFlags)pktHdr.PacketFlag)
                            {
                                case DtmMessageFlags.Transmission:
                                    {
                                        try
                                        {
                                            // received stream data
                                            ReceiveMessage(PacketStream);
                                        }
                                        catch (Exception)
                                        {
                                            // packet corrupted, request a retransmission and exit
                                            Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.Resend, pktHdr.Sequence);
                                            return;
                                        }

                                        // echo the packet to remove it from remote buffer
                                        Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.Echo, pktHdr.Sequence);
                                        break;
                                    }
                            }
                            break;
                        }
                    // service messages
                    case DtmPacketTypes.Service:
                        {
                            switch ((DtmServiceFlags)pktHdr.PacketFlag)
                            {
                                case DtmServiceFlags.KeepAlive:
                                    {
                                        // reset the keep alive counter
                                        _pulseCounter = 0;
                                        break;
                                    }
                                // process echo
                                case DtmServiceFlags.Echo:
                                    {
                                        // remove from buffer
                                        if (_sndBuffer.Exists(pktHdr.OptionFlag))
                                            _sndBuffer.Destroy(pktHdr.OptionFlag);

                                        break;
                                    }
                                case DtmServiceFlags.Resend:
                                    {
                                        // attempt resend, if not in buffer transmission, attempts a resync
                                        Resend(pktHdr);
                                        break;
                                    }
                                case DtmServiceFlags.DataLost:
                                    {
                                        // remote packet lost, try resync. note: if this happens often, increase buffer size in ctor + tcp
                                        MemoryStream pktData = CreateResync();
                                        _bytesSent += pktData.Length;
                                        Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.Resync, _bytesSent, pktData);
                                        break;
                                    }
                                case DtmServiceFlags.Resync:
                                    {
                                        // attempt to resync the crypto stream
                                        ProcessResync(PacketStream);
                                        break;
                                    }
                                case DtmServiceFlags.Refusal:
                                    {
                                        DtmErrorEventArgs args = new DtmErrorEventArgs(new ApplicationException("The session was refused by the remote host."), DtmErrorSeverity.Connection);
                                        if (SessionError != null)
                                            SessionError(this, args);

                                        if (args.Cancel)
                                            Disconnect();

                                        break;
                                    }
                                case DtmServiceFlags.Terminate:
                                    {
                                        // reserved
                                        DtmErrorEventArgs args = new DtmErrorEventArgs(new ApplicationException("The session was terminated by the remote host."), DtmErrorSeverity.Critical);
                                        if (SessionError != null)
                                            SessionError(this, args);

                                        Disconnect();
                                        break;
                                    }
                            }

                            break;
                        }
                    // file transfer
                    case DtmPacketTypes.Transfer:
                        {
                            switch ((DtmTransferFlags)pktHdr.PacketFlag)
                            {
                                case DtmTransferFlags.Request:
                                    {
                                        // received file transfer request
                                        ReceiveFile(PacketStream);
                                        break;
                                    }
                                case DtmTransferFlags.Refused:
                                    {
                                        // refused by remote
                                        DtmErrorEventArgs args = new DtmErrorEventArgs(new ApplicationException("The session was refused by the remote host."), DtmErrorSeverity.Connection);
                                        if (SessionError != null)
                                            SessionError(this, args);

                                        CloseTransfer(pktHdr.OptionFlag);
                                        break;
                                    }
                                case DtmTransferFlags.Received:
                                    {
                                        // refused by remote
                                        CloseTransfer(pktHdr.OptionFlag);
                                        break;
                                    }
                            }
                            break;
                        }
                    // key exchange
                    case DtmPacketTypes.Exchange:
                    {
                        // process message
                        switch ((DtmExchangeFlags)pktHdr.PacketFlag)
                        {
                            case DtmExchangeFlags.Connect:
                                {
                                    // received public id
                                    ProcessConnect(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Init:
                                {
                                    // received auth-stage params
                                    ProcessInit(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.PreAuth:
                                {
                                    // received public key
                                    ProcessPreAuth(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.AuthEx:
                                {
                                    // received symmetric key
                                    ProcessAuthEx(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Auth:
                                {
                                    // received private id
                                    ProcessAuth(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Sync:
                                {
                                    // received primary public key params
                                    ProcessSync(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Primary:
                                {
                                    // received primary public key
                                    ProcessPrimary(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.PrimeEx:
                                {
                                    // received primary session key
                                    ProcessPrimeEx(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Established:
                                {
                                    // received ack established
                                    ProcessEstablish(PacketStream);
                                    break;
                                }
                        }

                        break;
                    }
                    default:
                    {
                        if (SessionError != null)
                            SessionError(this, new DtmErrorEventArgs(new CryptoProcessingException("DtmKex:Process", "The data transmission encountered an error!", new InvalidDataException()), DtmErrorSeverity.Critical));
                        
                        break;
                    }
                }

                // notify app
                if (PacketReceived != null)
                    PacketReceived(this, new DtmPacketEventArgs(pktHdr.PacketFlag, pktHdr.PayloadLength));
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorEventArgs(new CryptoProcessingException("DtmKex:Process", "The data transmission encountered an error!", ex), DtmErrorSeverity.Critical));
            }
        }

        /// <summary>
        /// Resend a packet to a host
        /// </summary>
        private void Resend(DtmPacket Packet)
        {
            if (_sndBuffer.Exists(Packet.Sequence))
            {
                _maxSendCounter++;

                // limit attack scope with session resend max
                if (_maxSendCounter > MaxResend)
                {
                    // let the app decide what to do next
                    DtmErrorEventArgs args = new DtmErrorEventArgs(new InvalidDataException("The stream has encountered data loss, attempting to resync.."), DtmErrorSeverity.DataLoss);
                    if (SessionError != null)
                        SessionError(this, args);

                    if (args.Cancel)
                    {
                        Disconnect();
                        return;
                    }
                }

                try
                {
                    MemoryStream pktStm = _sndBuffer.Peek(Packet.Sequence);
                    if (pktStm != null)
                    {
                        if (pktStm.Length > 0)
                            pktStm.WriteTo(_clientSocket.TcpStream);

                        _sndSequence++;
                    }
                }
                catch 
                {
                    // packet lost, request a resync
                    Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.DataLost);
                }
            }
            else
            {
                // packet lost, request a resync
                Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.DataLost);
            }
        }

        /// <summary>
        /// Sends a packet with increasing wait times. 
        /// <para>After 4 attempts fires a SessionError with optional cancellation token.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">The packet to send</param>
        private void Throttle(MemoryStream PacketStream)
        {
            int maxwait = 10;

            for (int i = 0; i < 4; i++)
            {
                try
                {
                    Wait(maxwait);
                    _clientSocket.SendAsync(PacketStream);

                    break;
                }
                catch (CryptoSocketException ce)
                {
                    SocketException se = ce.InnerException as SocketException;

                    if (se.SocketErrorCode == SocketError.WouldBlock ||
                        se.SocketErrorCode == SocketError.IOPending ||
                        se.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                    {
                        // buffer is full
                        maxwait *= 2;
                    }
                    else
                    {
                        // possible connection dropped, alert app
                        if (SessionError != null)
                        {
                            DtmErrorEventArgs args = new DtmErrorEventArgs(ce, DtmErrorSeverity.Warning);
                            SessionError(this, args);

                            if (args.Cancel == true)
                                Disconnect();
                        }
                    }
                }
            }

            // all attempts have failed
            if (maxwait > 160)
            {
                // possible connection dropped, alert app
                if (SessionError != null)
                {
                    DtmErrorEventArgs args = new DtmErrorEventArgs(new SocketException((int)SocketError.HostUnreachable), DtmErrorSeverity.DataLoss);
                    SessionError(this, args);

                    if (args.Cancel == true)
                        Disconnect();
                }
            }
        }

        /// <summary>
        /// Frame and Transmit the packet to the remote client
        /// </summary>
        /// 
        /// <param name="PacketType">The packet class</param>
        /// <param name="PacketFlag">The packet message type flag</param>
        /// <param name="OptionFlag">The option flag</param>
        /// <param name="Payload">The packet payload flag</param>
        /// <param name="Blocking">Blocking or Async transmit</param>
        private void Transmit(DtmPacketTypes PacketType, short PacketFlag, long OptionFlag = 0, MemoryStream Payload = null, bool Blocking = false)
        {
            lock (_sendLock)
            {
                long pldLen = Payload == null ? 0 : Payload.Length;
                // create a new packet: packet flag, payload size, sequence, and state flag
                MemoryStream pktStm = new DtmPacket(PacketType, pldLen, _sndSequence, PacketFlag, OptionFlag).ToStream();

                // add payload
                if (Payload != null)
                {
                    // store total encrypted bytes sent
                    if (_isEstablished)
                        _bytesSent += Payload.Length;

                    // copy to output
                    pktStm.Seek(0, SeekOrigin.End);
                    Payload.WriteTo(pktStm);
                    pktStm.Seek(0, SeekOrigin.Begin);
                }

                // service requests are not buffered
                if (PacketType != DtmPacketTypes.Service)
                {
                    // store in the packet buffer
                    _sndBuffer.Push(_sndSequence, pktStm);
                }

                // increment send counter
                _sndSequence++;

                // transmit to remote client
                if (_clientSocket.IsConnected)
                {
                    if (Blocking)
                    {
                        try
                        {
                            _clientSocket.SendAsync(pktStm);
                        }
                        catch (CryptoSocketException ce)
                        {
                            SocketException se = ce.InnerException as SocketException;

                            if (se.SocketErrorCode == SocketError.WouldBlock ||
                                se.SocketErrorCode == SocketError.IOPending ||
                                se.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                            {
                                // buffer is full, slow down
                                Throttle(pktStm);
                            }
                            else if (se.SocketErrorCode != SocketError.Success)
                            {
                                // possible connection dropped, alert app
                                if (SessionError != null)
                                {
                                    DtmErrorEventArgs args = new DtmErrorEventArgs(ce, DtmErrorSeverity.Connection);
                                    SessionError(this, args);

                                    if (args.Cancel == true)
                                        Disconnect();
                                }
                            }
                        }
                    }
                    else
                    {
                        try
                        {
                            pktStm.WriteTo(_clientSocket.TcpStream);
                        }
                        catch (Exception ex)
                        {
                            // internal error, alert app
                            if (SessionError != null)
                            {
                                DtmErrorEventArgs args = new DtmErrorEventArgs(ex, DtmErrorSeverity.Critical);
                                SessionError(this, args);

                                if (args.Cancel == true)
                                    Disconnect();
                            }
                        }
                    }

                    // notify app
                    if (PacketSent != null)
                        PacketSent(this, new DtmPacketEventArgs((short)_exchangeState, pldLen));
                }
                else
                {
                    // possible connection dropped, alert app
                    if (SessionError != null)
                    {
                        DtmErrorEventArgs args = new DtmErrorEventArgs(new SocketException((int)SocketError.ConnectionReset), DtmErrorSeverity.Connection);
                        SessionError(this, args);

                        if (args.Cancel == true)
                            Disconnect();
                    }
                }
            }
        }

        /// <summary>
        /// Blocking transceiver; sends a packet and waits for a response.
        /// <para>For use with time sensitive data, that requires fast synchronous processing.
        /// Sent and received packets are not queued or buffered.</para>
        /// </summary>
        /// 
        /// <param name="DataStream">The payload data to send to the remote host</param>
        /// <param name="TimeOut">The number of milliseconds to wait before timing out (default is infinite)</param>
        /// 
        /// <returns>The return streams decrypted payload data, or an empty stream on failure</returns>
        public MemoryStream SendReceive(MemoryStream DataStream, int TimeOut = Timeout.Infinite)
        {
            if (!_isEstablished)
                throw new CryptoProcessingException("DtmKex:SendReceive", "The VPN is not established!", new InvalidOperationException());

            byte[] data = DataStream.ToArray();
            // append/prepend random
            data = WrapMessage(data, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt the data with the clients symmetric processor
            byte[] enc = SymmetricTransform(_srvSymProcessor, data);
            // store total bytes sent
            _bytesSent += enc.Length;

            // optional delay before transmission
            if (_dtmParameters.MaxMessageDelayMS > 0)
                SendWait(_dtmParameters.MaxMessageDelayMS);

            // create the packet
            MemoryStream pktStm = new DtmPacket(DtmPacketTypes.Message, enc.Length, _sndSequence, (short)DtmMessageFlags.Transmission).ToStream();
            pktStm.Seek(0, SeekOrigin.End);
            pktStm.Write(enc, 0, enc.Length);
            pktStm.Seek(0, SeekOrigin.Begin);
            // transmit data
            _clientSocket.Send(pktStm);
            _sndSequence++;

            // wait for response
            pktStm = BlockingReceive();
            // get the header
            DtmPacket dtmHdr = new DtmPacket(pktStm);
            // payload buffer
            data = new byte[dtmHdr.PayloadLength];
            // copy data to buffer
            pktStm.Write(data, 0, data.Length);
            // decrypt response
            data = SymmetricTransform(_cltSymProcessor, data);
            // remove padding
            data = UnwrapMessage(data);
            // increment rcv counter
            _rcvSequence++;
            // record encrypted byte count for resync
            _bytesReceived += dtmHdr.PayloadLength;

            return new MemoryStream(data);
        }
        #endregion

        #region KeepAlive
        /// <summary>
        /// Begins the keep alive timer
        /// </summary>
        private void StartPulse()
        {
            _pulseTimer = new System.Timers.Timer();
            _pulseTimer.Elapsed += new ElapsedEventHandler(OnTimerPulse);
            // 1 second intervals
            _pulseTimer.Interval = 1000;
            _pulseTimer.Start();
        }

        /// <summary>
        /// Stops the keep alive timer
        /// </summary>
        private void StopPulse()
        {
            if (_pulseTimer != null)
            {
                _pulseTimer.Stop();
                _pulseTimer.Dispose();
            }
        }

        /// <summary>
        /// The keep alive timer event handler
        /// </summary>
        private void OnTimerPulse(object sender, ElapsedEventArgs e)
        {
            _pulseCounter++;

            // default trigger is 30 seconds without a keep alive
            if (_pulseCounter > ConnectionTimeOut)
            {
                if (_autoReconnect)
                {
                    // attempt to reconnect
                    if (!Reconnect())
                    {
                        // connection unvailable
                        if (SessionError != null)
                        {
                            DtmErrorEventArgs args = new DtmErrorEventArgs(new SocketException((int)SocketError.ConnectionReset), DtmErrorSeverity.Critical);
                            SessionError(this, args);
                            Disconnect();
                        }
                    }
                    else
                    {
                        // resync the crypto stream
                        Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.DataLost);
                    }
                }
                else
                {
                    // possible connection dropped, alert app
                    if (SessionError != null)
                    {
                        DtmErrorEventArgs args = new DtmErrorEventArgs(new SocketException((int)SocketError.ConnectionReset), DtmErrorSeverity.Critical);
                        SessionError(this, args);

                        if (args.Cancel == true)
                            Disconnect();
                    }
                }
            }
            else
            {
                Transmit(DtmPacketTypes.Service, (short)DtmServiceFlags.KeepAlive);
            }
        }
        #endregion

        #region Reconnect
        /// <summary>
        /// Attempt to reconnect to the remote host
        /// </summary>
        /// 
        /// <returns>Returns true if connected</returns>
        public bool Reconnect()
        {
            if (_isDisconnecting)
                return false;

            try
            {
                if (_clientSocket.IsConnected)
                    _clientSocket.Close();
            }
            catch { }

            try
            {
                if (_isServer)
                {
                    _clientSocket.Listen(_clientSocket.LocalAddress, _clientSocket.LocalPort);

                    return _clientSocket.IsConnected;
                }
                else
                {
                    _clientSocket.Connect(_clientSocket.LocalAddress, _clientSocket.LocalPort, 10000);

                    return _clientSocket.IsConnected;
                }

            }
            catch
            {
                return false;
            }
        }
        #endregion

        #region Resync
        /// <summary>
        /// Creates a Resync packet.
        /// <para>The packet contains the encrypted identity field, 
        /// used to test for a successful resyning of the crypto stream.</para>
        /// </summary>
        /// 
        /// <returns>A resync packet payload</returns>
        private MemoryStream CreateResync()
        {
            // wrap the id
            byte[] data = WrapMessage(_srvIdentity.Identity, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt with servers session key
            byte[] enc = SymmetricTransform(_srvSymProcessor, data);

            return new MemoryStream(enc);
        }

        /// <summary>
        /// Used to process a resync response.
        /// <para>The remote host has sent the number of bytes encrypted as the OptionFlag in the DtmPacket.
        /// The resynchronization of the crypto stream involves first encrypting an equal sized array, 
        /// and then testing for validity by decrypting the payload and comparing it to the stored client id.
        /// If the Resync fails, the client Disconnects, notifies the application, and performs a teardown of the VPN.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A resync packet</param>
        private void ProcessResync(MemoryStream PacketStream)
        {
            // get the header
            DtmPacket pktHdr = new DtmPacket(PacketStream);
            int len = (int)(pktHdr.OptionFlag - pktHdr.PayloadLength - _bytesReceived);

            if (len > 0)
            {
                byte[] pad = new byte[len];
                // sync the cipher stream
                SymmetricTransform(_cltSymProcessor, pad);
            }
            else if (len < 0)
            {
                // can't resync, alert user and disconnect
                DtmErrorEventArgs args = new DtmErrorEventArgs(new InvalidDataException("The data stream could not be resynced, connection aborted!"), DtmErrorSeverity.Critical);
                if (SessionError != null)
                    SessionError(this, args);

                Disconnect();
                return;
            }

            // read the packet
            byte[] data = new byte[pktHdr.PayloadLength];
            // get the encrypted data
            PacketStream.Read(data, 0, data.Length);
            // decrypt the payload
            byte[] id = SymmetricTransform(_cltSymProcessor, data);
            // remove random padding
            id = UnwrapMessage(id);

            // compare to stored id
            if (!ArrayUtils.AreEqual(id, _cltIdentity.Identity))
            {
                // resync failed, abort connection
                DtmErrorEventArgs args = new DtmErrorEventArgs(new InvalidDataException("The data stream could not be resynced, connection aborted!"), DtmErrorSeverity.Critical);
                if (SessionError != null)
                    SessionError(this, args);

                Disconnect();
                return;
            }
        }
        #endregion

        #region Post-Exchange Channels
        #region Receive
        /// <summary>
        /// Used to read a blocking message response
        /// </summary>
        private MemoryStream BlockingReceive()
        {
            MemoryStream pktStm = null;

            try
            {
                // get the header
                pktStm = _clientSocket.GetStreamData(DtmPacket.GetHeaderSize(), EXCHTIMEOUT);
                DtmPacket pktHdr = new DtmPacket(pktStm);

                // add the payload
                if (pktHdr.PayloadLength > 0)
                    _clientSocket.GetStreamData((int)pktHdr.PayloadLength, EXCHTIMEOUT).WriteTo(pktStm);

                pktStm.Seek(0, SeekOrigin.Begin);
            }
            catch (ObjectDisposedException)
            {
                // host is disconnected, notify app
                DtmErrorEventArgs args = new DtmErrorEventArgs(new SocketException((int)SocketError.HostDown), DtmErrorSeverity.Connection);
                if (SessionError != null)
                    SessionError(this, args);

                if (args.Cancel == true)
                    Disconnect();
            }

            if (pktStm == null || pktStm.Length == 0)
            {
                // exchange failed

                if (SessionError != null)
                    SessionError(this, new DtmErrorEventArgs(new SocketException((int)SocketError.HostUnreachable), DtmErrorSeverity.Critical));

                Disconnect();
            }

            return pktStm;
        }

        /// <summary>
        /// Used Post-Exchange to decrypt bytes received from the client
        /// </summary>
        /// 
        /// <param name="PacketStream">The stream containing the ciphertext</param>
        private void ReceiveMessage(Stream PacketStream)
        {
            if (!_isEstablished)
                throw new CryptoProcessingException("DtmKex:Receive", "The VPN has not been established!", new InvalidOperationException());

            // get the header
            DtmPacket pktHdr = new DtmPacket(PacketStream);
            // store total bytes received
            _bytesReceived += pktHdr.PayloadLength;
            byte[] enc = new byte[pktHdr.PayloadLength];
            // get the encrypted data
            PacketStream.Read(enc, 0, enc.Length);
            // decrypt it using servers processor
            byte[] dec = SymmetricTransform(_cltSymProcessor, enc);
            // remove padding
            dec = UnwrapMessage(dec);

            // return the data
            if (DataReceived != null)
            {
                DtmDataReceivedEventArgs args = new DtmDataReceivedEventArgs(new MemoryStream(dec), 0);
                DataReceived(this, args);
            }
        }
        #endregion

        #region Send
        /// <summary>
        /// Used Post-Exchange to encrypt data before it is sent to the client
        /// </summary>
        /// 
        /// <param name="PacketStream">The stream containing the data to encrypt</param>
        public void Send(Stream PacketStream)
        {
            if (!_isEstablished)
                throw new CryptoProcessingException("DtmKex:Send", "The VPN has not been established!", new InvalidOperationException());

            byte[] enc;
            int len = (int)(PacketStream.Length - PacketStream.Position);
            byte[] data = new byte[len];
            PacketStream.Read(data, 0, data.Length);

            // append/prepend random
            data = WrapMessage(data, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt the data with the clients symmetric processor
            enc = SymmetricTransform(_srvSymProcessor, data);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);

            // optional delay before transmission
            if (_dtmParameters.MaxMessageDelayMS > 0)
                SendWait(_dtmParameters.MaxMessageDelayMS);

            // send to client
            Transmit(DtmPacketTypes.Message, (short)DtmMessageFlags.Transmission, 0, pldStm);
        }
        #endregion

        #region Receive File
        /// <summary>
        /// Used Post-Exchange to setup a file transfer from the remote host
        /// </summary>
        /// 
        /// <param name="PacketStream">The stream containing the file transfer request</param>
        private void ReceiveFile(Stream PacketStream)
        {
            // asynchronous transfer by sending a file key and info, and running the entire transfer on another socket..
            if (!_isEstablished)
                throw new CryptoProcessingException("DtmKex:ReceiveFile", "The VPN has not been established!", new InvalidOperationException());
            if (FileRequest == null)
                throw new CryptoProcessingException("DtmKex:ReceiveFile", "The FileRequest and FileReceived must be connected to perform a file transfer, read the documentation!", new InvalidOperationException());
            if (FileReceived == null)
                throw new CryptoProcessingException("DtmKex:ReceiveFile", "The FileRequest and FileReceived must be connected to perform a file transfer, read the documentation!", new InvalidOperationException());

            // get the header
            DtmPacket pktHdr = new DtmPacket(PacketStream);
            // read the packet
            byte[] enc = new byte[pktHdr.PayloadLength];
            // get the encrypted data
            PacketStream.Read(enc, 0, enc.Length);
            // decrypt it using client crypto processor
            byte[] dec = SymmetricTransform(_cltSymProcessor, enc);
            // remove padding
            dec = UnwrapMessage(dec);
            MemoryStream pktStm = new MemoryStream(dec);

            // get file info header
            DtmFileInfo pktFi = new DtmFileInfo(pktStm);
            // get the key
            KeyParams fileKey = KeyParams.DeSerialize(pktStm);

            // forward request to app
            DtmFileRequestEventArgs args = new DtmFileRequestEventArgs(pktFi.FileName);
            FileRequest(this, args);

            // accept file or refuse and exit; app must send back a valid path or cancel; if cancel, send a refuse notice which will signal the end of the transfer, otherwise store file path and port
            if (args.Cancel || string.IsNullOrEmpty(args.FilePath) || args.FilePath.Equals(pktFi.FileName) || !Directory.Exists(Path.GetDirectoryName(args.FilePath)))
            {
                // send refuse and exit
                Transmit(DtmPacketTypes.Transfer, (short)DtmTransferFlags.Refused, pktHdr.OptionFlag);
            }
            else
            {
                // create the files crypto processor
                ICipherMode fileSymProcessor = SymmetricInit(_cltIdentity.Session, fileKey);
                // enable parallel decryption
                int blockSize = ((int)MessageBufferSize - DtmPacket.GetHeaderSize()) - ((int)MessageBufferSize - DtmPacket.GetHeaderSize()) % ((CTR)fileSymProcessor).ParallelMinimumSize;
                ((CTR)fileSymProcessor).ParallelBlockSize = blockSize;

                // init the file transfer host
                DtmFileTransfer fileTransfer = new DtmFileTransfer(fileSymProcessor, pktHdr.OptionFlag, 1024, (int)FileBufferSize);
                fileTransfer.FileTransferred += new DtmFileTransfer.FileTransferredDelegate(OnFileReceived);
                fileTransfer.ProgressPercent += new DtmFileTransfer.ProgressDelegate(OnFileReceivedProgress);
                // add to dictionary
                _transQueue.TryAdd(pktHdr.OptionFlag, fileTransfer);

                try
                {
                    // start the transfer on a new thread
                    Task socketTask = Task.Factory.StartNew(() =>
                    {
                        fileTransfer.StartReceive(_clientSocket.RemoteAddress, (int)pktFi.OptionsFlag, args.FilePath);
                    });
                    socketTask.Wait(10);
                }
                catch (AggregateException ae)
                {
                    if (SessionError != null)
                        SessionError(this, new DtmErrorEventArgs(ae.GetBaseException(), DtmErrorSeverity.Warning));
                }
            }
        }

        /// <summary>
        /// Fires when a file received operation has completed
        /// </summary>
        private void OnFileReceived(object owner, DtmPacketEventArgs args)
        {
            if (FileReceived != null)
                FileReceived(this, args);

            lock (_fileLock)
            {
                // ackowledge file received and cleanup
                Transmit(DtmPacketTypes.Transfer, (short)DtmTransferFlags.Received, args.OptionFlag);
                Wait(10);
                // close processor
                CloseTransfer(args.OptionFlag);
            }
        }

        /// <summary>
        /// Fires when a file receive operation completes
        /// </summary>
        private void OnFileReceivedProgress(object sender, System.ComponentModel.ProgressChangedEventArgs e)
        {
            if (ProgressPercent != null)
                ProgressPercent(this, e);
        }
        #endregion

        #region Send File
        /// <summary>
        /// Used to initialize the file transfer sequence.
        /// <para>Sends a file request with the file id, name, and size.</para>
        /// </summary>
        /// 
        /// <param name="FilePath">The full path to the file to send</param>
        public void SendFile(string FilePath)
        {
            // store file length
            long len = new FileInfo(FilePath).Length;
            // increment file id
            _fileCounter++;
            // get an open port
            int port = _clientSocket.NextOpenPort();
            // create the file info header
            byte[] btInfo = new DtmFileInfo(Path.GetFileName(FilePath), len, port).ToBytes();

            // create a new symmetric key 
            KeyParams fileKey = GenerateSymmetricKey(_srvIdentity.Session);
            MemoryStream keyStrm = (MemoryStream)KeyParams.Serialize(fileKey);
            // add the key
            btInfo = ArrayUtils.Concat(btInfo, keyStrm.ToArray());

            // wrap the request
            btInfo = WrapMessage(btInfo, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt with master
            btInfo = SymmetricTransform(_srvSymProcessor, btInfo);

            // initialize the files unique crypto processor
            ICipherMode fileSymProcessor = SymmetricInit(_srvIdentity.Session, fileKey);
            // tune for parallel processing
            int blockSize = ((int)MessageBufferSize - DtmPacket.GetHeaderSize()) - ((int)MessageBufferSize - DtmPacket.GetHeaderSize()) % ((CTR)fileSymProcessor).ParallelMinimumSize;
            ((CTR)fileSymProcessor).ParallelBlockSize = blockSize;

            // build the file transfer instance
            DtmFileTransfer fileTransfer = new DtmFileTransfer(fileSymProcessor, _fileCounter, 1024, (int)FileBufferSize);
            fileTransfer.FileTransferred += new DtmFileTransfer.FileTransferredDelegate(OnFileSent);
            fileTransfer.ProgressPercent += new DtmFileTransfer.ProgressDelegate(OnFileSentProgress);
            // add to dictionary
            _transQueue.TryAdd(_fileCounter, fileTransfer);

            // send header to the remote host in a file request
            Transmit(DtmPacketTypes.Transfer, (short)DtmTransferFlags.Request, _fileCounter, new MemoryStream(btInfo));

            // initiate with non-blocking listen
            fileTransfer.StartSend(_clientSocket.LocalAddress, port, FilePath);

            if (fileTransfer.IsConnected)
            {
                try
                {
                    // start on a new thread
                    Task socketTask = Task.Factory.StartNew(() =>
                    {
                        fileTransfer.SendFile();
                    });
                    socketTask.Wait(10);
                }
                catch (AggregateException ae)
                {
                    if (SessionError != null)
                        SessionError(this, new DtmErrorEventArgs(ae.GetBaseException(), DtmErrorSeverity.Warning));
                }
            }
            else
            {
                // remove from pending and dispose
                CloseTransfer(_fileCounter);

                // alert app
                DtmErrorEventArgs args = new DtmErrorEventArgs(new SocketException((int)SocketError.ConnectionAborted), DtmErrorSeverity.Connection);
                if (SessionError != null)
                    SessionError(this, args);

                if (args.Cancel == true)
                    Disconnect();
            }
        }

        /// <summary>
        /// Removes a file transfer instance from the queue
        /// </summary>
        private void CloseTransfer(long FileId)
        {
            lock (_fileLock)
            {
                if (_transQueue.ContainsKey(FileId))
                {
                    DtmFileTransfer fileTransfer = null;
                    _transQueue.TryRemove(FileId, out fileTransfer);

                    try
                    {
                        if (fileTransfer != null)
                            fileTransfer.Dispose();
                    }
                    catch { }
                }
            }
        }

        /// <summary>
        /// Fires when a file send operation completes
        /// </summary>
        private void OnFileSent(object owner, DtmPacketEventArgs args)
        {
            if (FileSent != null)
                FileSent(this, args);
        }

        /// <summary>
        /// File send progress event handler
        /// </summary>
        private void OnFileSentProgress(object sender, System.ComponentModel.ProgressChangedEventArgs e)
        {
            if (ProgressPercent != null)
                ProgressPercent(this, e);
        }
        #endregion
        #endregion

        #region Exchange Staging
        // Functions are in order of execution. The Create functions create a reponse packet, the Process functions process the result.

        /// <summary>
        /// Send the servers partial public identity structure <see cref="DtmIdentity"/>.
        /// <para>The packet header; <see cref="DtmPacket"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers public identity field in a default DtmIdentity structure.</para>
        /// </summary>
        /// 
        /// <param name="Trust">The level of trust expected (for future use)</param>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers public identity structure</returns>
        private MemoryStream CreateConnect(DtmTrustStates Trust = DtmTrustStates.None)
        {
            // the option flag on the DtmIdentity can be used to indicate the session keys expiry time.
            // create a partial id and add auth asymmetric and session params.
            MemoryStream sid = new DtmIdentity(_srvIdentity.Identity, new byte[] { 0, 0, 0, 0 }, new DtmSession(), 0).ToStream();
            // stage completed
            _exchangeState = DtmExchangeFlags.Connect;

            return sid;
        }

        /// <summary>
        /// Processes the clients public identity field for preliminary authentication.
        /// <para>Process the clients partial Auth-Stage public identity structure; <see cref="DtmIdentity"/></para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        /// 
        /// <remarks>
        /// Fires the <see cref="IdentityReceived"/> event; returning the <see cref="DtmIdentityEventArgs"/> object containing the clients public id structure.
        /// <para>The session can be aborted by setting the DtmIdentityEventArgs Cancel flag to true.</para>
        /// </remarks>
        private void ProcessConnect(MemoryStream PacketStream)
        {
            // seek past header
            PacketStream.Seek(DtmPacket.GetHeaderSize(), SeekOrigin.Begin);
            // get the clients id structure
            _cltIdentity = new DtmIdentity(PacketStream);

            // pass it to the client, evaluate the id
            long resp = 0;
            if (IdentityReceived != null)
            {
                DtmIdentityEventArgs args = new DtmIdentityEventArgs(DtmExchangeFlags.Init, 0, _cltIdentity);
                IdentityReceived(this, args);
                // this flag is the trust level
                resp = args.Flag;
                if (args.Cancel)
                {
                    // back out of session
                    TearDown();
                }
            }
        }

        /// <summary>
        /// Send the servers full public identity structure <see cref="DtmIdentity"/>; contains the public id field, the asymmetric parameters, and the symmetric session parameters.
        /// <para>The packet header; <see cref="DtmPacket"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers preliminary identity structure (DtmIdentity), containing the public id field, the session key parameters <see cref="DtmSession"/>, and the
        /// Auth-Stage PKE parameters OId.</para>
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers public identity structure</returns>
        private MemoryStream CreateInit()
        {
            // create a partial id and add auth asymmetric and session params
            MemoryStream sid = _srvIdentity.ToStream();
            // stage completed
            _exchangeState = DtmExchangeFlags.Init;

            return sid;
        }

        /// <summary>
        /// Processes the clients public identity and clients Auth-Stage PKE parameter set Id; <see cref="IAsymmetricParameters"/>.
        /// <para>Process the clients Auth-Stage public identity structure; <see cref="DtmIdentity"/></para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        /// 
        /// <remarks>Fires the <see cref="IdentityReceived"/> event; returning the <see cref="DtmIdentityEventArgs"/> object containing the clients public id structure.
        /// <para>The session can be aborted by setting the DtmIdentityEventArgs Cancel flag to true.</para>
        /// </remarks>
        private void ProcessInit(MemoryStream PacketStream)
        {
            // seek past header
            PacketStream.Seek(DtmPacket.GetHeaderSize(), SeekOrigin.Begin);
            // get the clients id structure
            _cltIdentity = new DtmIdentity(PacketStream);
            // get client asymmetric params
            _cltAsmParams = GetAsymmetricParams(_cltIdentity.PkeId);
            // store the auth session
            _cltAuthSession = _cltIdentity.Session;

            // pass it to the client again, so it can be refused on basis of params
            long resp = 0;
            if (IdentityReceived != null)
            {
                DtmIdentityEventArgs args = new DtmIdentityEventArgs(DtmExchangeFlags.Init, 0, _cltIdentity);
                IdentityReceived(this, args);
                resp = args.Flag;
                if (args.Cancel)
                {
                    // back out of session
                    TearDown();
                }
            }
        }

        /// <summary>
        /// Send the servers Auth-Stage Asymmetric Public key; <see cref="IAsymmetricKey"/>, built using the PKE params id from the servers identity structure.
        /// <para>The packet header; <see cref="DtmPacket"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers Auth-Stage asymmetric Public Key.</para>
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers Auth-Stage asymmetric Public Key</returns>
        private MemoryStream CreatePreAuth()
        {
            // server asym params
            _srvAsmParams = GetAsymmetricParams(_srvIdentity.PkeId);
            // generate the servers auth-stage key pair
            _authKeyPair = GenerateAsymmetricKeyPair(_srvAsmParams);
            // serialize servers public key
            MemoryStream pbk = _authKeyPair.PublicKey.ToStream();
            // stage completed
            _exchangeState = DtmExchangeFlags.PreAuth;

            return pbk;
        }

        /// <summary>
        /// Processes the clients Auth-Stage <see cref="IAsymmetricKey">AsymmetricKey</see> Public key.
        /// <para>Stores the clients Auth-Stage Asymmetric Public Key.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessPreAuth(MemoryStream PacketStream)
        {
            // seek past header
            PacketStream.Seek(DtmPacket.GetHeaderSize(), SeekOrigin.Begin);
            // get client params from option flag
            _cltAsmParams = GetAsymmetricParams(_cltIdentity.PkeId);
            // store client public key
            _cltPublicKey = GetAsymmetricPublicKey(PacketStream, _cltAsmParams);
        }

        /// <summary>
        /// Send the servers Auth-Stage Symmetric <see cref="KeyParams"/>, encrypted with the clients Public Key.
        /// <para>The packet header; <see cref="DtmPacket"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers Auth-Stage Symmetric KeyParams, encrypted with the clients Asymmetric Public Key.</para>
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers Auth-Stage Symmetric Key</returns>
        private MemoryStream CreateAuthEx()
        {
            // create a session key based on servers symmetric session params
            _srvKeyParams = GenerateSymmetricKey(_srvIdentity.Session);
            // serialize the keyparams structure
            byte[] srvKrw = ((MemoryStream)KeyParams.Serialize(_srvKeyParams)).ToArray();
            // encrypt the servers symmetric key with the clients public key
            byte[] enc = AsymmetricEncrypt(_cltAsmParams, _cltPublicKey, srvKrw);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.AuthEx;

            // optional delay before transmission
            if (_dtmParameters.MaxSymKeyDelayMS > 0)
                SendWait(_dtmParameters.MaxSymKeyDelayMS, _dtmParameters.MaxSymKeyDelayMS / 2);

            return pldStm;
        }

        /// <summary>
        /// Processes and stores the clients Auth-Stage Symmetric <see cref="KeyParams"/>, 
        /// decrypted with the servers <see cref="IAsymmetricKeyPair">Asymmetric KeyPair</see>.
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessAuthEx(MemoryStream PacketStream)
        {
            // get the header
            DtmPacket pktHdr = new DtmPacket(PacketStream);
            // read the data
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // decrypt the symmetric key
            byte[] dec = AsymmetricDecrypt(_srvAsmParams, _authKeyPair, data);
            // deserialize the keyparams structure
            _cltKeyParams = KeyParams.DeSerialize(new MemoryStream(dec));
        }

        /// <summary>
        /// Sends the servers private identity; <see cref="DtmIdentity"/>, encrypted with the servers Symmetric Key.
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers private identity</returns>
        private MemoryStream CreateAuth()
        {
            // send secret id and return auth status in options flag
            _srvIdentity.Identity = _dtmHost.SecretId;
            // create the servers auth-stage symmetric cipher
            _srvSymProcessor = SymmetricInit(_srvIdentity.Session, _srvKeyParams);
            byte[] data = _srvIdentity.ToBytes();
            // wrap the id with random
            data = WrapMessage(data, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt the identity
            byte[] enc = SymmetricTransform(_srvSymProcessor, data);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.Auth;

            return pldStm;
        }

        /// <summary>
        /// Process the clients private identity.
        /// <para>Decrypts and stores the clients private identity using the clients Auth-Stage Symmetric Key.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessAuth(MemoryStream PacketStream)
        {
            // get the header
            DtmPacket pktHdr = new DtmPacket(PacketStream);
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // create the clients auth-stage symmetric cipher
            _cltSymProcessor = SymmetricInit(_cltIdentity.Session, _cltKeyParams);
            // decrypt the payload
            byte[] dec = SymmetricTransform(_cltSymProcessor, data);
            // remove random padding
            dec = UnwrapMessage(dec);
            // get the clients private id
            _cltIdentity = new DtmIdentity(new MemoryStream(dec));

            // notify user
            long resp = 0;
            if (IdentityReceived != null)
            {
                DtmIdentityEventArgs args = new DtmIdentityEventArgs(DtmExchangeFlags.Auth, resp, _cltIdentity);
                IdentityReceived(this, args);
                resp = args.Flag;
                if (args.Cancel)
                {
                    // back out of session
                    TearDown();
                }
            }
        }

        /// <summary>
        /// Send the servers Primary-Stage session parameters in a <see cref="DtmIdentity"/> structure.
        /// <para>The packet header; <see cref="DtmPacket"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers identity structure (DtmIdentity), containing the secret id field, the session key parameters <see cref="DtmSession"/>, and the
        /// primary-stage PKE parameters Id.</para>
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers private identity</returns>
        private MemoryStream CreateSync()
        {
            // change to primary parameters
            _srvIdentity = new DtmIdentity(_dtmHost.SecretId, _dtmParameters.PrimaryPkeId, _dtmParameters.PrimarySession, 0);
            // serialize identity
            byte[] data = _srvIdentity.ToBytes();
            // wrap the id with random
            data = WrapMessage(data, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt with servers session key
            byte[] enc = SymmetricTransform(_srvSymProcessor, data);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.Sync;

            return pldStm;
        }

        /// <summary>
        /// Process the clients identity structure <see cref="DtmIdentity"/>.
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessSync(MemoryStream PacketStream)
        {
            // get the header
            DtmPacket pktHdr = new DtmPacket(PacketStream);
            // read the data
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // use clients symmetric key to decrypt data
            byte[] dec = SymmetricTransform(_cltSymProcessor, data);
            // remove random padding
            dec = UnwrapMessage(dec);
            // get the identity
            _cltIdentity = new DtmIdentity(dec);

            // pass id to the client, include oid
            long resp = 0;
            if (IdentityReceived != null)
            {
                DtmIdentityEventArgs args = new DtmIdentityEventArgs(DtmExchangeFlags.Init, _cltIdentity.OptionFlag, _cltIdentity);
                IdentityReceived(this, args);
                resp = args.Flag;
                if (args.Cancel)
                {
                    // back out of session
                    TearDown();
                }
            }

            // get the params oid
            _cltAsmParams = GetAsymmetricParams(_cltIdentity.PkeId);
        }

        /// <summary>
        /// Sends the servers Primary-Stage <see cref="IAsymmetricKey">AsymmetricKey</see> Public key.
        /// </summary>
        /// 
        /// <returns>A Stream containing the raw packet data</returns>
        private MemoryStream CreatePrimeEx()
        {
            // get the cipher parameters
            _srvAsmParams = GetAsymmetricParams(_srvIdentity.PkeId);
            // create new public key pair
            _primKeyPair = GenerateAsymmetricKeyPair(_srvAsmParams);
            // serailize the public key
            byte[] keyBytes = _primKeyPair.PublicKey.ToBytes();
            // pad public key
            keyBytes = WrapMessage(keyBytes, _dtmParameters.MaxAsmKeyAppend, _dtmParameters.MaxAsmKeyPrePend);
            // encrypt the servers public key
            byte[] enc = SymmetricTransform(_srvSymProcessor, keyBytes);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.PrimeEx;

            // optional wait random timeout
            if (_dtmParameters.MaxAsmKeyDelayMS > 0)
                SendWait(_dtmParameters.MaxAsmKeyDelayMS, _dtmParameters.MaxAsmKeyDelayMS / 2);

            return pldStm;
        }

        /// <summary>
        /// Processes the clients Primary-Stage <see cref="IAsymmetricKey">AsymmetricKey</see> Public key.
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessPrimeEx(MemoryStream PacketStream)
        {
            // get the header
            DtmPacket pktHdr = new DtmPacket(PacketStream);
            // read the data
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // use clients symmetric key to decrypt data
            byte[] dec = SymmetricTransform(_cltSymProcessor, data);
            // remove padding
            dec = UnwrapMessage(dec);
            MemoryStream cltStream = new MemoryStream(dec);
            // store the clients public key
            _cltPublicKey = GetAsymmetricPublicKey(cltStream, _cltAsmParams);
        }

        /// <summary>
        /// Sends the servers primary-stage Symmetric <see cref="KeyParams"/>.
        /// </summary>
        /// 
        /// <returns>A Stream containing the raw packet data</returns>
        private MemoryStream CreatePrimary()
        {
            // create the primary session key
            KeyParams tmpKey = GenerateSymmetricKey(_srvIdentity.Session);
            // serialize the keyparams structure
            byte[] srvKrw = ((MemoryStream)KeyParams.Serialize(tmpKey)).ToArray();
            // encrypt the symmetric key with the primary asymmetric cipher
            byte[] enc = AsymmetricEncrypt(_cltAsmParams, _cltPublicKey, srvKrw);
            // pad the encrypted key with random
            enc = WrapMessage(enc, _dtmParameters.MaxSymKeyAppend, _dtmParameters.MaxSymKeyPrePend);
            // encrypt the result with the auth symmetric key
            enc = SymmetricTransform(_srvSymProcessor, enc);
            // clear auth key
            _srvKeyParams.Dispose();
            // swap to primary symmetric key
            _srvKeyParams = tmpKey;
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.Primary;

            return pldStm;
        }

        /// <summary>
        /// Processes and stores the clients primary-stage Symmetric <see cref="KeyParams"/>, 
        /// decrypted with the servers <see cref="IAsymmetricKeyPair">Asymmetric KeyPair</see>.
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessPrimary(MemoryStream PacketStream)
        {
            // get the header
            DtmPacket pktHdr = new DtmPacket(PacketStream);
            // read the data
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // decrypt using the auth stage symmetric key
            data = SymmetricTransform(_cltSymProcessor, data);
            // remove random padding
            data = UnwrapMessage(data);
            // decrypt the symmetric key using the primary asymmetric cipher
            byte[] dec = AsymmetricDecrypt(_srvAsmParams, _primKeyPair, data);
            // clear auth key
            _cltKeyParams.Dispose();
            // deserialize the primary session key
            _cltKeyParams = KeyParams.DeSerialize(new MemoryStream(dec));
        }

        /// <summary>
        /// Notify that the VPN is established
        /// </summary>
        /// 
        /// <returns>A Stream containing the raw packet data</returns>
        private MemoryStream CreateEstablish()
        {
            MemoryStream pktStm = new DtmPacket(DtmPacketTypes.Exchange, 0, _sndSequence, (short)DtmExchangeFlags.Established).ToStream();

            // notify
            if (PacketSent != null)
                PacketSent(this, new DtmPacketEventArgs((short)_exchangeState, pktStm.Length));

            // stage completed
            _exchangeState = DtmExchangeFlags.Established;

            return pktStm;
        }

        /// <summary>
        /// The VPN is two-way established.
        /// <para>Note that SessionEstablished event is used, it is expected that processing will continue externally.
        /// In this case the post-exchange symmetric cipher instances are not initialized internally, 
        /// and the Send and Receive methods will throw an error, i.e. you can use either the event or the internal processors.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessEstablish(MemoryStream PacketStream)
        {
            // clear the auth processors
            _srvSymProcessor.Dispose();
            _cltSymProcessor.Dispose();

            // initialize the Send/Receive encryption ciphers
            _srvSymProcessor = SymmetricInit(_srvIdentity.Session, _srvKeyParams);
            _cltSymProcessor = SymmetricInit(_cltIdentity.Session, _cltKeyParams);

            // one or the other
            if (SessionEstablished != null)
            {
                // app can continue processing out of class; must set the DestroyEngine flag to false in the constructor if this class is to be disposed
                DtmEstablishedEventArgs args = new DtmEstablishedEventArgs(_clientSocket.Client, _srvSymProcessor, _cltSymProcessor, 0);
                SessionEstablished(this, args);
            }

            _isEstablished = true;
        }
        #endregion

        #region Crypto
        /// <summary>
        /// Decrypt an array with an asymmetric cipher
        /// </summary>
        private byte[] AsymmetricDecrypt(IAsymmetricParameters Parameters, IAsymmetricKeyPair KeyPair, byte[] Data)
        {
            using (IAsymmetricCipher cipher = GetAsymmetricCipher(Parameters))
            {
                if (cipher.GetType().Equals(typeof(NTRUEncrypt)))
                    ((NTRUEncrypt)cipher).Initialize(KeyPair);
                else
                    cipher.Initialize(KeyPair.PrivateKey);

                return cipher.Decrypt(Data);
            }
        }

        /// <summary>
        /// Encrypt an array with an asymmetric cipher
        /// </summary>
        private byte[] AsymmetricEncrypt(IAsymmetricParameters Parameters, IAsymmetricKey PublicKey, byte[] Data)
        {
            using (IAsymmetricCipher cipher = GetAsymmetricCipher(Parameters))
            {
                cipher.Initialize(PublicKey);
                return cipher.Encrypt(Data);
            }
        }

        /// <summary>
        /// Generat an asymmetric key-pair
        /// </summary>
        private IAsymmetricKeyPair GenerateAsymmetricKeyPair(IAsymmetricParameters Parameters)
        {
            using (IAsymmetricGenerator gen = GetAsymmetricGenerator(Parameters))
                _authKeyPair = gen.GenerateKeyPair();

            return (IAsymmetricKeyPair)_authKeyPair.Clone();
        }

        /// <summary>
        /// Generate a symmetric key
        /// </summary>
        private KeyParams GenerateSymmetricKey(DtmSession Session)
        {
            return new KeyParams(_rndGenerator.GetBytes(Session.KeySize), _rndGenerator.GetBytes(Session.IvSize));
        }

        /// <summary>
        /// Initialize the symmetric cipher
        /// </summary>
        private ICipherMode SymmetricInit(DtmSession Session, KeyParams Key)
        {
            ICipherMode cipher = GetSymmetricCipher(Session);
            cipher.Initialize(true, Key);

            return cipher;
        }

        /// <summary>
        /// Transform an array with the symmetric cipher
        /// </summary>
        private byte[] SymmetricTransform(ICipherMode Cipher, byte[] Data)
        {
            byte[] ptext = new byte[Data.Length];
            Cipher.Transform(Data, ptext);

            return ptext;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Creates a serialized request packet (DtmPacket)
        /// </summary>
        private MemoryStream CreateRequest(DtmPacketTypes Message, short State, int Sequence = 0)
        {
            return new DtmPacket(Message, 0, 0, State).ToStream();
        }

        /// <summary>
        /// Get the asymmetric cipher instance
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher parameters</param>
        /// 
        /// <returns>The cipher instance</returns>
        private IAsymmetricCipher GetAsymmetricCipher(IAsymmetricParameters Parameters)
        {
            IAsymmetricCipher cipher = null;

            try
            {
                if (Parameters.GetType().Equals(typeof(NTRUParameters)))
                    cipher = new NTRUEncrypt((NTRUParameters)Parameters);
                else if (Parameters.GetType().Equals(typeof(MPKCParameters)))
                    cipher = new MPKCEncrypt((MPKCParameters)Parameters);
                else if (Parameters.GetType().Equals(typeof(RLWEParameters)))
                    cipher = new RLWEEncrypt((RLWEParameters)Parameters);

                return cipher;
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("DtmKex:GetAsymmetricCipher", "The cipher could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Get the asymmetric generator instance
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher parameters</param>
        /// 
        /// <returns>The generator instance</returns>
        private IAsymmetricGenerator GetAsymmetricGenerator(IAsymmetricParameters Parameters)
        {
            IAsymmetricGenerator gen = null;

            try
            {
                if (Parameters.GetType().Equals(typeof(NTRUParameters)))
                    gen = new NTRUKeyGenerator((NTRUParameters)Parameters);
                else if (Parameters.GetType().Equals(typeof(MPKCParameters)))
                    gen = new MPKCKeyGenerator((MPKCParameters)Parameters);
                else if (Parameters.GetType().Equals(typeof(RLWEParameters)))
                    gen = new RLWEKeyGenerator((RLWEParameters)Parameters);

                return gen;
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("DtmKex:GetAsymmetricGenerator", "The generator could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Get the asymmetric parameters from a byte array
        /// </summary>
        /// 
        /// <param name="Data">The encoded parameters</param>
        /// 
        /// <returns>The asymmetric parameters</returns>
        private IAsymmetricParameters GetAsymmetricParams(byte[] Data)
        {
            IAsymmetricParameters param = null;

            try
            {
                if (Data.Length > 4)
                {
                    if (Data[0] == (byte)AsymmetricEngines.McEliece)
                        param = new MPKCParameters(Data);
                    else if (Data[0] == (byte)AsymmetricEngines.NTRU)
                        param = new NTRUParameters(Data);
                    else if (Data[0] == (byte)AsymmetricEngines.RingLWE)
                        param = new RLWEParameters(Data);
                }
                else
                {
                    if (Data[0] == (byte)AsymmetricEngines.McEliece)
                        param = MPKCParamSets.FromId(Data);
                    else if (Data[0] == (byte)AsymmetricEngines.NTRU)
                        param = NTRUParamSets.FromId(Data);
                    else if (Data[0] == (byte)AsymmetricEngines.RingLWE)
                        param = RLWEParamSets.FromId(Data);
                }

                return param;
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("DtmKex:GetAsymmetricParams", "The param set is unknown!", ex);
            }
        }

        /// <summary>
        /// Get the asymmetric public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The encoded public key</param>
        /// <param name="Parameters">The cipher parameters</param>
        /// 
        /// <returns>The public key</returns>
        private IAsymmetricKey GetAsymmetricPublicKey(Stream KeyStream, IAsymmetricParameters Parameters)
        {
            IAsymmetricKey key = null;

            try
            {
                if (Parameters.GetType().Equals(typeof(NTRUParameters)))
                    key = new NTRUPublicKey(KeyStream);
                else if (Parameters.GetType().Equals(typeof(MPKCParameters)))
                    key = new MPKCPublicKey(KeyStream);
                else if (Parameters.GetType().Equals(typeof(RLWEParameters)))
                    key = new RLWEPublicKey(KeyStream);

                return key;
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("DtmKex:GetAsymmetricPublicKey", "The public key could nt be loaded!", ex);
            }
        }

        /// <summary>
        /// Get the digest instance
        /// </summary>
        /// 
        /// <param name="Digest">The Digests enumeration member</param>
        /// 
        /// <returns>The hash digest instance</returns>
        private IDigest GetDigest(Digests Digest)
        {
            switch (Digest)
            {
                case Digests.Blake256:
                    return new Blake256();
                case Digests.Blake512:
                    return new Blake512();
                case Digests.Keccak256:
                    return new Keccak256();
                case Digests.Keccak512:
                    return new Keccak512();
                case Digests.Keccak1024:
                    return new Keccak1024();
                case Digests.SHA256:
                    return new SHA256();
                case Digests.SHA512:
                    return new SHA512();
                case Digests.Skein256:
                    return new Skein256();
                case Digests.Skein512:
                    return new Skein512();
                case Digests.Skein1024:
                    return new Skein1024();
                default:
                    throw new CryptoProcessingException("DtmKex:GetDigest", "The digest type is unknown!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the Prng instance
        /// </summary>
        /// 
        /// <param name="Prng">The Prngs enumeration member</param>
        /// 
        /// <returns>The Prng instance</returns>
        private IRandom GetPrng(Prngs Prng)
        {
            switch (Prng)
            {
                case Prngs.CTRPrng:
                    return new CTRPrng();
                case Prngs.DGCPrng:
                    return new DGCPrng();
                case Prngs.CSPRng:
                    return new CSPRng();
                case Prngs.BBSG:
                    return new BBSG();
                case Prngs.CCG:
                    return new CCG();
                case Prngs.MODEXPG:
                    return new MODEXPG();
                case Prngs.QCG1:
                    return new QCG1();
                case Prngs.QCG2:
                    return new QCG2();
                default:
                    throw new CryptoProcessingException("DtmKex:GetPrng", "The Prng type is unknown!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the symmetric cipher instance
        /// </summary>
        /// 
        /// <param name="Session">The session parameters</param>
        /// 
        /// <returns>The initialized cipher instance</returns>
        private ICipherMode GetSymmetricCipher(DtmSession Session)
        {
            switch ((BlockCiphers)Session.EngineType)
            {
                case BlockCiphers.RDX:
                    return new CTR(new RDX());
                case BlockCiphers.RHX:
                    return new CTR(new RHX((int)Session.RoundCount, (int)Session.IvSize, (Digests)Session.KdfEngine));
                case BlockCiphers.RSM:
                    return new CTR(new RSM((int)Session.RoundCount, (int)Session.IvSize, (Digests)Session.KdfEngine));
                case BlockCiphers.SHX:
                    return new CTR(new SHX((int)Session.RoundCount, (Digests)Session.KdfEngine));
                case BlockCiphers.SPX:
                    return new CTR(new SPX((int)Session.RoundCount));
                case BlockCiphers.TFX:
                    return new CTR(new TFX((int)Session.RoundCount));
                case BlockCiphers.THX:
                    return new CTR(new THX((int)Session.RoundCount, (Digests)Session.KdfEngine));
                case BlockCiphers.TSM:
                    return new CTR(new TSM((int)Session.RoundCount, (Digests)Session.KdfEngine));
                default:
                    throw new CryptoProcessingException("DtmKex:GetSymmetricCipher", "The symmetric cipher type is unknown!", new ArgumentException());
            }
        }

        /// <summary>
        /// Waits a maximum (random) number of milliseconds before resuming thread
        /// </summary>
        /// 
        /// <param name="WaitMaxMs">The maximum wait time in milliseconds</param>
        /// <param name="WaitMinMs">The minimum wait time in milliseconds</param>
        private void SendWait(int WaitMaxMs, int WaitMinMs = 0)
        {
            if (WaitMaxMs > 0)
            {
                int max;
                if (WaitMinMs > 0 && WaitMinMs < WaitMaxMs)
                    max  = _rndGenerator.Next(WaitMaxMs);
                else
                    max = _rndGenerator.Next(WaitMinMs, WaitMaxMs);

                if (_evtSendWait == null)
                    _evtSendWait = new ManualResetEvent(false);

                _evtSendWait.WaitOne(max);
                _evtSendWait.Set();
            }
        }

        /// <summary>
        /// Tear down the connection; destroys all structures provided by this class
        /// </summary>
        private void TearDown()
        {
            if (_rndGenerator != null)
            {
                _rndGenerator.Dispose();
                _rndGenerator = null;
            }
            if (_authKeyPair != null)
            {
                _authKeyPair.Dispose();
                _authKeyPair = null;
            }
            if (_cltAsmParams != null)
            {
                _cltAsmParams.Dispose();
                _cltAsmParams = null;
            }
            if (_cltPublicKey != null)
            {
                _cltPublicKey.Dispose();
                _cltPublicKey = null;
            }
            if (_primKeyPair != null)
            {
                _primKeyPair.Dispose();
                _primKeyPair = null;
            }
            // cipher streaming managed through class
            if (SessionEstablished == null || _disposeEngines == true)
            {
                if (_cltKeyParams != null)
                {
                    _cltKeyParams.Dispose();
                    _cltKeyParams = null;
                }
                if (_srvKeyParams != null)
                {
                    _srvKeyParams.Dispose();
                    _srvKeyParams = null;
                }
                if (_srvSymProcessor != null)
                {
                    _srvSymProcessor.Dispose();
                    _srvSymProcessor = null;
                }
                if (_cltSymProcessor != null)
                {
                    _cltSymProcessor.Dispose();
                    _cltSymProcessor = null;
                }
            }

            _bufferCount = 0;
            _bytesSent = 0;
            _bytesReceived = 0;
            _cltIdentity.Reset();
            _fileCounter = 0;
            _maxSendCounter = 0;
            _maxSendAttempts = MAXSNDATTEMPT;
            _rcvSequence = 0;
            _sndSequence = 0;
        }

        /// <summary>
        /// Removes random padding from a message array
        /// </summary>
        /// 
        /// <param name="Data">The message aray</param>
        /// 
        /// <returns>The unwrapped message</returns>
        private byte[] UnwrapMessage(byte[] Data)
        {
            DtmMessage msg = new DtmMessage(Data);
            int hdrLen = msg.GetHeaderSize();

            // remove prepended padding
            if (msg.MessagePrePend > 0)
                ArrayUtils.RemoveRange(ref Data, 0, (msg.MessagePrePend + hdrLen) - 1);
            else
                ArrayUtils.RemoveRange(ref Data, 0, hdrLen - 1);

            // remove appended padding
            if (msg.MessageAppend > 0)
            {
                int pos = Data.Length - msg.MessageAppend;
                ArrayUtils.RemoveRange(ref Data, pos, Data.Length - 1);
            }

            return Data;
        }

        /// <summary>
        /// Waits the number specified of milliseconds before resuming thread
        /// </summary>
        /// 
        /// <param name="WaitMs">The wait time in milliseconds; <c>0</c> = forever</param>
        private void Wait(int WaitMs)
        {
            if (_evtSendWait == null)
                _evtSendWait = new ManualResetEvent(false);

            if (WaitMs < 1)
            {
                // manual reset
                _evtSendWait.WaitOne();
            }
            else
            {
                _evtSendWait.WaitOne(WaitMs);
                _evtSendWait.Set();
            }
        }

        /// <summary>
        /// Wrap a message with random bytes
        /// </summary>
        /// 
        /// <param name="Data">The data to wrap</param>
        /// <param name="MaxAppend">The (random) maximum number of bytes to append</param>
        /// <param name="MaxPrepend">The (random) maximum number of bytes to prepend</param>
        /// 
        /// <returns>The wrapped array</returns>
        private byte[] WrapMessage(byte[] Data, int MaxAppend, int MaxPrepend)
        {
            // wrap the message in random and add a message header
            if (MaxAppend > 0 || MaxPrepend > 0)
            {
                byte[] rand = new byte[0];
                int apl = 0;
                int ppl = 0;
                int min = 0;

                // wrap the message with a random number of bytes
                if (MaxAppend > 0)
                {
                    min = MaxAppend / 2; // min is half
                    apl = _rndGenerator.Next(min, MaxAppend);
                }
                if (MaxPrepend > 0)
                {
                    min = MaxPrepend / 2;
                    ppl = _rndGenerator.Next(min, MaxPrepend);
                }

                int len = apl + ppl;
                if (len > 0)
                    rand = _rndGenerator.GetBytes(len);

                if (ppl > 0 && apl > 0)
                {
                    byte[][] rds = ArrayUtils.Split(rand, ppl);
                    Data = ArrayUtils.Concat(rds[0], Data, rds[1]);
                }
                else if (apl > 0)
                {
                    Data = ArrayUtils.Concat(Data, rand);
                }
                else if (ppl > 0)
                {
                    Data = ArrayUtils.Concat(rand, Data);
                }

                return ArrayUtils.Concat(new DtmMessage(apl, ppl).ToBytes(), Data);
            }
            else
            {
                return ArrayUtils.Concat(new DtmMessage(0, 0).ToBytes(), Data);
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                Disconnect();
                _isDisposed = true;
            }
        }
        #endregion
    }
}
