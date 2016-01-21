#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Principal Algorithms:
// An implementation of the Generalized Merkle Signature Scheme Asymmetric Signature Scheme.
// 
// Code Base Guides:
// Portions of this code based on the Bouncy Castle Based on the Bouncy Castle Java 
// <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.
// 
// Implementation Details:
// An implementation of an Generalized Merkle Signature Scheme. 
// Written by John Underhill, July 06, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS
{
    /// <summary>
    /// Creates, reads and writes parameter settings for GMSS.
    /// <para>Predefined parameter sets are available through the <see cref="GMSSParamSets"/> class.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create a parameter set and write to stream:</description>
    /// <code>
    /// MemoryStream ks = new MemoryStream();
    /// using (GMSSParameters mp = new GMSSParameters(new byte[] { 4, 1, 2, 1 }, new int[] { 19, 26, 32, 38, 49 }))
    ///    mp.WriteTo(ks);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/06/07" version="1.0.1.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.GMSSSign">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS GMSSSign Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.GMSSPublicKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS GMSSPublicKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.GMSSPrivateKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS GMSSPrivateKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKeyPair Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKey Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom">VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration Prngs Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Generalized Merkle Signature Scheme Parameter Description:</h4></description>
    /// <list type="table">
    /// <item><description>OId - Three bytes that uniquely identify the parameter set.</description></item>
    /// <item><description>Vi - An array containing the number of vinegar variables per layer.</description></item>
    /// <item><description>Engine - The Prng engine.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Selecting Parameters for the Generalized Merkle Signature Scheme Signature Scheme<cite>Generalized Merkle Signature Scheme Parameters</cite>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class GMSSParameters : IAsymmetricParameters
    {
        #region Constants
        private const int OID_SIZE = 4;
        private const string ALG_NAME = "GMSSParameters";
        #endregion

        #region Fields
        // The number of authentication tree layers
        private int _numLayers;
        // The height of the authentication trees of each layer
        private int[] _heightOfTrees;
        // The Winternitz Parameter 'w' of each layer
        private int[] _winternitzParameter;
        // The parameter K needed for the authentication path computation
        private int[] _K;
        private byte[] _oId;
        private bool _isDisposed = false;
        private Digests _dgtEngineType = Digests.SHA512;
        private Prngs _rndEngineType = Prngs.CTRPrng;
        #endregion

        #region Properties
        /// <summary>
        /// The hash engine type
        /// </summary>
        public Digests DigestEngine
        {
            get { return _dgtEngineType; }
            private set { _dgtEngineType = value; }
        }

        /// <summary>
        /// Get: Returns the array of height (for each layer) of the authentication trees
        /// </summary>
        public int[] HeightOfTrees
        {
            get { return _heightOfTrees; }
        }

        /// <summary>
        /// Get: Returns the parameter K needed for authentication path computation
        /// </summary>
        public int[] K
        {
            get { return _K; }
        }

        /// <summary>
        /// Get: Parameters name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Returns the number of levels of the authentication trees
        /// </summary>
        public int NumLayers
        {
            get { return _numLayers; }
        }

        /// <summary>
        /// Get: Four bytes that uniquely identify the parameter set
        /// </summary>
        public byte[] OId
        {
            get { return _oId; }
            private set { _oId = value; }
        }

        /// <summary>
        /// The random generator engine type
        /// </summary>
        public Prngs RandomEngine
        {
            get { return _rndEngineType; }
            private set { _rndEngineType = value; }
        }
        /// <summary>
        /// Get: Returns the array of WinternitzParameter (for each layer) of the authentication trees
        /// </summary>
        public int[] WinternitzParameter
        {
            get { return _winternitzParameter; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Intitialize this class
        /// </summary>
        /// 
        /// <param name="OId">OId - Unique identifier; <c>Family</c>, <c>Set</c>, <c>SubSet</c>, and <c>Designator</c>. The Generalized Merkle Signature Scheme family must be <c>4</c> corresponding with the <see cref="AsymmetricEngines"/> enumeration.</param>
        /// <param name="NumLayers">The number of authentication tree layers</param>
        /// <param name="HeightOfTrees">The height of the authentication trees of each layer</param>
        /// <param name="WinternitzParameter">The Winternitz Parameter 'w' of each layer</param>
        /// <param name="K">The parameter K needed for the authentication path computation</param>
        /// <param name="Digest">The hash engine type</param>
        /// <param name="RandomEngine">The random generator type</param>
        /// 
        /// <exception cref="System.ArgumentException">Thrown if the Vi or Oid settings are invalid</exception>
        public GMSSParameters(byte[] OId, int NumLayers, int[] HeightOfTrees, int[] WinternitzParameter, int[] K, Digests Digest = Digests.SHA256, Prngs RandomEngine = Prngs.CTRPrng)
        {
            if (OId.Length != OID_SIZE)
                throw new CryptoAsymmetricException("GMSSParameters:Ctor", string.Format("The OId is invalid, the OId length must be {0} bytes!", OID_SIZE, new ArgumentException()));
            if (OId[0] != (byte)AsymmetricEngines.GMSS)
                throw new CryptoAsymmetricException("GMSSParameters:Ctor", string.Format("The OId is invalid, first byte must be family designator ({0})!", AsymmetricEngines.GMSS, new ArgumentException()));

            _oId = OId;
            _dgtEngineType = Digest;
            _rndEngineType = RandomEngine;
            Initialize(NumLayers, HeightOfTrees, WinternitzParameter, K);
        }
                
        /// <summary>
        /// Reconstructs a GMSSParameters from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="ParamStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the Stream is unreadable</exception>
        public GMSSParameters(Stream ParamStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(ParamStream);
                int len;

                _oId = reader.ReadBytes(OID_SIZE);
                _dgtEngineType = (Digests)reader.ReadByte();
                _rndEngineType = (Prngs)reader.ReadByte();
                _numLayers = reader.ReadInt32();
                len = reader.ReadInt32();
                _heightOfTrees = ArrayEx.ToArray32(reader.ReadBytes(len));
                len = reader.ReadInt32();
                _winternitzParameter = ArrayEx.ToArray32(reader.ReadBytes(len));
                len = reader.ReadInt32();
                _K = ArrayEx.ToArray32(reader.ReadBytes(len));
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("GMSSParameters:CTor", "The GMSSParameters could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Assign default H, W, and K values based on a Power of 2^10, 2^20, or 2^30 signatures scale.
        /// <para>Ex. Values up to 10 creates 2^10 (1024) signatures, up to 20 2^20 (1048576) signatures, more than 20 = 2^40 (1099511627776) signatures created</para>
        /// </summary>
        /// 
        /// <param name="KeySize">Can be 0-10 (2^10), 10-20 (2^20), or 20+ (2^40)</param>
        public GMSSParameters(int KeySize = 10)
        {
            if (KeySize <= 10)
            {
                // create 2^10 keys
                int[] defh = { 10 };
                int[] defw = { 3 };
                int[] defk = { 2 };
                Initialize(defh.Length, defh, defw, defk);
            }
            else if (KeySize <= 20)
            {
                // create 2^20 keys
                int[] defh = { 10, 10 };
                int[] defw = { 5, 4 };
                int[] defk = { 2, 2 };
                Initialize(defh.Length, defh, defw, defk);
            }
            else
            {
                // create 2^40 keys, keygen lasts around 80 seconds
                int[] defh = { 10, 10, 10, 10 };
                int[] defw = { 9, 9, 9, 3 };
                int[] defk = { 2, 2, 2, 2 };
                Initialize(defh.Length, defh, defw, defk);
            }
        }

        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="ParamArray">The encoded key array</param>
        public GMSSParameters(byte[] ParamArray) :
            this(new MemoryStream(ParamArray))
        {
        }

        private GMSSParameters()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~GMSSParameters()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read an encoded Parameter set from a byte array
        /// </summary>
        /// 
        /// <param name="ParamArray">The byte array containing the parameters</param>
        /// 
        /// <returns>An initialized GMSSParameters class</returns>
        public static GMSSParameters From(byte[] ParamArray)
        {
            return new GMSSParameters(ParamArray);
        }

        /// <summary>
        /// Read an encoded Parameters set from a Stream
        /// </summary>
        /// 
        /// <param name="ParamStream">The Stream containing the encoded Parameter set</param>
        /// 
        /// <returns>An initialized GMSSParameters class</returns>
        public static GMSSParameters From(Stream ParamStream)
        {
            return new GMSSParameters(ParamStream);
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded byte array
        /// </summary>
        /// 
        /// <returns>GMSSParameters as a byte array</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the current Parameter set to an encoded Stream
        /// </summary>
        /// 
        /// <returns>GMSSParameters as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] data;

            writer.Write(_oId);
            writer.Write((byte)_dgtEngineType);
            writer.Write((byte)_rndEngineType);
            writer.Write(_numLayers);

            data = ArrayEx.ToBytes(_heightOfTrees);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayEx.ToBytes(_winternitzParameter);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayEx.ToBytes(_K);
            writer.Write(data.Length);
            writer.Write(data);
            writer.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes the GMSSParameters to a byte array
        /// </summary>
        /// 
        /// <param name="Output">Output array receiving the encoded Parameters</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the GMSSParameters to a byte array
        /// </summary>
        /// 
        /// <param name="Output">Output array receiving the encoded Parameters</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if The output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("GMSSParameters:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the GMSSParameters to a Stream
        /// </summary>
        /// 
        /// <param name="Output">The Output stream receiving the encoded Parameters</param>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (IOException e)
            {
                throw new CryptoAsymmetricException(e.Message);
            }
        }
        #endregion

        #region Private Methods
        private void Initialize(int Layers, int[] HeightOfTrees, int[] WinternitzParameter, int[] K)
        {
            _numLayers = Layers;

            if ((_numLayers != WinternitzParameter.Length) || (_numLayers != HeightOfTrees.Length) || (_numLayers != K.Length))
                throw new CryptoAsymmetricException("GMSSParameters:Ctor", "Unexpected parameterset format!", new ArgumentException());

            for (int i = 0; i < _numLayers; i++)
            {
                if ((K[i] < 2) || ((HeightOfTrees[i] - K[i]) % 2 != 0))
                    throw new CryptoAsymmetricException("GMSSParameters:Ctor", "Wrong parameter K (K >= 2 and H-K even required)!", new ArgumentException());

                if ((HeightOfTrees[i] < 4) || (WinternitzParameter[i] < 2))
                    throw new CryptoAsymmetricException("GMSSParameters:Ctor", "Wrong parameter H or w (H > 3 and w > 1 required)!", new ArgumentException());
            }

            _heightOfTrees = ArrayEx.Clone(HeightOfTrees);
            _winternitzParameter = ArrayEx.Clone(WinternitzParameter);
            _K = ArrayEx.Clone(K);
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int result = 1;

            for (int i = 0; i < _heightOfTrees.Length; i++)
                result += 31 * _heightOfTrees[i];
            for (int i = 0; i < _winternitzParameter.Length; i++)
                result += 31 * _winternitzParameter[i];
            for (int i = 0; i < _K.Length; i++)
                result += 31 * _K[i];

            result += 31 * (int)_dgtEngineType;
            result += 31 * _numLayers;

            return result;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (this == Obj)
                return true;
            if (Obj == null && this != null)
                return false;

            GMSSParameters other = (GMSSParameters)Obj;

            if (!Compare.IsEqual(_heightOfTrees, other.HeightOfTrees))
                return false;
            if (!Compare.IsEqual(_winternitzParameter, other.WinternitzParameter))
                return false;
            if (!Compare.IsEqual(_K, other.K))
                return false;
            if (_numLayers != other.NumLayers)
                return false;
            if (_dgtEngineType != other.DigestEngine)
                return false;

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this GMSSParameters instance
        /// </summary>
        /// 
        /// <returns>The GMSSParameters copy</returns>
        public object Clone()
        {
            return new GMSSParameters(_oId, _numLayers, _heightOfTrees, _winternitzParameter, _K, _dgtEngineType, _rndEngineType);
        }

        /// <summary>
        /// Create a deep copy of this GMSSParameters instance
        /// </summary>
        /// 
        /// <returns>The GMSSParameters copy</returns>
        public object DeepCopy()
        {
            return new GMSSParameters(ToStream());
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
                try
                {
                    _dgtEngineType = Digests.SHA256;
                    _rndEngineType = Prngs.CTRPrng;
                    _numLayers = 0;

                    if (_oId != null)
                    {
                        Array.Clear(_oId, 0, _oId.Length);
                        _oId = null;
                    }
                    if (_heightOfTrees != null)
                    {
                        Array.Clear(_heightOfTrees, 0, _heightOfTrees.Length);
                        _heightOfTrees = null;
                    }
                    if (_winternitzParameter != null)
                    {
                        Array.Clear(_winternitzParameter, 0, _winternitzParameter.Length);
                        _winternitzParameter = null;
                    }
                    if (_K != null)
                    {
                        Array.Clear(_K, 0, _K.Length);
                        _K = null;
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
