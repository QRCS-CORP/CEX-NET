#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.Arithmetic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
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
// The Ring-LWE Asymmetric Cipher
// 
// Implementation Details:
// An implementation based on the description in the paper 'Efficient Software Implementation of Ring-LWE Encryption' 
// https://eprint.iacr.org/2014/725.pdf and accompanying Github project: https://github.com/ruandc/Ring-LWE-Encryption
// Written by John Underhill, June 8, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE
{
    /// <summary>
    /// This class implements key pair generation of the Ring-LWE Public Key Cryptosystem
    /// </summary>
    /// <example>
    /// <description>Example of creating a keypair:</description>
    /// <code>
    /// RLWEParameters ps = RLWEParamSets.RLWEN512Q12289;
    /// RLWEKeyGenerator gen = new RLWEKeyGenerator(ps);
    /// IAsymmetricKeyPair kp = gen.GenerateKeyPair();
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/06/07" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEEncrypt">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE RLWEEncrypt Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEPublicKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE RLWEPublicKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE.RLWEPrivateKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE RLWEPrivateKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKeyPair Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKey Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Efficient Software Implementation of Ring-LWE Encryption<cite>Ring-LWE Encryption</cite>.</description></item>
    /// <item><description>Compact Ring-LWE Cryptoprocessor<cite>Ring-LWE Cryptoprocessor</cite>.</description></item>
    /// <item><description>A Simple Provably Secure Key Exchange Scheme Based on the Learning with Errors Problem<cite>RLWE Scheme</cite>.</description></item>
    /// <item><description>The Knuth-Yao Quadrangle-Inequality Speedup is a Consequence of Total-Monotonicity<cite>Knuth-Yao Quadrangle-Inequality Speedup</cite>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Ring-LWE-Encryption C version: <see href="https://github.com/ruandc/Ring-LWE-Encryption">ruandc/Ring-LWE-Encryption</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class RLWEKeyGenerator : IAsymmetricGenerator
    {
        #region Constants
        private const string ALG_NAME = "RLWEKeyGenerator";
        #endregion

        #region Fields
        private bool _isDisposed;
        private RLWEParameters _rlweParams;
        private IRandom _rndEngine;
        private bool _frcLinear = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Generator name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CipherParams">The RLWEParameters instance containing the cipher settings</param>
        /// <param name="Parallel">Use parallel processing when generating a key; set to false if using a passphrase type generator (default is true)</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if a Prng that requires pre-initialization is specified; (wrong constructor)</exception>
        public RLWEKeyGenerator(RLWEParameters CipherParams, bool Parallel = true)
        {
            if (CipherParams.RandomEngine == Prngs.PBPrng)
                throw new CryptoAsymmetricException("RLWEKeyGenerator:Ctor", "Passphrase based digest and CTR generators must be pre-initialized, use the other constructor!", new ArgumentException());

            _frcLinear = ParallelUtils.ForceLinear;
            ParallelUtils.ForceLinear = !Parallel;
            _rlweParams = CipherParams;
            _rndEngine = GetPrng(CipherParams.RandomEngine);
        }

        /// <summary>
        /// Use an initialized prng to generate the key; use this constructor with an Rng that requires pre-initialization, i.e. PBPrng
        /// </summary>
        /// 
        /// <param name="CipherParams">The RLWEParameters instance containing the cipher settings</param>
        /// <param name="RngEngine">An initialized Prng instance</param>
        /// <param name="Parallel">Use parallel processing when generating a key; set to false if using a passphrase type generator (default is true)</param>
        public RLWEKeyGenerator(RLWEParameters CipherParams, IRandom RngEngine, bool Parallel = true)
        {
            _rlweParams = CipherParams;
            _rndEngine = RngEngine;
            _frcLinear = ParallelUtils.ForceLinear;

            // passphrase gens must be linear processed
            if (RngEngine.GetType().Equals(typeof(PBPRng)))
                ParallelUtils.ForceLinear = true;
            else
                ParallelUtils.ForceLinear = !Parallel;
        }

        private RLWEKeyGenerator()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWEKeyGenerator()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Generate an encryption Key pair
        /// </summary>
        /// 
        /// <returns>A RLWEKeyPair containing public and private keys</returns>
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            if (_rlweParams.N == 512)
                return new NTT512(_rndEngine).Generate();
            else
                return new NTT256(_rndEngine).Generate();
        }

        /// <summary>
        /// Generates an encryption key pair using a passphrase based prng.
        /// <para>Invoking this method with the same passphrase and salt will always return the same key pair.</para>
        /// </summary>
        /// 
        /// <param name="Passphrase">The passphrase</param>
        /// <param name="Salt">Salt for the passphrase; can be <c>null</c> but this is strongly discouraged</param>
        /// 
        /// <returns>A populated IAsymmetricKeyPair</returns>
        public IAsymmetricKeyPair GenerateKeyPair(byte[] Passphrase, byte[] Salt)
        {
            using (IDigest dgt = GetDigest(_rlweParams.Digest))
            {
                using (IRandom rnd = new PBPRng(dgt, Passphrase, Salt, 10000, false))
                    return GenerateKeyPair();
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="DigestType">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests DigestType)
        {
            try
            {
                return DigestFromName.GetInstance(DigestType);
            }
            catch
            {
                throw new CryptoRandomException("RLWEKeyGenerator:GetDigest", "The digest type is not recognized!", new ArgumentException());
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="PrngType">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        private IRandom GetPrng(Prngs PrngType)
        {
            try
            {
                return PrngFromName.GetInstance(PrngType);
            }
            catch
            {
                throw new CryptoAsymmetricException("RLWEKeyGenerator:GetPrng", "The Prng type is not supported!", new ArgumentException());
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            ParallelUtils.ForceLinear = _frcLinear;
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_rndEngine != null)
                    {
                        _rndEngine.Dispose();
                        _rndEngine = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
