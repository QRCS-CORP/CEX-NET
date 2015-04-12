using System;

namespace VTDev.Projects.CEX.CryptoGraphic
{
    internal class HKDF
    {
        private HMAC hMacHash;
        private int hashLen;
        private byte[] info = new byte[0];
        private byte[] currentT;
        private int generatedBytes;

        /// <summary>
        /// Creates a HKDFBytesGenerator based on the given hash function.
        /// </summary>
        /// <param name="hash">hash the digest to be used as the source of generatedBytes bytes</param>
        public HKDF(SHA256Digest hash)
        {
            this.hMacHash = new HMAC(hash);
            this.hashLen = hash.DigestSize;
        }

        public void Init(byte[] Seed)
        {
            hMacHash.Init(Seed);
            generatedBytes = 0;
            currentT = new byte[hashLen];
        }

        public int GenerateBytes(byte[] Out, int outOff, int len)
        {
            if (generatedBytes + len > 255 * hashLen)
            {
               // throw new DataLengthException(
               //     "HKDF may only be used for 255 * HashLen bytes of output");
            }

            if (generatedBytes % hashLen == 0)
            {
                ExpandNext();
            }

            // copy what is left in the currentT (1..hash
            int toGenerate = len;
            int posInT = generatedBytes % hashLen;
            int leftInT = hashLen - generatedBytes % hashLen;
            int toCopy = Math.Min(leftInT, toGenerate);
            Array.Copy(currentT, posInT, Out, outOff, toCopy);
            generatedBytes += toCopy;
            toGenerate -= toCopy;
            outOff += toCopy;

            while (toGenerate > 0)
            {
                ExpandNext();
                toCopy = Math.Min(hashLen, toGenerate);
                System.Array.Copy(currentT, 0, Out, outOff, toCopy);
                generatedBytes += toCopy;
                toGenerate -= toCopy;
                outOff += toCopy;
            }

            return len;
        }

        /// <summary>
        /// Performs the extract part of the key derivation function.
        /// </summary>
        /// <param name="salt">salt the salt to use</param>
        /// <param name="ikm">ikm  the input keying material</param>
        /// <returns>the PRK</returns>
        private byte[] Extract(byte[] salt, byte[] ikm)
        {
            hMacHash.Init(ikm);
            if (salt == null)
            {
                //Array.Clone(ikm);
                // TODO check if hashLen is indeed same as HMAC size
                hMacHash.Init(new byte[hashLen]);
            }
            else
            {
                hMacHash.Init(salt);
            }

            hMacHash.BlockUpdate(ikm, 0, ikm.Length);

            byte[] prk = new byte[hashLen];
            hMacHash.DoFinal(prk, 0);
            return prk;
        }

        /// <summary>
        /// Performs the expand part of the key derivation function, using currentT as input and output buffer.
        /// </summary>
        private void ExpandNext()
        {
            int n = generatedBytes / hashLen + 1;
            if (n >= 256)
            {
               // throw new DataLengthException(
               //     "HKDF cannot generate more than 255 blocks of HashLen size");
            }
            // special case for T(0): T(0) is empty, so no update
            if (generatedBytes != 0)
            {
                hMacHash.BlockUpdate(currentT, 0, hashLen);
            }
            hMacHash.BlockUpdate(info, 0, info.Length);
            hMacHash.Update((byte)n);
            hMacHash.DoFinal(currentT, 0);
        }
    }
}
