﻿using System;
using System.Security.Cryptography;
using System.Text;

namespace VTDev.Projects.CEX.Helper
{
    internal class DataProtect
    {
        #region Protected Storage
        public static byte[] DecryptProtectedData(byte[] Data, byte[] Salt)
        {
            if (Data == null) 
                return null;
            if (Data.Length < 1)
                return null;

            try
            {
                return ProtectedData.Unprotect(Data, Salt, DataProtectionScope.CurrentUser);
            }
            catch
            {
                throw;
            }
        }

        public static byte[] EncryptProtectedData(byte[] Data, byte[] Salt)
        {
            if (Data == null) 
                return null;
            if (Data.Length < 1) 
                return null;

            try
            {
                return ProtectedData.Protect(Data, Salt, DataProtectionScope.CurrentUser);
            }
            catch
            {
                throw;
            }
        }

        private static  byte[] ByteArrayFromString(string Data)
        {
            int length = Data.Length / 2;
            byte[] numArray = new byte[length];

            if (Data.Length > 0)
            {
                for (int i = 0; i < length; i++)
                    numArray[i] = byte.Parse(Data.Substring(2 * i, 2), System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture);
            }
            return numArray;
        }

        /// <summary>
        /// Encrypt a byte array
        /// </summary>
        /// <param name="Buffer">Buffer [byte[]]</param>
        public static void EncryptProtectedMemory(byte[] Buffer, MemoryProtectionScope Scope)
        {
            if (Buffer == null) 
                return;
            if (Buffer.Length < 1) 
                return;

            ProtectedMemory.Protect(Buffer, Scope);
        }

        /// <summary>
        /// Decrypt a buffer
        /// </summary>
        /// <param name="Buffer">Buffer [byte[]]</param>
        public static void DecryptProtectedMemory(byte[] Buffer, MemoryProtectionScope Scope)
        {
            if (Buffer == null) 
                return;
            if (Buffer.Length < 1) 
                return;

            ProtectedMemory.Unprotect(Buffer, Scope);
        }

        /// <summary>
        /// Encrypts a string
        /// </summary>
        /// <param name="Data">String to encrypt</param>
        /// <returns>Encrypted buffer [byte[]]</returns>
        public static byte[] EncryptProtectedString(string Data, MemoryProtectionScope Scope)
        {
            if (string.IsNullOrEmpty(Data)) return null;

            byte[] buffer = Encoding.GetEncoding("Latin1").GetBytes(Data);
            ProtectedMemory.Protect(buffer, Scope);
            return buffer;
        }

        /// <summary>
        /// Decrypts a string
        /// </summary>
        /// <param name="Buffer">Encrypted buffer</param>
        /// <returns>Decrypted data [string]</returns>
        public static string DecryptProtectedString(byte[] Buffer, MemoryProtectionScope Scope)
        {
            if (Buffer == null) 
                return string.Empty;
            if (Buffer.Length < 1) 
                return string.Empty;

            ProtectedMemory.Unprotect(Buffer, Scope);
            return Encoding.GetEncoding("Latin1").GetString(Buffer);
        }
        #endregion
    }
}
