#region Directives
using System;
using System.Collections.Generic;
using System.Linq;
using VTDev.Libraries.CEXEngine.Crypto.Prng ;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Numeric
{
    /// <summary>
    /// Various array utilities including: AreEqual, ConCat, CopyOf, Fill and Reverse
    /// </summary>
    public static class ArrayUtils
    {
        /// <summary>
        /// Compare Lists for equality
        /// </summary>
        /// 
        /// <typeparam name="T">Type of list</typeparam>
        /// <param name="A">List instance A</param>
        /// <param name="B">List instance B</param>
        /// 
        /// <returns>True if lists are equal, otherwise false</returns>
        public static bool AreEqual<T>(List<T> A, List<T> B)
        {
            if (A.Except(B).ToList().Count > 0)
                return false;
            else if (B.Except(A).ToList().Count > 0)
                return false;

            return true;
        }

        /// <summary>
        /// Compare Byte Arrays
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(byte[] A, byte[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare Char Arrays
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(char[] A, char[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare Integer Arrays
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(int[] A, int[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Compare Integer Arrays
        /// </summary>
        /// 
        /// <param name="A">Array A</param>
        /// <param name="B">Array B</param>
        /// 
        /// <returns>Equal</returns>
        public static bool AreEqual(long[] A, long[] B)
        {
            int i = A.Length;

            if (i != B.Length)
                return false;

            while (i != 0)
            {
                --i;
                if (A[i] != B[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Concatenate 2 arrays
        /// </summary>
        /// 
        /// <param name="Arrays">Arrays to be joined</param>
        /// 
        /// <returns>Joined array</returns>
        public static byte[] Concat(params byte[][] Arrays)
        {
            int len = 0;
            for (int i = 0; i < Arrays.Length; i++)
                len += Arrays[i].Length;

            byte[] rv = new byte[len];
            int offset = 0;
            foreach (byte[] array in Arrays)
            {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        /// <summary>
        /// Concatenate 2 arrays
        /// </summary>
        /// 
        /// <param name="Arrays">Arrays to be joined</param>
        /// 
        /// <returns>Joined array</returns>
        [CLSCompliant(false)]
        public static int[] Concat(params int[][] Arrays)
        {
            int len = 0;
            for (int i = 0; i < Arrays.Length; i++)
                len += Arrays[i].Length;

            int[] rv = new int[len];
            int offset = 0;

            foreach (int[] array in Arrays)
            {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length * 4);
                offset += array.Length * 4;
            }
            return rv;
        }

        /// <summary>
        /// Concatenate 2 arrays
        /// </summary>
        /// 
        /// <param name="Arrays">Arrays to be joined</param>
        /// 
        /// <returns>Joined array</returns>
        [CLSCompliant(false)]
        public static long[] Concat(params long[][] Arrays)
        {
            int len = 0;
            for (int i = 0; i < Arrays.Length; i++)
                len += Arrays[i].Length;

            long[] rv = new long[len];
            int offset = 0;

            foreach (long[] array in Arrays)
            {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length * 4);
                offset += array.Length * 4;
            }
            return rv;
        }

        /// <summary>
        /// Create a copy of a BigDecimal array
        /// </summary>
        /// 
        /// <param name="Source">BigDecimal source</param>
        /// <param name="Length">Number of elements to copy</param>
        /// 
        /// <returns>BigDecimal array copy</returns>
        public static BigDecimal[] CopyOf(BigDecimal[] Source, int Length)
        {
            BigDecimal[] copy = new BigDecimal[Length];
            Array.Copy(Source, copy, Math.Min(Source.Length, Length));

            return copy;
        }

        /// <summary>
        /// Create a copy of a BigInteger array
        /// </summary>
        /// 
        /// <param name="Source">BigInteger source</param>
        /// <param name="Length">Number of elements to copy</param>
        /// 
        /// <returns>BigInteger array copy</returns>
        public static BigInteger[] CopyOf(BigInteger[] Source, int Length)
        {
            BigInteger[] copy = new BigInteger[Length];
            Array.Copy(Source, copy, Math.Min(Source.Length, Length));

            return copy;
        }

        /// <summary>
        /// Create a copy of a byte array
        /// </summary>
        /// 
        /// <param name="Source">Array source</param>
        /// <param name="Size">Number of elements to copy</param>
        /// 
        /// <returns>A copy of the source array</returns>
        public static byte[] CopyOf(byte[] Source, int Size)
        {
            byte[] copy = new byte[Size];
            Array.Copy(Source, copy, Math.Min(Source.Length, Size));

            return copy;
        }

        /// <summary>
        /// Create a copy of an int array
        /// </summary>
        /// 
        /// <param name="Source">Array source</param>
        /// <param name="Size">Number of elements to copy</param>
        /// 
        /// <returns>A copy of the source array</returns>
        public static int[] CopyOf(int[] Source, int Size)
        {
            int[] copy = new int[Size];
            Array.Copy(Source, copy, Math.Min(Source.Length, Size));

            return copy;
        }

        /// <summary>
        /// Create a copy of a long array
        /// </summary>
        /// 
        /// <param name="Source">Array source</param>
        /// <param name="Size">Number of elements to copy</param>
        /// 
        /// <returns>A copy of the source array</returns>
        public static long[] CopyOf(long[] Source, int Size)
        {
            long[] copy = new long[Size];
            Array.Copy(Source, copy, Math.Min(Source.Length, Size));

            return copy;
        }

        /// <summary>
        /// Create a ranged copy of a BigInteger array
        /// </summary>
        /// 
        /// <param name="Source">BigInteger source array</param>
        /// <param name="From">First element to copy</param>
        /// <param name="To">Last element to copy</param>
        /// 
        /// <returns>BigInteger array copy</returns>
        public static BigInteger[] CopyOfRange(BigInteger[] Source, int From, int To)
        {
            int newLength = To - From;
            BigInteger[] copy = new BigInteger[newLength];

            if (newLength < 0)
                throw new Exception(From + " > " + To);

            Array.Copy(Source, From, copy, 0, Math.Min(Source.Length - From, newLength));

            return copy;
        }

        /// <summary>
        /// Create a ranged copy of a byte array
        /// </summary>
        /// 
        /// <param name="Source">Byte source array</param>
        /// <param name="From">First element to copy</param>
        /// <param name="To">Last element to copy</param>
        /// 
        /// <returns>Byte array copy</returns>
        public static byte[] CopyOfRange(byte[] Source, int From, int To)
        {
            int newLength = To - From;
            byte[] copy = new byte[newLength];

            if (newLength < 0)
                throw new Exception(From + " > " + To);

            Array.Copy(Source, From, copy, 0, Math.Min(Source.Length - From, newLength));

            return copy;
        }

        /// <summary>
        /// Create a ranged copy of an integer array
        /// </summary>
        /// 
        /// <param name="Source">Byte source array</param>
        /// <param name="From">First element to copy</param>
        /// <param name="To">Last element to copy</param>
        /// 
        /// <returns>Integer array copy</returns>
        public static int[] CopyOfRange(int[] Source, int From, int To)
        {
            int newLength = To - From;
            int[] copy = new int[newLength];

            if (newLength < 0)
                throw new Exception(From + " > " + To);

            Array.Copy(Source, From, copy, 0, Math.Min(Source.Length - From, newLength));

            return copy;
        }

        /// <summary>
        /// Create a ranged copy of a long integer array
        /// </summary>
        /// 
        /// <param name="Source">Byte source array</param>
        /// <param name="From">First element to copy</param>
        /// <param name="To">Last element to copy</param>
        /// 
        /// <returns>Long integer array copy</returns>
        public static long[] CopyOfRange(long[] Source, int From, int To)
        {
            int newLength = To - From;
            long[] copy = new long[newLength];

            if (newLength < 0)
                throw new Exception(From + " > " + To);

            Array.Copy(Source, From, copy, 0, Math.Min(Source.Length - From, newLength));

            return copy;
        }

        /// <summary>
        /// Initialize a jagged array
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Lengths">The arrays lengths</param>
        /// 
        /// <returns>Initialized jagged array</returns>
        public static T CreateJaggedArray<T>(params int[] Lengths)
        {
            return (T)InitializeJaggedArray(typeof(T).GetElementType(), 0, Lengths);
        }

        /// <summary>
        /// Fill a byte array with a value
        /// </summary>
        /// 
        /// <param name="Source">The source byte array</param>
        /// <param name="Value">The value used to fill the array</param>
        public static void Fill(byte[] Source, byte Value)
        {
            for (int i = 0; i < Source.Length; i++)
                Source[i] = Value;
        }

        /// <summary>
        /// Fill an integer array with a value
        /// </summary>
        /// 
        /// <param name="Source">The source integer array</param>
        /// <param name="Value">The value used to fill the array</param>
        public static void Fill(int[] Source, int Value)
        {
            for (int i = 0; i < Source.Length; i++)
                Source[i] = Value;
        }

        /// <summary>
        /// Fill a long integer array with a value
        /// </summary>
        /// 
        /// <param name="Source">The source long integer array</param>
        /// <param name="Value">The value used to fill the array</param>
        public static void Fill(long[] Source, long Value)
        {
            for (int i = 0; i < Source.Length; i++)
                Source[i] = Value;
        }

        /// <summary>
        /// Fill a byte array range with a value
        /// </summary>
        /// 
        /// <param name="Source">The source byte array</param>
        /// <param name="From">First element to copy</param>
        /// <param name="To">Last element to copy</param>
        /// <param name="Value">The value used to fill the array</param>
        public static void Fill(byte[] Source, int From, int To, byte Value)
        {
            for (int i = From; i < To; i++)
                Source[i] = Value;
        }

        /// <summary>
        /// Fill a integer array range with a value
        /// </summary>
        /// 
        /// <param name="Source">The source integer array</param>
        /// <param name="From">First element to copy</param>
        /// <param name="To">Last element to copy</param>
        /// <param name="Value">The value used to fill the array</param>
        public static void Fill(int[] Source, int From, int To, int Value)
        {
            for (int i = From; i < To; i++)
                Source[i] = Value;
        }

        /// <summary>
        /// Fill a long integer array range with a value
        /// </summary>
        /// 
        /// <param name="Source">The source long integer array</param>
        /// <param name="From">First element to copy</param>
        /// <param name="To">Last element to copy</param>
        /// <param name="Value">The value used to fill the array</param>
        public static void Fill(long[] Source, int From, int To, long Value)
        {
            for (int i = From; i < To; i++)
                Source[i] = Value;
        }

        /// <summary>
        /// Initialize a member of a jagged array
        /// </summary>
        /// 
        /// <param name="Type">Type of array</param>
        /// <param name="Index">Array index</param>
        /// <param name="Lengths">Array lengths</param>
        /// 
        /// <returns>The jagged array</returns>
        private static object InitializeJaggedArray(Type Type, int Index, int[] Lengths)
        {
            Array array = Array.CreateInstance(Type, Lengths[Index]);
            Type elementType = Type.GetElementType();

            if (elementType != null)
            {
                for (int i = 0; i < Lengths[Index]; i++)
                    array.SetValue(InitializeJaggedArray(elementType, Index + 1, Lengths), i);
            }

            return array;
        }

        /// <summary>
        /// Shuffle an array using the SecureRandom class
        /// </summary>
        /// 
        /// <typeparam name="T">Type of list</typeparam>
        /// <param name="List">The list instance</param>
        public static void Shuffle<T>(IList<T> List)
        {
            SecureRandom rnd = new SecureRandom();
            for (int i = 0; i < List.Count - 1; i++)
            {
                int index = (int)rnd.NextInt32(i, List.Count - 1);

                if (i != index)
                {
                    T temp = List[i];
                    List[i] = List[index];
                    List[index] = temp;
                }
            }
        }

        /// <summary>
        /// Reverse a byte array order and copy to an integer
        /// </summary>
        /// 
        /// <param name="Data">The byte array to reverse</param>
        /// 
        /// <returns>The reversed integer</returns>
        public static int ReverseBytes(byte[] Data)
        {
            // make a copy
            byte[] temp = new byte[Data.Length];
            Buffer.BlockCopy(Data, 0, temp, 0, Data.Length);
            // reverse and copy to int
            Array.Reverse(temp);
            int[] ret = new int[1];
            Buffer.BlockCopy(Data, 0, ret, 0, Data.Length);

            return ret[0];
        }

        /// <summary>
        /// Reverse the byte order of an integer
        /// </summary>
        /// 
        /// <param name="Value">The integer value to reverse</param>
        /// 
        /// <returns>The reversed integer</returns>
        public static int ReverseInteger(int Value)
        {
            int[] data = new int[] { Value };
            byte[] ret = new byte[4];

            Buffer.BlockCopy(data, 0, ret, 0, 4);
            Array.Reverse(ret);
            Buffer.BlockCopy(ret, 0, data, 0, 4);

            return data[0];
        }

        /// <summary>
        /// Copy an sbyte array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Sbyte array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(sbyte[] Data)
        {
            byte[] data = new byte[Data.Length];
            Buffer.BlockCopy(Data, 0, data, 0, Data.Length);
            return data;
        }

        /// <summary>
        /// Copy a string to an ASCII byte array
        /// </summary>
        /// 
        /// <param name="Value">String to copy</param>
        /// 
        /// <returns>The byte array representation</returns>
        public static byte[] ToBytes(string Value)
        {
            return System.Text.Encoding.ASCII.GetBytes(Value);
        }
    }
}
