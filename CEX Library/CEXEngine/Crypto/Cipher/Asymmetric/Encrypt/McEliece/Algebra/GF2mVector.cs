#region Directives
using System;
using System.Text;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class implements vectors over the finite field <c>GF(2^m)</c> for small <c>m</c> (i.e., <c>1&lt;m&lt;32</c>). It extends the abstract class Vector.
    /// </summary>
    internal sealed class GF2mVector : Vector
    {
        #region Fields
        //he finite field this vector is defined over
        private GF2mField _field;
        // the element array
        private int[] _vector;
        #endregion

        #region Properties
        /// <summary>
        /// The finite field this vector is defined over
        /// </summary>
        public GF2mField Field
        {
            get { return _field; }
        }

        /// <summary>
        /// The int[] form of this vector
        /// </summary>
        public int[] IntArrayForm
        {
            get { return IntUtils.DeepCopy(_vector); }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Creates the vector over GF(2^m) of given length and with elements from array V (beginning at the first bit)
        /// </summary>
        /// 
        /// <param name="Field">The finite field</param>
        /// <param name="V">An array with elements of vector</param>
        public GF2mVector(GF2mField Field, byte[] V)
        {
            _field = new GF2mField(Field);

            // decode vector
            int d = 8;
            int count = 1;
            while (Field.Degree > d)
            {
                count++;
                d += 8;
            }

            if ((V.Length % count) != 0)
                throw new ArgumentException("GF2mVector: Byte array is not an encoded vector over the given finite field!");

            Length = V.Length / count;
            _vector = new int[Length];
            count = 0;

            for (int i = 0; i < _vector.Length; i++)
            {
                for (int j = 0; j < d; j += 8)
                    _vector[i] |= (V[count++] & 0xff) << j;
                
                if (!Field.IsElementOfThisField(_vector[i]))
                    throw new ArgumentException("GF2mVector: Byte array is not an encoded vector over the given finite field!");
            }
        }

        /// <summary>
        /// Create a new vector over <c>GF(2^m)</c> of the given length and element array
        /// </summary>
        /// 
        /// <param name="Field">The finite field <c>GF(2^m)</c></param>
        /// <param name="Vector">The element array</param>
        public GF2mVector(GF2mField Field, int[] Vector)
        {
            _field = Field;
            Length = Vector.Length;
            for (int i = Vector.Length - 1; i >= 0; i--)
            {
                if (!Field.IsElementOfThisField(Vector[i]))
                    throw new ArithmeticException("Element array is not specified over the given finite field.");
            }
            _vector = IntUtils.DeepCopy(Vector);
        }

        /// <summary>
        /// The copy constructor
        /// </summary>
        /// 
        /// <param name="GF">The GF2mVector to copy</param>
        public GF2mVector(GF2mVector GF)
        {
            _field = new GF2mField(GF._field);
            Length = GF.Length;
            _vector = IntUtils.DeepCopy(GF._vector);
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Not implemented
        /// </summary>
        /// 
        /// <param name="Addend">The other vector</param>
        /// <returns>throws NotImplementedException</returns>
        public override Vector Add(Vector Addend)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Compare this vector with another object
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>The result of the comparison</returns>
        public override bool Equals(Object Obj)
        {

            if (!(Obj is GF2mVector))
                return false;
            
            GF2mVector otherVec = (GF2mVector)Obj;

            if (!_field.Equals(otherVec.Field))
                return false;

            return Compare.AreEqual(IntArrayForm, otherVec.IntArrayForm);
        }

        /// <summary>
        /// Return a byte array encoding of this vector
        /// </summary>
        /// 
        /// <returns>The encoded vector</returns>
        public override byte[] GetEncoded()
        {
            int d = 8;
            int count = 1;
            while (_field.Degree > d)
            {
                count++;
                d += 8;
            }

            byte[] res = new byte[_vector.Length * count];
            count = 0;
            for (int i = 0; i < _vector.Length; i++)
            {
                for (int j = 0; j < d; j += 8)
                    res[count++] = (byte)(IntUtils.URShift(_vector[i], j));
            }

            return res;
        }

        /// <summary>
        /// Computes the hash code of this vector
        /// </summary>
        /// 
        /// <returns>The hsh code</returns>
        public override int GetHashCode()
        {
            int hash = this._field.GetHashCode();
            hash = hash * 31 + _vector.GetHashCode();

            return hash;
        }

        /// <summary>
        /// Returns whether this is the zero vector (i.e., all elements are zero)
        /// </summary>
        /// 
        /// <returns>Returns <c>true</c> if this is a zero vector</returns>
        public override bool IsZero()
        {
            for (int i = _vector.Length - 1; i >= 0; i--)
            {
                if (_vector[i] != 0)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Multiply this vector with a permutation
        /// </summary>
        /// 
        /// <param name="P">he permutation</param>
        /// 
        /// <returns>Returns <c>this*p = p*this</c></returns>
        public override Vector Multiply(Permutation P)
        {
            int[] pVec = P.GetVector();
            if (Length != pVec.Length)
                throw new ArithmeticException("permutation size and vector size mismatch");

            int[] result = new int[Length];
            for (int i = 0; i < pVec.Length; i++)
                result[i] = _vector[pVec[i]];

            return new GF2mVector(_field, result);
        }

        /// <summary>
        /// Return a human readable form of this vector
        /// </summary>
        /// 
        /// <returns>The vector as a string</returns>
        public override String ToString()
        {
            StringBuilder buf = new StringBuilder();
            for (int i = 0; i < _vector.Length; i++)
            {
                for (int j = 0; j < _field.Degree; j++)
                {
                    int r = j & 0x1f;
                    int bitMask = 1 << r;
                    int coeff = _vector[i] & bitMask;

                    if (coeff != 0)
                        buf.Append('1');
                    else
                        buf.Append('0');
                }
                buf.Append(' ');
            }

            return buf.ToString();
        }
        #endregion
    }
}
