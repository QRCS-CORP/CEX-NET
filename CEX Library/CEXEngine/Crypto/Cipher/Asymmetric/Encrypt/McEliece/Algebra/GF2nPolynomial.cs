#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class implements polynomials over GF2nElements
    /// </summary>
    internal sealed class GF2nPolynomial
    {
        #region Fields
        // keeps the coefficients of this polynomial
        private GF2nElement[] _coeff; 
        // the size of this polynomial
        private int _size;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the degree of this PolynomialGF2n
        /// </summary>
        public int Degree
        {
            get
            {
                for (int i = _size - 1; i >= 0; i--)
                {
                    if (!_coeff[i].IsZero())
                        return i;
                }

                return -1;
            }
        }

        /// <summary>
        /// Get: Returns the size (=maximum degree + 1) of this PolynomialGF2n; this is not the degree, use Degree instead.
        /// </summary>
        public int Size
        {
            get { return _size; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Creates a new PolynomialGF2n of size <c>Degree</c> and elem as coefficients
        /// </summary>
        /// 
        /// <param name="Degree">The maximum degree + 1</param>
        /// <param name="Element">A GF2nElement</param>
        public GF2nPolynomial(int Degree, GF2nElement Element)
        {
            _size = Degree;
            _coeff = new GF2nElement[_size];

            for (int i = 0; i < _size; i++)
                _coeff[i] = (GF2nElement)Element.Clone();
        }

        /// <summary>
        /// Creates a new PolynomialGF2n of size <c>Degree</c>
        /// </summary>
        /// 
        /// <param name="Degree">The maximum degree + 1</param>
        private GF2nPolynomial(int Degree)
        {
            _size = Degree;
            _coeff = new GF2nElement[_size];
        }

        /// <summary>
        /// Creates a new PolynomialGF2n by cloning the given PolynomialGF2n <c>G</c>
        /// </summary>
        /// 
        /// <param name="G">The PolynomialGF2n to clone</param>
        public GF2nPolynomial(GF2nPolynomial G)
        {
            int i;
            _coeff = new GF2nElement[G._size];
            _size = G._size;

            for (i = 0; i < _size; i++)
                _coeff[i] = (GF2nElement)G._coeff[i].Clone();
        }

        /// <summary>
        /// Creates a new PolynomialGF2n from the given Bitstring <c>G</c> over the GF2nField <c>B1</c>
        /// </summary>
        /// 
        /// <param name="G">The Bitstring to use</param>
        /// <param name="B1">The field</param>
        public GF2nPolynomial(GF2Polynomial G, GF2nField B1)
        {
            _size = B1.Degree + 1;
            _coeff = new GF2nElement[_size];
            int i;

            if (B1 is GF2nONBField)
            {
                for (i = 0; i < _size; i++)
                {
                    if (G.TestBit(i))
                        _coeff[i] = GF2nONBElement.One((GF2nONBField)B1);
                    else
                        _coeff[i] = GF2nONBElement.Zero((GF2nONBField)B1);
                }
            }
            else if (B1 is GF2nPolynomialField)
            {
                for (i = 0; i < _size; i++)
                {
                    if (G.TestBit(i))
                        _coeff[i] = GF2nPolynomialElement.One((GF2nPolynomialField)B1);
                    else
                        _coeff[i] = GF2nPolynomialElement.Zero((GF2nPolynomialField)B1);
                }
            }
            else
            {
                throw new ArgumentException("GF2nPolynomial: PolynomialGF2n(Bitstring, GF2nField): B1 must be an instance of GF2nONBField or GF2nPolynomialField!");
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Adds the PolynomialGF2n <c>G</c> to <c>this</c> and returns the result in a new <c>PolynomialGF2n</c>
        /// </summary>
        /// 
        /// <param name="P">The <c>PolynomialGF2n</c> to add</param>
        /// 
        /// <returns>Returns <c>this + b</c></returns>
        public GF2nPolynomial Add(GF2nPolynomial P)
        {
            GF2nPolynomial result;
            if (Size >= P.Size)
            {
                result = new GF2nPolynomial(Size);
                int i;

                for (i = 0; i < P.Size; i++)
                    result._coeff[i] = (GF2nElement)_coeff[i].Add(P._coeff[i]);
                for (; i < Size; i++)
                    result._coeff[i] = _coeff[i];
            }
            else
            {
                result = new GF2nPolynomial(P.Size);
                int i;

                for (i = 0; i < Size; i++)
                    result._coeff[i] = (GF2nElement)_coeff[i].Add(P._coeff[i]);
                for (; i < P.Size; i++)
                    result._coeff[i] = P._coeff[i];
            }

            return result;
        }

        /// <summary>
        /// Assign the value 0 to these elements
        /// </summary>
        public void AssignZeroToElements()
        {
            for (int i = 0; i < _size; i++)
                _coeff[i].AssignZero();
        }

        /// <summary>
        /// Returns the coefficient at <c>Index</c>
        /// </summary>
        /// 
        /// <param name="Index">The index</param>
        /// 
        /// <returns>Returns the GF2nElement stored as coefficient <c>Index</c></returns>
        public GF2nElement At(int Index)
        {
            return _coeff[Index];
        }

        /// <summary>
        /// Divides <c>this</c> by <c>b</c> and stores the result in a new PolynomialGF2n[2], quotient in result[0] and remainder in result[1]
        /// </summary>
        /// 
        /// <param name="B">The divisor</param>
        /// 
        /// <returns>Retuens the quotient and remainder of <c>this</c> / <c>b</c></returns>
        public GF2nPolynomial[] Divide(GF2nPolynomial B)
        {
            GF2nPolynomial[] result = new GF2nPolynomial[2];
            GF2nPolynomial a = new GF2nPolynomial(this);
            a.Shrink();
            GF2nPolynomial shift;
            GF2nElement factor;
            int bDegree = B.Degree;
            GF2nElement inv = (GF2nElement)B._coeff[bDegree].Invert();

            if (a.Degree < bDegree)
            {
                result[0] = new GF2nPolynomial(this);
                result[0].AssignZeroToElements();
                result[0].Shrink();
                result[1] = new GF2nPolynomial(this);
                result[1].Shrink();
                return result;
            }

            result[0] = new GF2nPolynomial(this);
            result[0].AssignZeroToElements();
            int i = a.Degree - bDegree;

            while (i >= 0)
            {
                factor = (GF2nElement)a._coeff[a.Degree].Multiply(inv);
                shift = B.ScalarMultiply(factor);
                shift.ShiftThisLeft(i);
                a = a.Add(shift);
                a.Shrink();
                result[0]._coeff[i] = (GF2nElement)factor.Clone();
                i = a.Degree - bDegree;
            }

            result[1] = a;
            result[0].Shrink();
            return result;
        }

        /// <summary>
        /// Enlarges the size of this PolynomialGF2n to <c>k</c> + 1
        /// </summary>
        /// 
        /// <param name="K">The new maximum degree</param>
        public void Enlarge(int K)
        {
            if (K <= _size)
                return;
            
            int i;
            GF2nElement[] res = new GF2nElement[K];
            Array.Copy(_coeff, 0, res, 0, _size);
            GF2nField f = _coeff[0].GetField();

            if (_coeff[0] is GF2nPolynomialElement)
            {
                for (i = _size; i < K; i++)
                    res[i] = GF2nPolynomialElement.Zero((GF2nPolynomialField)f);
            }
            else if (_coeff[0] is GF2nONBElement)
            {
                for (i = _size; i < K; i++)
                    res[i] = GF2nONBElement.Zero((GF2nONBField)f);
            }

            _size = K;
            _coeff = res;
        }

        /// <summary>
        /// Computes the greatest common divisor of <c>this</c> and <c>g</c> and returns the result in a new PolynomialGF2n
        /// </summary>
        /// 
        /// <param name="G">The GF2nPolynomial</param>
        /// 
        /// <returns>Returns gcd(<c>this</c>, <c>g</c>)</returns>
        public GF2nPolynomial Gcd(GF2nPolynomial G)
        {
            GF2nPolynomial a = new GF2nPolynomial(this);
            GF2nPolynomial b = new GF2nPolynomial(G);
            a.Shrink();
            b.Shrink();
            GF2nPolynomial c;
            GF2nPolynomial result;
            GF2nElement alpha;

            while (!b.IsZero())
            {
                c = a.Remainder(b);
                a = b;
                b = c;
            }

            alpha = a._coeff[a.Degree];
            result = a.ScalarMultiply((GF2nElement)alpha.Invert());

            return result;
        }

        /// <summary>
        /// Returns true if all coefficients equal zero
        /// </summary>
        /// 
        /// <returns>Returns true if all coefficients equal zero</returns>
        public bool IsZero()
        {
            int i;
            for (i = 0; i < _size; i++)
            {
                if (_coeff[i] != null)
                {
                    if (!_coeff[i].IsZero())
                        return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Multiplies <c>this</c> by <c>P</c> and returns the result in a new PolynomialGF2n
        /// </summary>
        /// 
        /// <param name="P">The PolynomialGF2n to multiply</param>
        /// 
        /// <returns>Returns <c>this</c> * <c>P</c></returns>
        public GF2nPolynomial Multiply(GF2nPolynomial P)
        {
            int i, j;
            int aDegree = Size;
            int bDegree = P.Size;
            if (aDegree != bDegree)
                throw new ArgumentException("PolynomialGF2n.Multiply: this and b must have the same size!");

            GF2nPolynomial result = new GF2nPolynomial((aDegree << 1) - 1);
            for (i = 0; i < Size; i++)
            {
                for (j = 0; j < P.Size; j++)
                {
                    if (result._coeff[i + j] == null)
                        result._coeff[i + j] = (GF2nElement)_coeff[i].Multiply(P._coeff[j]);
                    else
                        result._coeff[i + j] = (GF2nElement)result._coeff[i + j].Add(_coeff[i].Multiply(P._coeff[j]));
                }
            }

            return result;
        }

        /// <summary>
        /// Multiplies <c>this</c> by <c>B</c>, reduces the result by <c>G</c> and returns it in a new PolynomialGF2n
        /// </summary>
        /// 
        /// <param name="B">The PolynomialGF2n to multiply</param>
        /// <param name="G">The modulus</param>
        /// 
        /// <returns>Returns <c>this</c> * <c>B</c> mod <c>G</c></returns>
        public GF2nPolynomial MultiplyAndReduce(GF2nPolynomial B, GF2nPolynomial G)
        {
            return Multiply(B).Reduce(G);
        }

        /// <summary>
        /// Divides <c>this</c> by <c>B</c> and stores the quotient in a new PolynomialGF2n
        /// </summary>
        /// 
        /// <param name="B">The divisor</param>
        /// 
        /// <returns>Returns the quotient <c>this</c> / <c>B</c></returns>
        public GF2nPolynomial Quotient(GF2nPolynomial B)
        {
            GF2nPolynomial[] result = new GF2nPolynomial[2];
            result = Divide(B);

            return result[0];
        }

        /// <summary>
        /// Reduces <c>this</c> by <c>G</c> and returns the result in a newPolynomialGF2n
        /// </summary>
        /// 
        /// <param name="G">The modulus</param>
        /// 
        /// <returns>Returns <c>this</c> % <c>G</c></returns>
        public GF2nPolynomial Reduce(GF2nPolynomial G)
        {
            return Remainder(G); 
        }

        /// <summary>
        /// Divides <c>this</c> by <c>b</c> and stores the remainder in a new PolynomialGF2n
        /// </summary>
        /// 
        /// <param name="B">The divisor</param>
        /// 
        /// <returns>Returns The remainder <c>this</c> % <c>b</c></returns>
        public GF2nPolynomial Remainder(GF2nPolynomial B)
        {
            GF2nPolynomial[] result = new GF2nPolynomial[2];
            result = Divide(B);

            return result[1];
        }

        /// <summary>
        /// Multiplies the scalar <c>E</c> to each coefficient of this PolynomialGF2n and returns the result in a new PolynomialGF2n
        /// </summary>
        /// 
        /// <param name="E">The scalar to multiply</param>
        /// 
        /// <returns>Returns <c>this</c> x <c>E</c></returns>
        public GF2nPolynomial ScalarMultiply(GF2nElement E)
        {
            GF2nPolynomial result = new GF2nPolynomial(Size);

            for (int i = 0; i < Size; i++)
                result._coeff[i] = (GF2nElement)_coeff[i].Multiply(E);

            return result;
        }

        /// <summary>
        /// Sets the coefficient at <c>Index</c> to <c>Element</c>
        /// </summary>
        /// 
        /// <param name="Index">The index</param>
        /// <param name="E">The GF2nElement to store as coefficient <c>Index</c></param>
        public void Set(int Index, GF2nElement E)
        {
            if (!(E is GF2nPolynomialElement) && !(E is GF2nONBElement))
                throw new ArgumentException("GF2nPolynomial: PolynomialGF2n.Set f must be an instance of either GF2nPolynomialElement or GF2nONBElement!");
            
            _coeff[Index] = (GF2nElement)E.Clone();
        }

        /// <summary>
        /// Shifts left <c>this</c> by <c>N</c> and stores the result in <c>this</c> PolynomialGF2n
        /// </summary>
        /// 
        /// <param name="N">The amount the amount to shift the coefficients</param>
        /// 
        /// <returns>The shifted polynomial</returns>
        public GF2nPolynomial ShiftLeft(int N)
        {
            if (N <= 0)
                return new GF2nPolynomial(this);
            
            GF2nPolynomial result = new GF2nPolynomial(_size + N, _coeff[0]);
            result.AssignZeroToElements();

            for (int i = 0; i < _size; i++)
                result._coeff[i + N] = _coeff[i];
            
            return result;
        }

        /// <summary>
        /// Shifts left <c>this</c> by <c>N</c> and stores the result in <c>this</c> PolynomialGF2n
        /// </summary>
        /// 
        /// <param name="N">The amount the amount to shift the coefficients</param>
        public void ShiftThisLeft(int N)
        {
            if (N > 0)
            {
                int i;
                int oldSize = _size;
                GF2nField f = _coeff[0].GetField();
                Enlarge(_size + N);

                for (i = oldSize - 1; i >= 0; i--)
                    _coeff[i + N] = _coeff[i];
                
                if (_coeff[0] is GF2nPolynomialElement)
                {
                    for (i = N - 1; i >= 0; i--)
                        _coeff[i] = GF2nPolynomialElement.Zero((GF2nPolynomialField)f);
                }
                else if (_coeff[0] is GF2nONBElement)
                {
                    for (i = N - 1; i >= 0; i--)
                        _coeff[i] = GF2nONBElement.Zero((GF2nONBField)f);
                }
            }
        }

        /// <summary>
        /// Shrink the size of this PolynomialGF2n
        /// </summary>
        public void Shrink()
        {
            int i = _size - 1;
            while (_coeff[i].IsZero() && (i > 0))
            {
                i--;
            }
            i++;

            if (i < _size)
            {
                GF2nElement[] res = new GF2nElement[i];
                Array.Copy(_coeff, 0, res, 0, i);
                _coeff = res;
                _size = i;
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Compare this element with another object
        /// </summary>
        /// 
        /// <param name="Obj">The object for comprison</param>
        /// 
        /// <returns>Returns <c>true</c> if the two objects are equal, <c>false</c> otherwise</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is GF2nPolynomial))
                return false;

            GF2nPolynomial otherPol = (GF2nPolynomial)Obj;

            if (Degree != otherPol.Degree)
                return false;

            for (int i = 0; i < _size; i++)
            {
                if (!_coeff[i].Equals(otherPol._coeff[i]))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns the hash code of this element
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return Degree + _coeff.GetHashCode();
        }
        #endregion
    }
}
