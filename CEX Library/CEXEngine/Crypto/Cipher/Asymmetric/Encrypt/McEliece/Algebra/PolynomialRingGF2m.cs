#region Directives
using System;
using VTDev.Libraries.CEXEngine.Utility;
using System.Threading.Tasks;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class represents polynomial rings <c>GF(2^m)[X]/p(X)</c> for <c>m&lt;32</c>.
    /// <para>If <c>p(X)</c> is irreducible, the polynomial ring is in fact an extension field of <c>GF(2^m)</c>.</para>
    /// </summary>
    internal class PolynomialRingGF2m
    {
        #region Fields
        // the finite field this polynomial ring is defined over
        private GF2mField _field;

        // the reduction polynomial
        private PolynomialGF2mSmallM _poly;

        // the squaring matrix for this polynomial ring (given as the array of its row vectors)
        protected PolynomialGF2mSmallM[] _sqMatrix;

        // the matrix for computing square roots in this polynomial ring (given as the array of its row vectors). 
        // This matrix is computed as the inverse of the squaring matrix.
        protected PolynomialGF2mSmallM[] _sqRootMatrix;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Return the squaring matrix for this polynomial ring
        /// </summary>
        /// <returns></returns>
        public PolynomialGF2mSmallM[] SquaringMatrix
        {
            get { return _sqMatrix; }
        }

        /// <summary>
        /// Get: Return the matrix for computing square roots for this polynomial ring
        /// </summary>
        public PolynomialGF2mSmallM[] SquareRootMatrix
        {
            get { return _sqRootMatrix; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Field">The finite field</param>
        /// <param name="Poly">The reduction polynomial</param>
        public PolynomialRingGF2m(GF2mField Field, PolynomialGF2mSmallM Poly)
        {
            _field = Field;
            _poly = Poly;
            ComputeSquaringMatrix();
            ComputeSquareRootMatrix();
        }
        #endregion

        #region Methods
        /// <summary>
        /// Compute the squaring matrix for this polynomial ring, using the base field and the reduction polynomial
        /// </summary>
        private void ComputeSquaringMatrix()
        {
            int numColumns = _poly.Degree;
            _sqMatrix = new PolynomialGF2mSmallM[numColumns];
            PolynomialGF2mSmallM[] _sqMatrix2 = new PolynomialGF2mSmallM[numColumns];

            if (ParallelUtils.IsParallel)
            {
                int nct = numColumns >> 1;
                Parallel.For(0, nct, i =>
                {
                    int[] monomCoeffs = new int[(i << 1) + 1];
                    monomCoeffs[i << 1] = 1;
                    _sqMatrix[i] = new PolynomialGF2mSmallM(_field, monomCoeffs);
                });

                Parallel.For(nct, numColumns, i =>
                {
                    int[] monomCoeffs = new int[(i << 1) + 1];
                    monomCoeffs[i << 1] = 1;
                    PolynomialGF2mSmallM monomial = new PolynomialGF2mSmallM(_field, monomCoeffs);
                    _sqMatrix[i] = monomial.Mod(_poly);
                });
            }
            else
            {
                for (int i = 0; i < numColumns >> 1; i++)
                {
                    int[] monomCoeffs = new int[(i << 1) + 1];
                    monomCoeffs[i << 1] = 1;
                    _sqMatrix[i] = new PolynomialGF2mSmallM(_field, monomCoeffs);
                }

                for (int i = numColumns >> 1; i < numColumns; i++)
                {
                    int[] monomCoeffs = new int[(i << 1) + 1];
                    monomCoeffs[i << 1] = 1;
                    PolynomialGF2mSmallM monomial = new PolynomialGF2mSmallM(_field, monomCoeffs);
                    _sqMatrix[i] = monomial.Mod(_poly);
                }
            }
        }

        /// <summary>
        /// Compute the matrix for computing square roots in this polynomial ring by inverting the squaring matrix
        /// </summary>
        private void ComputeSquareRootMatrix()
        {
            int numColumns = _poly.Degree;

            // clone squaring matrix
            PolynomialGF2mSmallM[] tmpMatrix = new PolynomialGF2mSmallM[numColumns];
            for (int i = numColumns - 1; i >= 0; i--)
                tmpMatrix[i] = new PolynomialGF2mSmallM(_sqMatrix[i]);

            // initialize square root matrix as unit matrix
            _sqRootMatrix = new PolynomialGF2mSmallM[numColumns];
            for (int i = numColumns - 1; i >= 0; i--)
                _sqRootMatrix[i] = new PolynomialGF2mSmallM(_field, i);

            // simultaneously compute Gaussian reduction of squaring matrix and unit matrix
            for (int i = 0; i < numColumns; i++)
            {
                // if diagonal element is zero
                if (tmpMatrix[i].GetCoefficient(i) == 0)
                {
                    bool foundNonZero = false;
                    // find a non-zero element in the same row
                    for (int j = i + 1; j < numColumns; j++)
                    {
                        if (tmpMatrix[j].GetCoefficient(i) != 0)
                        {
                            // found it, swap columns ...
                            foundNonZero = true;
                            SwapColumns(tmpMatrix, i, j);
                            SwapColumns(_sqRootMatrix, i, j);
                            // ... and quit searching
                            j = numColumns;
                            continue;
                        }
                    }
                    // if no non-zero element was found the matrix is not invertible
                    if (!foundNonZero)
                        throw new ArithmeticException("Squaring matrix is not invertible.");
                }

                // normalize i-th column
                int coef = tmpMatrix[i].GetCoefficient(i);
                int invCoef = _field.Inverse(coef);
                tmpMatrix[i].MultThisWithElement(invCoef);
                _sqRootMatrix[i].MultThisWithElement(invCoef);

                if (ParallelUtils.IsParallel)
                {
                    // normalize all other columns
                    Parallel.For(0, numColumns, j =>
                    {
                        if (j != i)
                        {
                            int coefp = tmpMatrix[j].GetCoefficient(i);
                            if (coefp != 0)
                            {
                                PolynomialGF2mSmallM tmpSqColumn = tmpMatrix[i].MultWithElement(coefp);
                                PolynomialGF2mSmallM tmpInvColumn = _sqRootMatrix[i].MultWithElement(coefp);
                                tmpMatrix[j].AddToThis(tmpSqColumn);
                                lock (_sqRootMatrix)
                                    _sqRootMatrix[j].AddToThis(tmpInvColumn);
                            }
                        }
                    });
                }
                else
                {
                    for (int j = 0; j < numColumns; j++)
                    {
                        if (j != i)
                        {
                            coef = tmpMatrix[j].GetCoefficient(i);
                            if (coef != 0)
                            {
                                PolynomialGF2mSmallM tmpSqColumn = tmpMatrix[i].MultWithElement(coef);
                                PolynomialGF2mSmallM tmpInvColumn = _sqRootMatrix[i].MultWithElement(coef);
                                tmpMatrix[j].AddToThis(tmpSqColumn);
                                lock (_sqRootMatrix)
                                    _sqRootMatrix[j].AddToThis(tmpInvColumn);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Swap two columns
        /// </summary>
        private static void SwapColumns(PolynomialGF2mSmallM[] Matrix, int First, int Second)
        {
            PolynomialGF2mSmallM tmp = Matrix[First];
            Matrix[First] = Matrix[Second];
            Matrix[Second] = tmp;
        }
        #endregion
    }
}
