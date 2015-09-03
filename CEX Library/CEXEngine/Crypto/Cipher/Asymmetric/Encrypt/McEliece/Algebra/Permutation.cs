#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This class implements permutations of the set {0,1,...,n-1} for some given n &gt; 0.
    /// <para>i.e., ordered sequences containing each number <c>m</c> (<c>0 &lt;= m &lt; n</c>) once and only once.</para>
    /// </summary>
    internal sealed class Permutation
    {
        #region Fields
        private int[] _perm;
        #endregion

        #region Constructor
        /// <summary>
        /// Create the identity permutation of the given size
        /// </summary>
        /// 
        /// <param name="N">The size of the permutation</param>
        public Permutation(int N)
        {
            if (N <= 0)
                throw new ArgumentException("N is an invalid length!");

            _perm = new int[N];
            for (int i = N - 1; i >= 0; i--)
                _perm[i] = i;
        }

        /// <summary>
        /// Create a permutation using the given permutation vector
        /// </summary>
        /// 
        /// <param name="Perm">The permutation vector</param>
        public Permutation(int[] Perm)
        {
            if (!IsPermutation(Perm))
                throw new ArgumentException("Permutation: Array is not a permutation vector!");

            this._perm = IntUtils.DeepCopy(Perm);
        }
        
        /// <summary>
        /// Create a permutation using an encoded permutation
        /// </summary>
        /// 
        /// <param name="Encoded">The encoded permutation</param>
        public Permutation(byte[] Encoded)
        {
            if (Encoded.Length <= 4)
                throw new ArgumentException("Permutation: Invalid encoding!");

            int n = LittleEndian.OctetsToInt(Encoded, 0);
            int size = BigMath.CeilLog256(n - 1);

            if (Encoded.Length != 4 + n * size)
                throw new ArgumentException("Permutation: Invalid encoding!");

            _perm = new int[n];
            for (int i = 0; i < n; i++)
                _perm[i] = LittleEndian.OctetsToInt(Encoded, 4 + i * size, size);

            if (!IsPermutation(_perm))
                throw new ArgumentException("Permutation: Invalid encoding!");
        }

        /// <summary>
        /// Create a random permutation of the given size
        /// </summary>
        /// 
        /// <param name="N">The size of the permutation</param>
        /// <param name="SecRnd">The source of randomness</param>
        public Permutation(int N, IRandom SecRnd)
        {
            if (N <= 0)
                throw new ArgumentException("Permutation: Invalid length!");

            _perm = new int[N];
            int[] help = new int[N];

            for (int i = 0; i < N; i++)
                help[i] = i;

            int k = N;
            for (int j = 0; j < N; j++)
            {
                int i = RandomDegree.NextInt(SecRnd, k);
                k--;
                _perm[j] = help[i];
                help[i] = help[k];
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Reset the internal state
        /// </summary>
        public void Clear()
        {
            if (_perm != null)
                Array.Clear(_perm, 0, _perm.Length);
        }

        /// <summary>
        /// Compute the inverse permutation <c>P pow -1</c>
        /// </summary>
        /// 
        /// <returns>Returns <c>this pow -1</c></returns>
        public Permutation ComputeInverse()
        {
            Permutation result = new Permutation(_perm.Length);
            for (int i = _perm.Length - 1; i >= 0; i--)
                result._perm[_perm[i]] = i;

            return result;
        }

        /// <summary>
        /// Encode this permutation as byte array
        /// </summary>
        /// 
        /// <returns>The encoded permutation</returns>
        public byte[] GetEncoded()
        {
            int n = _perm.Length;
            int size = BigMath.CeilLog256(n - 1);
            byte[] result = new byte[4 + n * size];
            LittleEndian.IntToOctets(n, result, 0);

            for (int i = 0; i < n; i++)
                LittleEndian.IntToOctets(_perm[i], result, 4 + i * size, size);
            
            return result;
        }

        /// <summary>
        /// The permutation vector <c>(perm(0),perm(1),...,perm(n-1))</c>
        /// </summary>
        /// 
        /// <returns>The permutation vector</returns>
        public int[] GetVector()
        {
            return IntUtils.DeepCopy(_perm);
        }

        /// <summary>
        /// Compute the product of this permutation and another permutation
        /// </summary>
        /// 
        /// <param name="p">The other permutation</param>
        /// 
        /// <returns>Returns <c>this * P</c></returns>
        public Permutation RightMultiply(Permutation p)
        {
            if (p._perm.Length != _perm.Length)
                throw new ArgumentException("length mismatch");
            
            Permutation result = new Permutation(_perm.Length);
            for (int i = _perm.Length - 1; i >= 0; i--)
                result._perm[i] = _perm[p._perm[i]];
            
            return result;
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Checks if given object is equal to this permutation
        /// </summary>
        /// 
        /// <param name="Obj">The object to compare this with</param>
        /// 
        /// <returns>Returns false whenever the given object is not equl to this</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null)
                return false;
            if (!(Obj is Permutation))
                return false;

            Permutation otherPerm = (Permutation)Obj;

            return Compare.AreEqual(_perm, otherPerm._perm);
        }

        /// <summary>
        /// Returns the hash code of this permutation
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _perm.GetHashCode();
        }

        /// <summary>
        /// Creates a human readable form of the permutation
        /// </summary>
        /// 
        /// <returns>Returns the permutation in readable form</returns>
        public override String ToString()
        {
            String result = "[" + _perm[0];
            for (int i = 1; i < _perm.Length; i++)
                result += ", " + _perm[i];

            result += "]";

            return result;
        }
        #endregion

        #region Private Methods
        private bool IsPermutation(int[] Perm)
        {
            int n = Perm.Length;
            bool[] onlyOnce = new bool[n];

            for (int i = 0; i < n; i++)
            {
                if ((Perm[i] < 0) || (Perm[i] >= n) || onlyOnce[Perm[i]])
                    return false;
                
                onlyOnce[Perm[i]] = true;
            }

            return true;
        }
        #endregion
    }
}
