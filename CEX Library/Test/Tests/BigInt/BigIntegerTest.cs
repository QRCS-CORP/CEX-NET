using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Crypto.Prng;

namespace VTDev.Projects.CEX.Test.Tests.BigInt
{
    /// <summary>
    /// Tests from the Deevel Math distribution: https://github.com/deveel/deveel-math/blob/master/src/Deveel.Math/Deveel.Math/BigInteger.cs
    /// </summary>
    public class BigIntegerTest : ITest
    {
        #region Fields
        private BigInteger minusTwo = BigInteger.Parse("-2", 10);
        private BigInteger minusOne = BigInteger.Parse("-1", 10);
        private BigInteger zero = BigInteger.Parse("0", 10);
        private BigInteger one = BigInteger.Parse("1", 10);
        private BigInteger two = BigInteger.Parse("2", 10);
        private BigInteger ten = BigInteger.Parse("10", 10);
        private BigInteger sixteen = BigInteger.Parse("16", 10);
        private BigInteger oneThousand = BigInteger.Parse("1000", 10);
        private BigInteger aZillion = BigInteger.Parse("100000000000000000000000000000000000000000000000000", 10);
        private BigInteger twoToTheTen = BigInteger.Parse("1024", 10);
        private BigInteger twoToTheSeventy;
        private SecureRandom rand = new SecureRandom();
        private BigInteger bi;
        private BigInteger bi1;
        private BigInteger bi2;
        private BigInteger bi3;
        private BigInteger bi11;
        private BigInteger bi22;
        private BigInteger bi33;
        private BigInteger bi12;
        private BigInteger bi23;
        private BigInteger bi13;
        private BigInteger largePos;
        private BigInteger smallPos;
        private BigInteger largeNeg;
        private BigInteger smallNeg;
        private BigInteger[][] booleanPairs;
        #endregion

        #region Constants
        private const string DESCRIPTION = "A full range of BigInteger function tests.";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! BigInteger tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// A full range of BigInteger function tests.
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Run()
        {
            try
            {
                twoToTheSeventy = two.Pow(70);
                SetUp();

                ConstructorIRandom();
                CostructorIIRandom();
                OnProgress(new TestEventArgs("Passed Random Constructor tests.."));
                ConstructorBytes();
                ConstructorIBytes();
                OnProgress(new TestEventArgs("Passed Byte Constructor tests.."));
                ParseStringEmpty();
                OnProgress(new TestEventArgs("Passed Parse empty string tests.."));
                ToByteArray();
                OnProgress(new TestEventArgs("Passed ToByteArray tests.."));
                ToInt32();
                OnProgress(new TestEventArgs("Passed ToInt32 tests.."));
                ToInt64();
                OnProgress(new TestEventArgs("Passed ToInt64 tests.."));
                ParseString();
                ParseStringI();
                OnProgress(new TestEventArgs("Passed Parse string tests.."));
                TestToString();
                ToStringI();
                OnProgress(new TestEventArgs("Passed ToString tests.."));
                EqualsObject();
                OnProgress(new TestEventArgs("Passed Equality tests.."));
                CompareToBigInteger();
                OnProgress(new TestEventArgs("Passed Comparison tests.."));
                Signum();
                OnProgress(new TestEventArgs("Passed Signum tests.."));
                IsProbablePrimeI();
                OnProgress(new TestEventArgs("Passed IsProbablePrime tests.."));
                ValueOfJ();
                OnProgress(new TestEventArgs("Passed ValueOfJ tests.."));
                Abs();
                OnProgress(new TestEventArgs("Passed Abs tests.."));
                AddBigInteger();
                OnProgress(new TestEventArgs("Passed Add BigInteger tests.."));
                Negate();
                OnProgress(new TestEventArgs("Passed Negate tests.."));
                MmodInverseBigInteger();
                OnProgress(new TestEventArgs("Passed MmodInverse BigInteger tests.."));
                ShiftRightI();
                ShiftLeftI();
                OnProgress(new TestEventArgs("Passed right and left shift tests.."));
                MultiplyBigInteger();
                OnProgress(new TestEventArgs("Passed Multiply BigInteger tests.."));
                PowI();
                OnProgress(new TestEventArgs("Passed Pow tests.."));
                DivideBigInteger();
                OnProgress(new TestEventArgs("Passed Divide BigInteger tests.."));
                DivideAndRemainderBigInteger();
                OnProgress(new TestEventArgs("Passed DivideAndRemainder BigInteger tests.."));
                RemainderBigInteger();
                OnProgress(new TestEventArgs("Passed Remainder BigInteger tests.."));
                ModLBigInteger();
                OnProgress(new TestEventArgs("Passed Mod LBigIntegertests.."));
                AndLBigInteger();
                OnProgress(new TestEventArgs("Passed And LBigInteger tests.."));
                OrBigInteger();
                OnProgress(new TestEventArgs("Passed Or BigInteger tests.."));
                XOrBigInteger();
                OnProgress(new TestEventArgs("Passed XOr BigInteger tests.."));
                Not();
                AndNotBigInteger();
                OnProgress(new TestEventArgs("Passed AndNot BigInteger tests.."));
            
                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }

        public void SetUp()
        {
            bi1 = BigInteger.Parse("2436798324768978", 16);
            bi2 = BigInteger.Parse("4576829475724387584378543764555", 16);
            bi3 = BigInteger.Parse("43987298363278574365732645872643587624387563245", 16);
            bi33 = BigInteger.Parse("10730846694701319120609898625733976090865327544790136667944805934175543888691400559249041094474885347922769807001", 10);
            bi22 = BigInteger.Parse("33301606932171509517158059487795669025817912852219962782230629632224456249", 10);
            bi11 = BigInteger.Parse("6809003003832961306048761258711296064", 10);
            bi23 = BigInteger.Parse("597791300268191573513888045771594235932809890963138840086083595706565695943160293610527214057", 10);
            bi13 = BigInteger.Parse("270307912162948508387666703213038600031041043966215279482940731158968434008", 10);
            bi12 = BigInteger.Parse("15058244971895641717453176477697767050482947161656458456", 10);
            largePos = BigInteger.Parse("834759814379857314986743298675687569845986736578576375675678998612743867438632986243982098437620983476924376", 16);
            smallPos = BigInteger.Parse("48753269875973284765874598630960986276", 16);
            largeNeg = BigInteger.Parse("-878824397432651481891353247987891423768534321387864361143548364457698487264387568743568743265873246576467643756437657436587436", 16);
            smallNeg = BigInteger.Parse("-567863254343798609857456273458769843", 16);
            booleanPairs = new BigInteger[4][];
            booleanPairs[0] = new BigInteger[] { largePos, smallPos };
            booleanPairs[1] = new BigInteger[] { largePos, smallNeg };
            booleanPairs[2] = new BigInteger[] { largeNeg, smallPos };
            booleanPairs[3] = new BigInteger[] { largeNeg, smallNeg };
            /*
            booleanPairs = new BigInteger[][] { { largePos, smallPos },
                { largePos, smallNeg }, { largeNeg, smallPos },
                { largeNeg, smallNeg } };
            */
        }

        public void ConstructorIRandom()
        {
            // regression test for HARMONY-1047
            Throw(() => new BigInteger(Int32.MaxValue, (Random)null), "BigInteger: failed regression test");
            bi = new BigInteger(70, rand);
            bi2 = new BigInteger(70, rand);
            IsTrue(bi.CompareTo(zero) >= 0, "Random number is negative");
            IsTrue(bi.CompareTo(twoToTheSeventy) < 0, "Random number is too big");
            IsTrue(!bi.Equals(bi2), "Two random numbers in a row are the same (might not be a bug but it very likely is)");
            IsTrue(new BigInteger(0, rand).Equals(BigInteger.Zero), "Not zero");
        }

        public void CostructorIIRandom()
        {
            bi = new BigInteger(10, 5, rand);
            bi2 = new BigInteger(10, 5, rand);
            IsTrue(bi.CompareTo(zero) >= 0, "Random number one is negative");
            IsTrue(bi.CompareTo(twoToTheTen) < 0, "Random number one is too big");
            IsTrue(bi2.CompareTo(zero) >= 0, "Random number two is negative");
            IsTrue(bi2.CompareTo(twoToTheTen) < 0, "Random number two is too big");

            Random rand_b = new Random();
            BigInteger bi_b;
            int[] certainty = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, Int32.MinValue, Int32.MinValue + 1, -2, -1 };
            for (int i = 2; i <= 20; i++)
            {
                for (int c = 0; c < certainty.Length; c++)
                {
                    bi_b = new BigInteger(i, c, rand_b); // Create BigInteger
                    IsTrue(bi_b.BitLength == i, "Bit length incorrect");
                }
            }
        }

        public void ConstructorBytes()
        {
            var myByteArray = new byte[] { (byte)0x00, (byte)0xFF, (byte)0xFE };
            bi = new BigInteger(myByteArray);
            IsTrue(bi.Equals(BigInteger.Zero.SetBit(16).Subtract(two)), "Incorrect value for pos number");
            myByteArray = new byte[] { (byte)0xFF, (byte)0xFE };
            bi = new BigInteger(myByteArray);
            IsTrue(bi.Equals(minusTwo), "Incorrect value for neg number");
        }

        public void ConstructorIBytes()
        {
            var myByteArray = new byte[] { (byte)0xFF, (byte)0xFE };
            bi = new BigInteger(1, myByteArray);
            IsTrue(bi.Equals(BigInteger.Zero.SetBit(16).Subtract(two)), "Incorrect value for pos number");
            bi = new BigInteger(-1, myByteArray);
            IsTrue(bi.Equals(BigInteger.Zero.SetBit(16).Subtract(two).Negate()), "Incorrect value for neg number");
            myByteArray = new byte[] { (byte)0, (byte)0 };
            bi = new BigInteger(0, myByteArray);
            IsTrue(bi.Equals(zero), "Incorrect value for zero");
            myByteArray = new byte[] { (byte)1 };

            Throw(() => new BigInteger(0, myByteArray), "BigInteger: failed constructor test");
        }

        public void ParseStringEmpty()
        {
            Throw(() => BigInteger.Parse(""), "BigInteger: failed parse test");
        }

        public void ToByteArray()
        {
            var myByteArray = new byte[] { 97, 33, 120, 124, 50, 2, 0, 0, 0, 12, 124, 42 };
            var anotherByteArray = new BigInteger(myByteArray).ToByteArray();
            IsTrue(myByteArray.Length == anotherByteArray.Length, "Incorrect byte array returned");

            for (int counter = myByteArray.Length - 1; counter >= 0; counter--)
                IsTrue(myByteArray[counter] == anotherByteArray[counter], "Incorrect values in returned byte array");
        }

        public void IsProbablePrimeI()
        {
            int fails = 0;
            bi = new BigInteger(20, 20, rand);
            if (!bi.IsProbablePrime(17))
            {
                fails++;
            }
            bi = BigInteger.Parse("4", 10);
            if (bi.IsProbablePrime(17))
            {
                throw new Exception("IsProbablePrime failed for: " + bi.ToString());
            }
            bi = BigInteger.ValueOf(17L * 13L);
            if (bi.IsProbablePrime(17))
            {
                throw new Exception("IsProbablePrime failed for: " + bi.ToString());
            }
            for (long a = 2; a < 1000; a++)
            {
                if (isPrime(a))
                    IsTrue(BigInteger.ValueOf(a).IsProbablePrime(5), "false negative on prime number <1000");
                else if (BigInteger.ValueOf(a).IsProbablePrime(17))
                    fails++;
            }
            for (int a = 0; a < 1000; a++)
            {
                bi = BigInteger.ValueOf(rand.NextInt32(1000000)).Multiply(BigInteger.ValueOf(rand.NextInt32(1000000)));
                if (bi.IsProbablePrime(17))
                    fails++;
            }
            for (int a = 0; a < 200; a++)
            {
                bi = new BigInteger(70, rand).Multiply(new BigInteger(70, rand));
                if (bi.IsProbablePrime(17))
                    fails++;
            }

            IsTrue(fails <= 1, "Too many false positives - may indicate a problem");
        }

        public void EqualsObject()
        {
            IsTrue(zero.Equals(BigInteger.ValueOf(0)), "0=0");
            IsTrue(BigInteger.ValueOf(-123).Equals(BigInteger.ValueOf(-123)), "-123=-123");
            IsTrue(!zero.Equals(one), "0=1");
            IsTrue(!zero.Equals(minusOne), "0=-1");
            IsTrue(!one.Equals(minusOne), "1=-1");
            IsTrue(bi3.Equals(bi3), "bi3=bi3");
            IsTrue(bi3.Equals(bi3.Negate().Negate()), "bi3=copy of bi3");
            IsTrue(!bi3.Equals(bi2), "bi3=bi2");
        }

        public void CompareToBigInteger()
        {
            IsTrue(one.CompareTo(two) < 0, "Smaller number returned >= 0");
            IsTrue(two.CompareTo(one) > 0, "Larger number returned >= 0");
            IsTrue(one.CompareTo(one) == 0, "Equal numbers did not return 0");
            IsTrue(two.Negate().CompareTo(one) < 0, "Neg number messed things up");
        }

        public void ToInt32()
        {
            IsTrue(twoToTheSeventy.ToInt32() == 0, "Incorrect ToInt32 for 2**70");
            IsTrue(two.ToInt32() == 2, "Incorrect ToInt32 for 2");
        }

        public void ToInt64()
        {
            IsTrue(twoToTheSeventy.ToInt64() == 0, "Incorrect ToInt64 for 2**70");
            IsTrue(two.ToInt64() == 2, "Incorrect ToInt64 for 2");
        }

        public void ValueOfJ()
        {
            IsTrue(BigInteger.ValueOf(2L).Equals(two), "Incurred number returned for 2");
            IsTrue(BigInteger.ValueOf(200L).Equals(BigInteger.ValueOf(139).Add(BigInteger.ValueOf(61))), "Incurred number returned for 200");
        }

        public void AddBigInteger()
        {
            IsTrue(aZillion.Add(aZillion).Add(aZillion.Negate()).Equals(aZillion), "Incorrect sum--wanted a zillion");
            IsTrue(zero.Add(zero).Equals(zero), "0+0");
            IsTrue(zero.Add(one).Equals(one), "0+1");
            IsTrue(one.Add(zero).Equals(one), "1+0");
            IsTrue(one.Add(one).Equals(two), "1+1");
            IsTrue(zero.Add(minusOne).Equals(minusOne), "0+(-1)");
            IsTrue(minusOne.Add(zero).Equals(minusOne), "(-1)+0");
            IsTrue(minusOne.Add(minusOne).Equals(minusTwo), "(-1)+(-1)");
            IsTrue(one.Add(minusOne).Equals(zero), "1+(-1)");
            IsTrue(minusOne.Add(one).Equals(zero), "(-1)+1");

            for (int i = 0; i < 200; i++)
            {
                BigInteger midbit = zero.SetBit(i);
                IsTrue(midbit.Add(midbit).Equals(zero.SetBit(i + 1)), "add fails to carry on bit " + i);
            }

            BigInteger bi2p3 = bi2.Add(bi3);
            BigInteger bi3p2 = bi3.Add(bi2);
            IsTrue(bi2p3.Equals(bi3p2), "bi2p3=bi3p2");
        }

        public void Negate()
        {
            IsTrue(zero.Negate().Equals(zero), "Single negation of zero did not result in zero");
            IsTrue(!aZillion.Negate().Equals(aZillion), "Single negation resulted in original nonzero number");
            IsTrue(aZillion.Negate().Negate().Equals(aZillion), "Double negation did not result in original number");

            IsTrue(zero.Negate().Equals(zero), "0.neg");
            IsTrue(one.Negate().Equals(minusOne), "1.neg");
            IsTrue(two.Negate().Equals(minusTwo), "2.neg");
            IsTrue(minusOne.Negate().Equals(one), "-1.neg");
            IsTrue(minusTwo.Negate().Equals(two), "-2.neg");
            IsTrue(unchecked(BigInteger.ValueOf(0x62EB40FEF85AA9EBL * 2).Negate().Equals(BigInteger.ValueOf(-0x62EB40FEF85AA9EBL * 2))), "0x62EB40FEF85AA9EBL*2.neg");
            for (int i = 0; i < 200; i++)
            {
                BigInteger midbit = zero.SetBit(i);
                BigInteger negate = midbit.Negate();
                IsTrue(negate.Negate().Equals(midbit), "negate negate");
                IsTrue(midbit.Negate().Add(midbit).Equals(zero), "neg fails on bit " + i);
            }
        }

        public void Signum()
        {
            IsTrue(two.Signum() == 1, "Wrong positive signum");
            IsTrue(zero.Signum() == 0, "Wrong zero signum");
            IsTrue(zero.Negate().Signum() == 0, "Wrong neg zero signum");
            IsTrue(two.Negate().Signum() == -1, "Wrong neg signum");
        }

        public void Abs()
        {
            IsTrue(aZillion.Negate().Abs().Equals(aZillion.Abs()), "Invalid number returned for zillion");
            IsTrue(zero.Negate().Abs().Equals(zero), "Invalid number returned for zero neg");
            IsTrue(zero.Abs().Equals(zero), "Invalid number returned for zero");
            IsTrue(two.Negate().Abs().Equals(two), "Invalid number returned for two");
        }

        public void PowI()
        {
            IsTrue(two.Pow(10).Equals(twoToTheTen), "Incorrect exponent returned for 2**10");
            IsTrue(two.Pow(30).Multiply(two.Pow(40)).Equals(twoToTheSeventy), "Incorrect exponent returned for 2**70");
            IsTrue(ten.Pow(50).Equals(aZillion), "Incorrect exponent returned for 10**50");
        }

        public void MmodInverseBigInteger()
        {
            BigInteger a = zero, mod, inv;
            for (int j = 3; j < 50; j++)
            {
                mod = BigInteger.ValueOf(j);
                for (int i = -j + 1; i < j; i++)
                {
                    try
                    {
                        a = BigInteger.ValueOf(i);
                        inv = a.ModInverse(mod);
                        IsTrue(one.Equals(a.Multiply(inv).Mod(mod)), "bad inverse: " + a + " inv mod " + mod + " equals " + inv);
                        IsTrue(inv.CompareTo(mod) < 0, "inverse greater than modulo: " + a + " inv mod " + mod + " equals " + inv);
                        IsTrue(inv.CompareTo(BigInteger.Zero) >= 0, "inverse less than zero: " + a + " inv mod " + mod + " equals " + inv);
                    }
                    catch (ArithmeticException)
                    {
                        IsTrue(!one.Equals(a.Gcd(mod)), "should have found inverse for " + a + " mod " + mod);
                    }
                }
            }
            for (int j = 1; j < 10; j++)
            {
                mod = bi2.Add(BigInteger.ValueOf(j));
                for (int i = 0; i < 20; i++)
                {
                    try
                    {
                        a = bi3.Add(BigInteger.ValueOf(i));
                        inv = a.ModInverse(mod);
                        IsTrue(one.Equals(a.Multiply(inv).Mod(mod)), "bad inverse: " + a + " inv mod " + mod + " equals " + inv);
                        IsTrue(inv.CompareTo(mod) < 0, "inverse greater than modulo: " + a + " inv mod " + mod + " equals " + inv);
                        IsTrue(inv.CompareTo(BigInteger.Zero) >= 0, "inverse less than zero: " + a + " inv mod " + mod + " equals " + inv);
                    }
                    catch (ArithmeticException)
                    {
                        IsTrue(!one.Equals(a.Gcd(mod)), "should have found inverse for " + a + " mod " + mod);
                    }
                }
            }
        }

        public void ShiftRightI()
        {
            IsTrue(BigInteger.ValueOf(1).ShiftRight(0).Equals(BigInteger.One), "1 >> 0");
            IsTrue(BigInteger.ValueOf(1).ShiftRight(1).Equals(BigInteger.Zero), "1 >> 1");
            IsTrue(BigInteger.ValueOf(1).ShiftRight(63).Equals(BigInteger.Zero), "1 >> 63");
            IsTrue(BigInteger.ValueOf(1).ShiftRight(64).Equals(BigInteger.Zero), "1 >> 64");
            IsTrue(BigInteger.ValueOf(1).ShiftRight(65).Equals(BigInteger.Zero), "1 >> 65");
            IsTrue(BigInteger.ValueOf(1).ShiftRight(1000).Equals(BigInteger.Zero), "1 >> 1000");
            IsTrue(BigInteger.ValueOf(-1).ShiftRight(0).Equals(minusOne), "-1 >> 0");
            IsTrue(BigInteger.ValueOf(-1).ShiftRight(1).Equals(minusOne), "-1 >> 1");
            IsTrue(BigInteger.ValueOf(-1).ShiftRight(63).Equals(minusOne), "-1 >> 63");
            IsTrue(BigInteger.ValueOf(-1).ShiftRight(64).Equals(minusOne), "-1 >> 64");
            IsTrue(BigInteger.ValueOf(-1).ShiftRight(65).Equals(minusOne), "-1 >> 65");
            IsTrue(BigInteger.ValueOf(-1).ShiftRight(1000).Equals(minusOne), "-1 >> 1000");

            BigInteger a = BigInteger.One;
            BigInteger c = bi3;
            BigInteger E = bi3.Negate();
            BigInteger e = E;
            for (int i = 0; i < 200; i++)
            {
                BigInteger b = BigInteger.Zero.SetBit(i);
                IsTrue(a.Equals(b), "a==b");
                a = a.ShiftLeft(1);
                IsTrue(a.Signum() >= 0, "a non-neg");

                BigInteger d = bi3.ShiftRight(i);
                IsTrue(c.Equals(d), "c==d");
                c = c.ShiftRight(1);
                IsTrue(d.Divide(two).Equals(c), ">>1 == /2");
                IsTrue(c.Signum() >= 0, "c non-neg");

                BigInteger f = E.ShiftRight(i);
                IsTrue(e.Equals(f), "e==f");
                e = e.ShiftRight(1);
                IsTrue(f.Subtract(one).Divide(two).Equals(e), ">>1 == /2");
                IsTrue(e.Signum() == -1, "e negative");

                IsTrue(b.ShiftRight(i).Equals(one), "b >> i");
                IsTrue(b.ShiftRight(i + 1).Equals(zero), "b >> i+1");
                IsTrue(b.ShiftRight(i - 1).Equals(two), "b >> i-1");
            }
        }

        public void ShiftLeftI()
        {
            IsTrue(one.ShiftLeft(0).Equals(one), "1 << 0");
            IsTrue(one.ShiftLeft(1).Equals(two), "1 << 1");
            IsTrue(one.ShiftLeft(63).Equals(BigInteger.Parse("8000000000000000", 16)), "1 << 63");
            IsTrue(one.ShiftLeft(64).Equals(BigInteger.Parse("10000000000000000", 16)), "1 << 64");
            IsTrue(one.ShiftLeft(65).Equals(BigInteger.Parse("20000000000000000", 16)), "1 << 65");
            IsTrue(minusOne.ShiftLeft(0).Equals(minusOne), "-1 << 0");
            IsTrue(minusOne.ShiftLeft(1).Equals(minusTwo), "-1 << 1");
            IsTrue(minusOne.ShiftLeft(63).Equals(BigInteger.Parse("-9223372036854775808")), "-1 << 63");
            IsTrue(minusOne.ShiftLeft(64).Equals(BigInteger.Parse("-18446744073709551616")), "-1 << 64");
            IsTrue(minusOne.ShiftLeft(65).Equals(BigInteger.Parse("-36893488147419103232")), "-1 << 65");

            BigInteger a = bi3;
            BigInteger c = minusOne;
            for (int i = 0; i < 200; i++)
            {
                BigInteger b = bi3.ShiftLeft(i);
                IsTrue(a.Equals(b), "a==b");
                IsTrue(a.ShiftRight(i).Equals(bi3), "a >> i == bi3");
                a = a.ShiftLeft(1);
                IsTrue(b.Multiply(two).Equals(a), "<<1 == *2");
                IsTrue(a.Signum() >= 0, "a non-neg");
                IsTrue(a.BitCount == b.BitCount, "a.bitCount==b.bitCount");

                BigInteger d = minusOne.ShiftLeft(i);
                IsTrue(c.Equals(d), "c==d");
                c = c.ShiftLeft(1);
                IsTrue(d.Multiply(two).Equals(c), "<<1 == *2 negative");
                IsTrue(c.Signum() == -1, "c negative");
                IsTrue(d.ShiftRight(i).Equals(minusOne), "d >> i == minusOne");
            }
        }

        public void MultiplyBigInteger()
        {
            SetUp();
            IsTrue(aZillion.Add(aZillion).Add(aZillion).Equals(aZillion.Multiply(BigInteger.Parse("3", 10))), "Incorrect sum--wanted three zillion");

            IsTrue(zero.Multiply(zero).Equals(zero), "0*0");
            IsTrue(zero.Multiply(one).Equals(zero), "0*1");
            IsTrue(one.Multiply(zero).Equals(zero), "1*0");
            IsTrue(one.Multiply(one).Equals(one), "1*1");
            IsTrue(zero.Multiply(minusOne).Equals(zero), "0*(-1)");
            IsTrue(minusOne.Multiply(zero).Equals(zero), "(-1)*0");
            IsTrue(minusOne.Multiply(minusOne).Equals(one), "(-1)*(-1)");
            IsTrue(one.Multiply(minusOne).Equals(minusOne), "1*(-1)");
            IsTrue(minusOne.Multiply(one).Equals(minusOne), "(-1)*1");

            testAllMults(bi1, bi1, bi11);
            testAllMults(bi2, bi2, bi22);
            testAllMults(bi3, bi3, bi33);
            testAllMults(bi1, bi2, bi12);
            testAllMults(bi1, bi3, bi13);
            testAllMults(bi2, bi3, bi23);
        }

        public void DivideBigInteger()
        {
            TestAllDivs(bi33, bi3);
            TestAllDivs(bi22, bi2);
            TestAllDivs(bi11, bi1);
            TestAllDivs(bi13, bi1);
            TestAllDivs(bi13, bi3);
            TestAllDivs(bi12, bi1);
            TestAllDivs(bi12, bi2);
            TestAllDivs(bi23, bi2);
            TestAllDivs(bi23, bi3);
            TestAllDivs(largePos, bi1);
            TestAllDivs(largePos, bi2);
            TestAllDivs(largePos, bi3);
            TestAllDivs(largeNeg, bi1);
            TestAllDivs(largeNeg, bi2);
            TestAllDivs(largeNeg, bi3);
            TestAllDivs(largeNeg, largePos);
            TestAllDivs(largePos, largeNeg);
            TestAllDivs(bi3, bi3);
            TestAllDivs(bi2, bi2);
            TestAllDivs(bi1, bi1);
            TestDivRanges(bi1);
            TestDivRanges(bi2);
            TestDivRanges(bi3);
            TestDivRanges(smallPos);
            TestDivRanges(largePos);
            TestDivRanges(BigInteger.Parse("62EB40FEF85AA9EB", 16));
            TestAllDivs(BigInteger.ValueOf(0xCC0225953CL), BigInteger.ValueOf(0x1B937B765L));

            Throw(() => largePos.Divide(zero), "BigInteger: divide by zero test");
            Throw(() => bi1.Divide(zero), "BigInteger: divide by zero test");
            Throw(() => bi3.Negate().Divide(zero), "BigInteger: divide by zero test");
            Throw(() => zero.Divide(zero), "BigInteger: divide by zero test");
        }

        public void RemainderBigInteger()
        {
            Throw(() => largePos.Remainder(zero), "BigInteger: remainder divide by zero test");
            Throw(() => bi1.Remainder(zero), "BigInteger: divide by zero test");
            Throw(() => bi3.Negate().Remainder(zero), "BigInteger: divide by zero test");
            Throw(() => zero.Remainder(zero), "BigInteger: divide by zero test");
        }

        public void ModLBigInteger()
        {
            Throw(() => largePos.Mod(zero), "BigInteger: remainder divide by zero test");
            Throw(() => bi1.Mod(zero), "BigInteger: remainder divide by zero test");
            Throw(() => bi3.Negate().Mod(zero), "BigInteger: remainder divide by zero test");
            Throw(() => zero.Mod(zero), "BigInteger: remainder divide by zero test");
        }

        public void DivideAndRemainderBigInteger()
        {
            Throw(() => largePos.DivideAndRemainder(zero), "BigInteger: remainder divide by zero test");
            Throw(() => bi1.DivideAndRemainder(zero), "BigInteger: remainder divide by zero test");
            Throw(() => bi3.Negate().DivideAndRemainder(zero), "BigInteger: remainder divide by zero test");
            Throw(() => zero.DivideAndRemainder(zero), "BigInteger: remainder divide by zero test");
        }

        public void ParseString()
        {
            IsTrue(BigInteger.Parse("0").Equals(BigInteger.ValueOf(0)), "new(0)");
            IsTrue(BigInteger.Parse("1").Equals(BigInteger.ValueOf(1)), "new(1)");
            IsTrue(BigInteger.Parse("12345678901234").Equals(BigInteger.ValueOf(12345678901234L)), "new(12345678901234)");
            IsTrue(BigInteger.Parse("-1").Equals(BigInteger.ValueOf(-1)), "new(-1)");
            IsTrue(BigInteger.Parse("-12345678901234").Equals(BigInteger.ValueOf(-12345678901234L)), "new(-12345678901234)");
        }

        public void ParseStringI()
        {
            IsTrue(BigInteger.Parse("0", 16).Equals(BigInteger.ValueOf(0)), "new(0,16)");
            IsTrue(BigInteger.Parse("1", 16).Equals(BigInteger.ValueOf(1)), "new(1,16)");
            IsTrue(BigInteger.Parse("ABF345678901234", 16).Equals(BigInteger.ValueOf(0xABF345678901234L)), "new(ABF345678901234,16)");
            IsTrue(BigInteger.Parse("abf345678901234", 16).Equals(BigInteger.ValueOf(0xABF345678901234L)), "new(abf345678901234,16)");
            IsTrue(BigInteger.Parse("-1", 16).Equals(BigInteger.ValueOf(-1)), "new(-1,16)");
            IsTrue(BigInteger.Parse("-ABF345678901234", 16).Equals(BigInteger.ValueOf(-0xABF345678901234L)), "new(-ABF345678901234,16)");
            IsTrue(BigInteger.Parse("-abf345678901234", 16).Equals(BigInteger.ValueOf(-0xABF345678901234L)), "new(-abf345678901234,16)");
            IsTrue(BigInteger.Parse("-101010101", 2).Equals(BigInteger.ValueOf(-341)), "new(-101010101,2)");
        }

        public void TestToString()
        {
            IsTrue("0".Equals(BigInteger.ValueOf(0).ToString()), "0.ToString");
            IsTrue("1".Equals(BigInteger.ValueOf(1).ToString()), "1.ToString");
            IsTrue("12345678901234".Equals(BigInteger.ValueOf(12345678901234L).ToString()), "12345678901234.ToString");
            IsTrue("-1".Equals(BigInteger.ValueOf(-1).ToString()), "-1.ToString");
            IsTrue("-12345678901234".Equals(BigInteger.ValueOf(-12345678901234L).ToString()), "-12345678901234.ToString");
        }

        public void ToStringI()
        {
            IsTrue("0".Equals(BigInteger.ValueOf(0).ToString(16)), "0.ToString(16)");
            IsTrue("1".Equals(BigInteger.ValueOf(1).ToString(16)), "1.ToString(16)");
            IsTrue("abf345678901234".Equals(BigInteger.ValueOf(0xABF345678901234L).ToString(16)), "ABF345678901234.ToString(16)");
            IsTrue("-1".Equals(BigInteger.ValueOf(-1).ToString(16)), "-1.ToString(16)");
            IsTrue("-abf345678901234".Equals(BigInteger.ValueOf(-0xABF345678901234L).ToString(16)), "-ABF345678901234.ToString(16)");
            IsTrue("-101010101".Equals(BigInteger.ValueOf(-341).ToString(2)), "-101010101.ToString(2)");
        }

        public void AndLBigInteger()
        {
            foreach (BigInteger[] element in booleanPairs)
            {
                BigInteger i1 = element[0], i2 = element[1];
                BigInteger res = i1.And(i2);
                IsTrue(res.Equals(i2.And(i1)), "symmetry of and");
                int len = System.Math.Max(i1.BitLength, i2.BitLength) + 66;

                for (int i = 0; i < len; i++)
                    IsTrue((i1.TestBit(i) && i2.TestBit(i)) == res.TestBit(i), "and");
            }
        }

        public void OrBigInteger()
        {
            foreach (BigInteger[] element in booleanPairs)
            {
                BigInteger i1 = element[0], i2 = element[1];
                BigInteger res = i1.Or(i2);
                IsTrue(res.Equals(i2.Or(i1)), "symmetry of or");
                int len = System.Math.Max(i1.BitLength, i2.BitLength) + 66;

                for (int i = 0; i < len; i++)
                    IsTrue((i1.TestBit(i) || i2.TestBit(i)) == res.TestBit(i), "or");
            }
        }

        public void XOrBigInteger()
        {
            foreach (BigInteger[] element in booleanPairs)
            {
                BigInteger i1 = element[0], i2 = element[1];
                BigInteger res = i1.Xor(i2);
                IsTrue(res.Equals(i2.Xor(i1)), "symmetry of xor");
                int len = System.Math.Max(i1.BitLength, i2.BitLength) + 66;

                for (int i = 0; i < len; i++)
                    IsTrue((i1.TestBit(i) ^ i2.TestBit(i)) == res.TestBit(i), "xor");
            }
        }

        public void Not()
        {
            foreach (BigInteger[] element in booleanPairs)
            {
                BigInteger i1 = element[0];
                BigInteger res = i1.Not();
                int len = i1.BitLength + 66;

                for (int i = 0; i < len; i++)
                    IsTrue(!i1.TestBit(i) == res.TestBit(i), "not");
            }
        }

        public void AndNotBigInteger()
        {
            foreach (BigInteger[] element in booleanPairs)
            {
                BigInteger i1 = element[0], i2 = element[1];
                BigInteger res = i1.AndNot(i2);
                int len = System.Math.Max(i1.BitLength, i2.BitLength) + 66;

                for (int i = 0; i < len; i++)
                    IsTrue((i1.TestBit(i) && !i2.TestBit(i)) == res.TestBit(i), "andNot");

                // asymmetrical
                i1 = element[1];
                i2 = element[0];
                res = i1.AndNot(i2);

                for (int i = 0; i < len; i++)
                    IsTrue((i1.TestBit(i) && !i2.TestBit(i)) == res.TestBit(i), "andNot reversed");
            }

            Throw(() => BigInteger.Zero.AndNot(null), "BigInteger: AndNot null test");
            BigInteger bi = new BigInteger(0, new byte[] { });
            //AreEqual(BigInteger.Zero, bi.AndNot(BigInteger.Zero));
        }
        #endregion

        #region Private Methods
        private void TestDiv(BigInteger i1, BigInteger i2)
        {
            BigInteger q = i1.Divide(i2);
            BigInteger r = i1.Remainder(i2);
            BigInteger[] q2 = i1.DivideAndRemainder(i2);
            BigInteger quotient = q2[0];
            BigInteger remainder = q2[1];

            IsTrue(q.Equals(quotient), "Divide and DivideAndRemainder do not agree");
            IsTrue(r.Equals(remainder), "Remainder and DivideAndRemainder do not agree");
            IsTrue(q.Signum() != 0 || q.Equals(zero), "signum and equals(zero) do not agree on quotient");
            IsTrue(r.Signum() != 0 || r.Equals(zero), "signum and equals(zero) do not agree on remainder");
            IsTrue(q.Signum() == 0 || q.Signum() == i1.Signum() * i2.Signum(), "wrong sign on quotient");
            IsTrue(r.Signum() == 0 || r.Signum() == i1.Signum(), "wrong sign on remainder");
            IsTrue(r.Abs().CompareTo(i2.Abs()) < 0, "remainder out of range");
            IsTrue(q.Abs().Add(one).Multiply(i2.Abs()).CompareTo(i1.Abs()) > 0, "quotient too small");
            IsTrue(q.Abs().Multiply(i2.Abs()).CompareTo(i1.Abs()) <= 0, "quotient too large");
            BigInteger p = q.Multiply(i2);
            BigInteger a = p.Add(r);
            IsTrue(a.Equals(i1), "(a/b)*b+(a%b) != a");
            try
            {
                BigInteger mod = i1.Mod(i2);
                IsTrue(mod.Signum() >= 0, "mod is negative");
                IsTrue(mod.Abs().CompareTo(i2.Abs()) < 0, "mod out of range");
                IsTrue(r.Signum() < 0 || r.Equals(mod), "positive remainder == mod");
                IsTrue(r.Signum() >= 0 || r.Equals(mod.Subtract(i2)), "negative remainder == mod - divisor");
            }
            catch
            {
                IsTrue(i2.Signum() <= 0, "mod fails on negative divisor only");
            }
        }

        private void TestDivRanges(BigInteger i)
        {
            BigInteger bound = i.Multiply(two);
            for (BigInteger j = bound.Negate(); j.CompareTo(bound) <= 0; j = j.Add(i))
            {
                BigInteger innerbound = j.Add(two);
                BigInteger k = j.Subtract(two);

                for (; k.CompareTo(innerbound) <= 0; k = k.Add(one))
                    TestDiv(k, i);
            }
        }

        private static bool isPrime(long b)
        {
            if (b == 2)
                return true;
            
            // check for div by 2
            if ((b & 1L) == 0)
                return false;
            
            long maxlen = ((long)System.Math.Sqrt(b)) + 2;
            for (long x = 3; x < maxlen; x += 2)
            {
                if (b % x == 0)
                    return false;
            }
            return true;
        }

        private static void testAllMults(BigInteger i1, BigInteger i2, BigInteger ans)
        {
            IsTrue(i1.Multiply(i2).Equals(ans), "i1*i2=ans");
            IsTrue(i2.Multiply(i1).Equals(ans), "i2*i1=ans");
            IsTrue(i1.Negate().Multiply(i2).Equals(ans.Negate()), "-i1*i2=-ans");
            IsTrue(i2.Negate().Multiply(i1).Equals(ans.Negate()), "-i2*i1=-ans");
            IsTrue(i1.Multiply(i2.Negate()).Equals(ans.Negate()), "i1*-i2=-ans");
            IsTrue(i2.Multiply(i1.Negate()).Equals(ans.Negate()), "i2*-i1=-ans");
            IsTrue(i1.Negate().Multiply(i2.Negate()).Equals(ans), "-i1*-i2=ans");
            IsTrue(i2.Negate().Multiply(i1.Negate()).Equals(ans), "-i2*-i1=ans");
        }

        private void TestAllDivs(BigInteger i1, BigInteger i2)
        {
            TestDiv(i1, i2);
            TestDiv(i1.Negate(), i2);
            TestDiv(i1, i2.Negate());
            TestDiv(i1.Negate(), i2.Negate());
        }

        private static void IsTrue(bool Condition, string Message)
        {
            if (!Condition)
                throw new Exception("BigIntegerTest: " + Message);
        }

        private static void Throw(Action Condition, string Message)
        {
            try
            {
                Condition();
            }
            catch
            {
                return;
            }
            throw new Exception("BigIntegerTest: " + Message);
        }
        #endregion
    }
}
