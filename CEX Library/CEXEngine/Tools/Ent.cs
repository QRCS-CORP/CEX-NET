#region Directives
using System;
using System.IO;
using System.ComponentModel;
#endregion

#region Notes
/// A version of Brett Trotter's C# version of Ent: http://www.codeproject.com/Articles/11672/ENT-A-Pseudorandom-Number-Sequence-Test-Program-C?msg=4671947#xx4671947xx
/// The original c++ program written by John Walker: http://www.fourmilab.ch/random/
#endregion

namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// A version of the Ent random testing class; evaluates entropy levels within a sample or a file
    /// </summary>
    public class EntResult
    {
        /// <summary>
        /// Entropy bits per byte (ex. 7.999826)
        /// </summary>
        public double Entropy;
        /// <summary>
        /// Chi square distribution
        /// </summary>
        public double ChiSquare;
        /// <summary>
        /// The Chi square probability percentage, (50% is optimum)
        /// </summary>
        public double ChiProbability;
        /// <summary>
        /// Arithmetic mean value (127.5 = random)
        /// </summary>
        public double Mean;
        /// <summary>
        /// The constant 127.5
        /// </summary>
        public double ExpectedMeanForRandom;
        /// <summary>
        /// Monte Carlo value for Pi (value should be close to Pi)
        /// </summary>
        public double MonteCarloPiCalc;
        /// <summary>
        /// The Monte Carlo error percentage (lower is better)
        /// </summary>
        public double MonteCarloErrorPct;
        /// <summary>
        /// Serial correlation coefficient (totally uncorrelated = 0.0)
        /// </summary>
        public double SerialCorrelation;
        /// <summary>
        /// The collection bin counter
        /// </summary>
        public long[] OccuranceCount;
        /// <summary>
        /// The maximum compression ratio
        /// </summary>
        public double OptimumCompressionReductionPct;
        /// <summary>
        /// The number of samples tested
        /// </summary>
        public long NumberOfSamples;
        /// <summary>
        /// The Pi sample graph
        /// </summary>
        public double[] PiSamples;
        /// <summary>
        /// The Mean sample graph
        /// </summary>
        public double[] MeanSamples;
    }

    public class Ent : IDisposable
    {
        #region Event
        /// <summary>
        /// Ent evaluation progress counter
        /// </summary>
        /// <param name="Percent">The percentage calculated</param>
        public delegate void EntCounterDelegate(long Percent);
        /// <summary>
        /// The Ent progress counter
        /// </summary>
        public event EntCounterDelegate ProgressCounter;
        #endregion

        #region Constants
        private const int BIN_BUFFER = 32768;
        private const int MONTE_COUNT = 6;
        private const int SUB_SAMPLES = 64;
        private const int SAMPLE_SIZE = 4096;
        #endregion

        #region Fields
        private long[] _binCount = new long[256];
        private static double _currentProgress = 0;
        private double[] _entProbability = new double[256];
        private double _inCirc = 0;
        private bool _isDisposed = false;
        private double[] _meanSamples = new double[SUB_SAMPLES];
        private long _monteAccum = 0;
        private double _montePi = 0;
        private uint[] _montePiComp = new uint[MONTE_COUNT];
        private long _monteTries = 0;
        private double _monteX = 0;
        private double _monteY = 0;
        private double[] _piSamples = new double[SUB_SAMPLES];
        private long _totalBytes = 0;
        private double _serialCC = 0;
        private double _serialLast = 0;
        private double _serialRun = 0;
        private double _serialT1 = 0;
        private double _serialT2 = 0;
        private double _serialT3 = 0;
        private double _serialU0 = 0;
        private readonly double[,] _chiSqt = new double[2, 10] 
			{
				{0.5, 0.25, 0.1, 0.05, 0.025, 0.01, 0.005, 0.001, 0.0005, 0.0001}, 
				{0.0, 0.6745, 1.2816, 1.6449, 1.9600, 2.3263, 2.5758, 3.0902, 3.2905, 3.7190}
			};
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public Ent()
        {
            this.GraphCollection = false;
            Init();
        }

        /// <summary>
        /// Finalize resources
        /// </summary>
        ~Ent()
        {
            Dispose(false);
        }
        #endregion

        #region Properties
        /// <summary>
        /// If true, returns the Pi and Mean value graphs in the EntResult structure
        /// </summary>
        public bool GraphCollection { get; set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Calculate the entropy contained in a file
        /// </summary>
        /// 
        /// <param name="FileName">The full path to the file to be tested</param>
        /// 
        /// <returns>A populated <see cref="EntResult"/> class</returns>
        public EntResult Calculate(string FileName)
        {
            byte[] fileBuffer;
            _currentProgress = 0;

            using (FileStream fileStream = new FileStream(FileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                fileBuffer = new byte[fileStream.Length];
                fileStream.Read(fileBuffer, 0, (int)fileStream.Length);
            }

            AddSamples(fileBuffer);

            return EndCalculation();
        }

        /// <summary>
        /// Calculate the entropy contained in a sample
        /// </summary>
        /// 
        /// <param name="Buffer">The sample array to be tested</param>
        /// 
        /// <returns>A populated <see cref="EntResult"/> class</returns>
        public EntResult Calculate(byte[] Buffer)
        {
            _currentProgress = 0;
            AddSamples(Buffer);

            return EndCalculation();
        }

        /// <summary>
        /// Reset the class variables
        /// </summary>
        public void Reset()
        {
            _binCount = new long[256];
            _currentProgress = 0;
            _entProbability = new double[256];
            _inCirc = Math.Pow(Math.Pow(256.0, (double)(MONTE_COUNT / 2)) - 1, 2.0);
            _meanSamples = new double[SUB_SAMPLES];
            _monteAccum = 0;
            _montePi = 0;
            _montePiComp = new uint[MONTE_COUNT];
            _monteTries = 0;
            _monteX = 0;
            _monteY = 0;
            _piSamples = new double[SUB_SAMPLES];
            _totalBytes = 0;
            _serialCC = 0;
            _serialLast = 0;
            _serialRun = 0;
            _serialT1 = 0;
            _serialT2 = 0;
            _serialT3 = 0;
            _serialU0 = 0;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Calculate the progress
        /// </summary>
        /// 
        /// <param name="Position">Current position</param>
        /// <param name="Maximum">Progress max</param>
        private void CalculateProgress(long Position, long Maximum)
        {
            if (ProgressCounter != null)
            {
                double pos = Position;
                double percent = Math.Round((double)(pos / Maximum) * 100, 0);
                if (percent > _currentProgress)
                {
                    ProgressCounter((long)percent);
                    _currentProgress = percent;
                }
            }
        }

        /// <summary>
        /// Initialize random counters
        /// </summary>
        /// 
        /// <param name="BinaryMode">Binary mode</param>
        private void Init()
        {
            // Reset Monte Carlo accumulator pointer
            _monteAccum = 0;
            // Clear Monte Carlo tries
            _monteTries = 0;
            // Clear Monte Carlo inside count
            _inCirc = 65535.0 * 65535.0;
            // Mark first time for serial correlation
            _serialT1 = _serialT2 = _serialT3 = 0.0;
            // Clear serial correlation terms
            _inCirc = Math.Pow(Math.Pow(256.0, (double)(MONTE_COUNT / 2)) - 1, 2.0);

            for (int i = 0; i < 256; i++)
                _binCount[i] = 0;

            _totalBytes = 0;
        }

        /// <summary>
        /// Add one or more bytes to accumulation
        /// </summary>
        /// 
        /// <param name="Samples">Buffer</param>
        /// <param name="Fold">Fold - not implemented</param>
        private void AddSamples(byte[] Samples)
        {
            int mp = 0;
            bool sccFirst = true;
            int preProcessLength = (Samples.Length - BIN_BUFFER) / SAMPLE_SIZE;
            int counter = 0;

            if (this.GraphCollection)
            {
                _piSamples = new double[preProcessLength];
                _meanSamples = new double[preProcessLength];
            }

            for (int i = 0; i < Samples.Length; i++)
            {
                // Update counter for this bin
                _binCount[(int)Samples[i]]++;
                _totalBytes++;
                // Update inside/outside circle counts for Monte Carlo computation of PI
                _montePiComp[mp++] = Samples[i];

                // Save character for Monte Carlo
                if (mp >= MONTE_COUNT)
                {
                    // Calculate every MONTEN character
                    int mj;
                    mp = 0;
                    _monteAccum++;
                    _monteX = _monteY = 0;

                    for (mj = 0; mj < MONTE_COUNT / 2; mj++)
                    {
                        _monteX = (_monteX * 256.0) + _montePiComp[mj];
                        _monteY = (_monteY * 256.0) + _montePiComp[(MONTE_COUNT / 2) + mj];
                    }

                    if ((_monteX * _monteX + _monteY * _monteY) <= _inCirc)
                        _monteTries++;
                }

                // Update calculation of serial correlation coefficient
                _serialRun = (int)Samples[i];
                if (sccFirst)
                {
                    sccFirst = false;
                    _serialLast = 0;
                    _serialU0 = _serialRun;
                }
                else
                {
                    _serialT1 = _serialT1 + _serialLast * _serialRun;
                }

                _serialT2 = _serialT2 + _serialRun;
                _serialT3 = _serialT3 + (_serialRun * _serialRun);
                _serialLast = _serialRun;

                // collect samples for graphs
                if (this.GraphCollection)
                {
                    if (i % SAMPLE_SIZE == 0 && i > BIN_BUFFER)
                    {
                        double dataSum = 0.0;

                        for (int j = 0; j < 256; j++)
                            dataSum += ((double)j) * _binCount[j];

                        _meanSamples[counter] = dataSum / _totalBytes;
                        _piSamples[counter] = 4.0 * (((double)_monteTries) / _monteAccum);
                        counter++;
                    }
                }

                if (i == Samples.Length - 1)
                {
                    byte[] b = new byte[16];
                    Buffer.BlockCopy(Samples, Samples.Length - 17, b, 0, 16);
                }
                CalculateProgress(_totalBytes, Samples.Length);
            }
        }

        /// <summary>
        /// Complete calculation and return results
        /// </summary>
        /// 
        /// <returns>EntResult Structure</returns>
        private EntResult EndCalculation()
        {
            double entropy = 0.0;
            double chiSq = 0.0;
            double dataSum = 0.0;
            double binVal = 0.0;
            int pos = 0;

            // Complete calculation of serial correlation coefficient
            _serialT1 = _serialT1 + _serialLast * _serialU0;
            _serialT2 = _serialT2 * _serialT2;
            _serialCC = _totalBytes * _serialT3 - _serialT2;

            if (_serialCC == 0.0)
                _serialCC = -100000;
            else
                _serialCC = (_totalBytes * _serialT1 - _serialT2) / _serialCC;

            // Scan bins and calculate probability for each bin and Chi-Square distribution
            double cExp = _totalBytes / 256.0;

            // Expected count per bin
            for (int i = 0; i < 256; i++)
            {
                _entProbability[i] = (double)_binCount[i] / _totalBytes;
                binVal = _binCount[i] - cExp;
                chiSq = chiSq + (binVal * binVal) / cExp;
                dataSum += ((double)i) * _binCount[i];
            }

            // Calculate entropy
            for (int i = 0; i < 256; i++)
            {
                if (_entProbability[i] > 0.0)
                    entropy += _entProbability[i] * Log2(1 / _entProbability[i]);
            }

            // Calculate Monte Carlo value for PI from percentage of hits within the circle
            _montePi = 4.0 * (((double)_monteTries) / _monteAccum);

            // Calculate probability of observed distribution occurring from the results of the Chi-Square test
            double chip = Math.Sqrt(2.0 * chiSq) - Math.Sqrt(2.0 * 255.0 - 1.0);

            binVal = Math.Abs(chip);

            for (pos = 9; pos >= 0; pos--)
            {
                if (_chiSqt[1, pos] < binVal)
                    break;
            }

            if (pos < 0) pos = 0;

            chip = (chip >= 0.0) ? _chiSqt[0, pos] : 1.0 - _chiSqt[0, pos];
            double compReductionPct = (8 - entropy) / 8.0;

            // Return results
            EntResult result = new EntResult()
            {
                Entropy = entropy,
                ChiSquare = chiSq,
                ChiProbability = chip,
                Mean = dataSum / _totalBytes,
                ExpectedMeanForRandom = 127.5,
                MonteCarloPiCalc = _montePi,
                MonteCarloErrorPct = (Math.Abs(Math.PI - _montePi) / Math.PI),
                SerialCorrelation = _serialCC,
                OptimumCompressionReductionPct = compReductionPct,
                OccuranceCount = _binCount,
                NumberOfSamples = _totalBytes,
                MeanSamples = _meanSamples,
                PiSamples = _piSamples
            };

            return result;
        }

        /// <summary>
        /// Returns log faction
        /// </summary>
        private double Log2(double x)
        {
            return Math.Log(x, 2);
        }
        #endregion

        #region IDispose
        public void Dispose()
        {
            Dispose(true);
        }

        void IDisposable.Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed)
            {
                if (Disposing)
                {
                    // clear the arrays
                    if (_binCount != null)
                        Array.Clear(_binCount, 0, _binCount.Length);
                    if (_entProbability != null)
                        Array.Clear(_entProbability, 0, _entProbability.Length);
                    if (_meanSamples != null)
                        Array.Clear(_meanSamples, 0, _meanSamples.Length);
                    if (_montePiComp != null)
                        Array.Clear(_montePiComp, 0, _montePiComp.Length);
                    if (_piSamples != null)
                        Array.Clear(_piSamples, 0, _piSamples.Length);
                    if (_chiSqt != null)
                        Array.Clear(_chiSqt, 0, _chiSqt.Length);
                }
                _isDisposed = true;
            }
        }
        #endregion
    }
}
