#region Directives
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
#endregion

namespace VTDev.Projects.CEX.Helper
{
    [Serializable]
    [StructLayout(LayoutKind.Sequential)]
    internal struct SettingsContainer
    {
        #region Constants
        private const int AUTH_SIZE = 128;
        private const int CIPH_SIZE = 40;
        private const int SIGN_SIZE = 1;
        private const int DOMA_SIZE = 1;
        private const int VOLT_SIZE = 1;
        private const int SING_SIZE = 1;
        private const int OVWR_SIZE = 1;
        private const int PKGA_SIZE = 1;
        private const int NONA_SIZE = 1;
        private const int NOEX_SIZE = 1;
        private const long AUTH_SEEK = 0;
        private const long CIPH_SEEK = AUTH_SIZE;
        private const long SIGN_SEEK = AUTH_SIZE + CIPH_SIZE;
        private const long DOMA_SEEK = AUTH_SIZE + CIPH_SIZE + SIGN_SEEK;
        private const long VOLT_SEEK = AUTH_SIZE + CIPH_SIZE + SIGN_SEEK + DOMA_SIZE;
        private const long SING_SEEK = AUTH_SIZE + CIPH_SIZE + SIGN_SEEK + DOMA_SIZE + VOLT_SIZE;
        private const long OVWR_SEEK = AUTH_SIZE + CIPH_SIZE + SIGN_SEEK + DOMA_SIZE + VOLT_SIZE + SING_SIZE;
        private const long PKGA_SEEK = AUTH_SIZE + CIPH_SIZE + SIGN_SEEK + DOMA_SIZE + VOLT_SIZE + SING_SIZE + OVWR_SIZE;
        private const long NONA_SEEK = AUTH_SIZE + CIPH_SIZE + SIGN_SEEK + DOMA_SIZE + VOLT_SIZE + SING_SIZE + OVWR_SIZE + PKGA_SIZE;
        private const long NOEX_SEEK = AUTH_SIZE + CIPH_SIZE + SIGN_SEEK + DOMA_SIZE + VOLT_SIZE + SING_SIZE + OVWR_SIZE + PKGA_SIZE + NONA_SIZE;
        #endregion

        #region Public Fields
        // use a keyauthority structure to store local id settings
        [MarshalAs(UnmanagedType.Struct, SizeConst = AUTH_SIZE)]
        internal KeyAuthority Authority;

        // use a cipherdescription to store cipher settings
        [MarshalAs(UnmanagedType.Struct, SizeConst = CIPH_SIZE)]
        internal CipherDescription Description;

        // key policies
        internal bool SignChecked;
        internal bool DomainRestrictChecked;
        internal bool VolatileChecked;
        internal bool SingleUseChecked;
        internal bool PostOverwriteChecked;
        internal bool PackageAuthChecked;
        internal bool NoNarrativeChecked;
        internal bool NoExportChecked;
        #endregion

        #region Methods
        /// <summary>
        /// Reset all struct members
        /// </summary>
        internal void Reset()
        {
            Authority.Reset();
            Description.Reset();
            SignChecked = false;
            DomainRestrictChecked = false;
            VolatileChecked = false;
            SingleUseChecked = false;
            PostOverwriteChecked = false;
            PackageAuthChecked = false;
            NoNarrativeChecked = false;
            NoExportChecked = false;
        }

        /// <summary>
        /// Convert a string to a PackageKey structure
        /// </summary>
        /// 
        /// <param name="Settings">The string containing the PackageKey</param>
        /// 
        /// <returns>A PackageKey structuree</returns>
        public static SettingsContainer FromString(string Settings)
        {
            return DeSerialize(new MemoryStream(Encoding.ASCII.GetBytes(Settings)));
        }

        /// <summary>
        /// Convert a SettingsStruct to a string representation
        /// </summary>
        /// 
        /// <param name="Package">The SettingsStruct</param>
        /// 
        /// <returns>A base 64 string representation of the structure</returns>
        internal static string ToString(SettingsContainer Settings)
        {
            return Encoding.ASCII.GetString(Serialize(Settings).ToArray());
        }

        /// <summary>
        /// Deserialize a SettingsStruct>
        /// </summary>
        /// 
        /// <param name="SettingsStream">Stream containing a serialized SettingsStruct</param>
        /// 
        /// <returns>A populated SettingsStruct</returns>
        internal static SettingsContainer DeSerialize(MemoryStream SettingsStream)
        {
            BinaryReader reader = new BinaryReader(SettingsStream);
            SettingsContainer settings = new SettingsContainer();

            settings.Authority = new KeyAuthority(SettingsStream);
            settings.Description = new CipherDescription(SettingsStream);
            settings.SignChecked = reader.ReadBoolean();
            settings.DomainRestrictChecked = reader.ReadBoolean();
            settings.VolatileChecked = reader.ReadBoolean();
            settings.SingleUseChecked = reader.ReadBoolean();
            settings.PostOverwriteChecked = reader.ReadBoolean();
            settings.PackageAuthChecked = reader.ReadBoolean();
            settings.NoNarrativeChecked = reader.ReadBoolean();
            settings.NoExportChecked = reader.ReadBoolean();
            
            return settings;
        }

        /// <summary>
        /// Serialize a SettingsStruct structure
        /// </summary>
        /// 
        /// <param name="Settings">A SettingsStruct structure</param>
        /// 
        /// <returns>A stream containing the SettingsStruct data</returns>
        internal static MemoryStream Serialize(SettingsContainer Settings)
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(Settings.Authority.ToBytes());
            writer.Write(Settings.Description.ToBytes());
            writer.Write(Settings.SignChecked);
            writer.Write(Settings.DomainRestrictChecked);
            writer.Write(Settings.VolatileChecked);
            writer.Write(Settings.SingleUseChecked);
            writer.Write(Settings.PostOverwriteChecked);
            writer.Write(Settings.PackageAuthChecked);
            writer.Write(Settings.NoNarrativeChecked);
            writer.Write(Settings.NoExportChecked);
            stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }
        #endregion
    }
}
