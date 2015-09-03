using System;
using System.Windows.Forms;

namespace VTDev.Projects.CEX.Helper
{
    public static class ComboEnumHelper
    {
        public static void AddEnumRange(ComboBox Target, Type EnumType, int Start, int End)
        {
            Target.Items.Clear();

            foreach (var val in Enum.GetValues(EnumType))
            {
                if ((int)val >= Start && (int)val <= End)
                    Target.Items.Add(Enum.GetName(EnumType, val));
            }
        }

        public static string[] GetEnumNames(ComboBox Target, Type EnumType)
        {
            return Enum.GetNames(EnumType);
        }

        public static Array GetEnumValues(ComboBox Target, Type EnumType)
        {
            return Enum.GetValues(EnumType);
        }

        public static void LoadEnumValues(ComboBox Target, Type EnumType)
        {
            Target.DataSource = Enum.GetValues(EnumType);
        }

        public static void SetSelectedIndex(ComboBox Target, int Index)
        {
            try
            {
                // necessary because bug in .net throws null exception
                if (Target.Items.Count > Index)
                    Target.SelectedIndex = Index;
            }
            catch { }
        }
    }
}
