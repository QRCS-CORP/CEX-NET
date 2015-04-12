using System;
using System.Windows.Forms;

namespace VTDev.Projects.CEX.Helper
{
    public static class ComboHelper
    {
        public static int IndexFromValue(int Value, ComboBox Target)
        {
            int ct = -1;
            foreach (var val in Target.Items)
            {
                ct++;
                if (val.Equals((object)Value))
                    return ct;
            }
            return -1;
        }

        public static int IndexFromValue(int Value, Type EnumType)
        {
            int ct = -1;
            foreach (var val in Enum.GetValues(EnumType))
            {
                ct++;
                if ((int)val == Value)
                    return ct;
            }
            return -1;
        }

        public static int IndexFromValue(int Value, Type EnumType, ComboBox Target)
        {
            int ct = -1;
            var match = Enum.GetName(EnumType, Value);

            foreach (var val in Target.Items)
            {
                ct++;
                if (val.ToString().Equals(match))
                    return ct;
            }
            return -1;
        }

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
