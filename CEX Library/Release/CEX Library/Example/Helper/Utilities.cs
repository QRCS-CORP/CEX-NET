using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace VTDev.Projects.CEX
{
    public static class Utilities
    {
        /// <summary>
        /// Test a directory for create file access permissions
        /// </summary>
        /// <param name="DirectoryPath">Full path to file or directory </param>
        /// <param name="AccessRight">File System right tested</param>
        /// <returns>State [bool]</returns>
        public static bool DirectoryHasPermission(string DirectoryPath, FileSystemRights AccessRight)
        {
            if (string.IsNullOrEmpty(DirectoryPath)) return false;

            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(DirectoryPath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference))
                    {
                        if ((AccessRight & rule.FileSystemRights) == AccessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        public static long GetFileSize(string FilePath)
        {
            try
            {
                return new FileInfo(FilePath).Length;
            }
            catch { }
            return -1;
        }

        /// <summary>
        /// Directory can write/create (works every time)
        /// </summary>
        /// <param name="DirectoryPath">Directory path</param>
        /// <returns>Success [bool]</returns>
        public static bool DirectoryIsWritable(string DirectoryPath)
        {
            try
            {
                if (!Directory.Exists(DirectoryPath)) return false;

                string path = Path.Combine(DirectoryPath, Path.GetRandomFileName());

                using (FileStream stream = File.Create(path, 1, FileOptions.DeleteOnClose))
                    return File.Exists(path);
            }
            catch
            {
                return false;
            }
        }

        public static string GetUniquePath(string FilePath)
        {
            string directory = Path.GetDirectoryName(FilePath);
            string fileName = Path.GetFileNameWithoutExtension(FilePath);
            string extension = Path.GetExtension(FilePath);

            for (int j = 1; j < 101; j++)
            {
                // test unique names
                if (File.Exists(FilePath))
                    FilePath = Path.Combine(directory, fileName + j.ToString() + extension);
                else
                    break;
            }
            return FilePath;
        }

        public static string GetUniquePath(string DirectoryPath, string FileName, string FileExtension)
        {
            string filePath = Path.Combine(DirectoryPath, FileName + FileExtension);

            for (int j = 1; j < 101; j++)
            {
                // test unique names
                if (File.Exists(filePath))
                    filePath = Path.Combine(DirectoryPath, FileName + j.ToString() + FileExtension);
                else
                    break;
            }
            return filePath;
        }
    }
}
