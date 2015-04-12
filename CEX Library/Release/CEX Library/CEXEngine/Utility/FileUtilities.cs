#region Directives
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// <h3>File, Folder and Drive methods wrapper class.</h3>
    /// </summary>
    public static class FileUtilities
    {
        #region Drive Tools
        /// <summary>
        /// Get Total Drive space
        /// </summary>
        /// 
        /// <param name="DrivePath">Path to drive</param>
        /// 
        /// <returns>Result</returns>
        public static long DriveGetSize(string DrivePath)
        {
            if (!string.IsNullOrEmpty(DrivePath))
            {
                DriveInfo d = new DriveInfo(DrivePath);

                if (d.IsReady)
                    return d.TotalSize;
            }
            return 0;
        }

        /// <summary>
        /// Get Drive Free space
        /// </summary>
        /// 
        /// <param name="DrivePath">Path to drive</param>
        /// 
        /// <returns>Result</returns>
        public static long DriveGetFreeSpace(string DrivePath)
        {
            if (!string.IsNullOrEmpty(DrivePath))
            {
                DriveInfo d = new DriveInfo(DrivePath);

                if (d.IsReady)
                    return d.AvailableFreeSpace;
            }
            return 0;
        }

        /// <summary>
        /// Get Drive Free space
        /// </summary>
        /// 
        /// <param name="DrivePath">Path to drive</param>
        /// 
        /// <returns>Result</returns>
        public static long DriveGetFreeSpaceMB(string DrivePath)
        {
            if (!string.IsNullOrEmpty(DrivePath))
            {
                DriveInfo d = new DriveInfo(DrivePath);

                if (d.IsReady)
                {
                    double bytes = d.AvailableFreeSpace;
                    double divisor = Math.Pow(1024, 2);

                    return (bytes > divisor) ? (long)(bytes / divisor) : 0;
                }
            }
            return 0;
        }

        /// <summary>
        /// Get the drive path from a directory or file path
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Path</param>
        /// 
        /// <returns>Result</returns>
        public static string DriveGetPath(string DirectoryPath)
        {
            return (!string.IsNullOrEmpty(DirectoryPath) ? Path.GetPathRoot(DirectoryPath) : string.Empty);
        }

        /// <summary>
        /// Drive is available
        /// </summary>
        /// 
        /// <param name="DrivePath">Path to drive</param>
        /// 
        /// <returns>Result</returns>
        public static bool IsDriveReady(string DrivePath)
        {
            return (!string.IsNullOrEmpty(DrivePath)) ? new DriveInfo(DrivePath).IsReady : false;
        }
        #endregion

        #region Directory Tools
        /// <summary>
        /// Create a folder
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to folder</param>
        /// 
        /// <returns>Success</returns>
        public static bool DirectoryCreate(string DirectoryPath)
        {
            return (!string.IsNullOrEmpty(DirectoryPath)) ? Directory.CreateDirectory(DirectoryPath).Exists : false;
        }

        /// <summary>
        /// Test for directory and create
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to folder</param>
        /// 
        /// <returns>Success</returns>
        public static bool DirectoryChecked(string DirectoryPath)
        {
            if (!string.IsNullOrEmpty(DirectoryPath)) return false;
            return Directory.Exists(DirectoryPath) ? true : DirectoryCreate(DirectoryPath);
        }

        /// <summary>
        /// Test for directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to folder</param>
        /// 
        /// <returns>Success</returns>
        public static bool DirectoryExists(string DirectoryPath)
        {
            bool b = Directory.Exists(DirectoryPath);
            return (!string.IsNullOrEmpty(DirectoryPath)) ? Directory.Exists(DirectoryPath) : false;
        }

        /// <summary>
        /// Get the number of files in a directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full directory path</param>
        /// 
        /// <returns>Count</returns>
        public static int DirectoryGetFileCount(string DirectoryPath)
        {
            string[] filePaths = DirectoryGetFiles(DirectoryPath);
            return filePaths == null ? 0 : filePaths.Length;
        }

        /// <summary>
        /// Return all the files in a directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Directory path</param>
        /// 
        /// <returns>File names [string]]</returns>
        public static string[] DirectoryGetFiles(string DirectoryPath)
        {
            try
            {
                return (DirectoryExists(DirectoryPath)) ? Directory.GetFiles(DirectoryPath) : null;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Get common directories
        /// </summary>
        /// 
        /// <param name="FolderPath">Folder enum</param>
        /// 
        /// <returns>Directory [string]</returns>
        public static string DirectoryGetCommon(Environment.SpecialFolder FolderPath)
        {
            try
            {
                return Environment.GetFolderPath(FolderPath);
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Get file directory from path
        /// </summary>
        /// 
        /// <param name="FilePath">File path</param>
        /// 
        /// <returns>Directory [string]</returns>
        public static string DirectoryGetPath(string FilePath)
        {
            return (!string.IsNullOrEmpty(FilePath)) ? Path.GetDirectoryName(FilePath) : string.Empty;
        }

        /// <summary>
        /// Return all the files in a directory
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Directory path</param>
        /// 
        /// <returns>File names [string]]</returns>
        public static long DirectoryGetSize(string DirectoryPath)
        {
            if (!DirectoryExists(DirectoryPath)) return -1;
            long size = 0;

            try
            {
                string[] files = Directory.GetFiles(DirectoryPath, "*.*", SearchOption.AllDirectories);

                foreach (var file in files)
                    size += FileGetSize(file);

                return size;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Test a directory for create file access permissions
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full path to file or directory </param>
        /// <param name="AccessRight">File System right tested</param>
        /// 
        /// <returns>State</returns>
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

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Directory can write/create
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Directory path</param>
        /// 
        /// <returns>Success</returns>
        public static bool DirectoryIsWritable(string DirectoryPath)
        {
            try
            {
                if (!DirectoryExists(DirectoryPath)) return false;

                string path = Path.Combine(DirectoryPath, Path.GetRandomFileName());
                using (FileStream fs = File.Create(path, 1, FileOptions.DeleteOnClose))
                    return File.Exists(path);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Test a directory for create file access permissions
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full directory path</param>
        /// 
        /// <returns>State</returns>
        public static bool DirectoryCanCreate(string DirectoryPath)
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
                        if ((FileSystemRights.CreateFiles & rule.FileSystemRights) == FileSystemRights.CreateFiles)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
                return false;
            }
            catch 
            { 
                return false;
            }
        }

        /// <summary>
        /// Test a directory for write file access permissions
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Full directory path</param>
        /// 
        /// <returns>State</returns>
        public static bool DirectoryCanWrite(string DirectoryPath)
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
                        if ((FileSystemRights.Write & rule.FileSystemRights) == FileSystemRights.Write)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
                return false;
            }
            catch 
            { 
                return false;
            }
        }
        #endregion

        #region Directory Security
        /// <summary>
        /// Add an access rule to a folder
        /// </summary>
        /// 
        /// <param name="Path">Folder path</param>
        /// <param name="User">UNC path to user profile ex. Environment.UserDomainName + "\\" + Environment.UserName</param>
        /// <param name="Rights">Desired file system rights</param>
        /// <param name="Access">Desired level of access</param>
        public static void DirectoryAddAccessRule(string Path, string User, FileSystemRights Rights, AccessControlType Access)
        {
            // Get a DirectorySecurity object that represents the current security settings
            System.Security.AccessControl.DirectorySecurity sec = System.IO.Directory.GetAccessControl(Path);
            // Add the FileSystemAccessRule to the security settings
            FileSystemAccessRule accRule = new FileSystemAccessRule(User, Rights, Access);
            sec.AddAccessRule(accRule);
        }

        /// <summary>
        /// Add a file system right to a directory
        /// </summary>
        /// 
        /// <param name="Path">Full path to directory</param>
        /// <param name="Account">UNC path to user profile</param>
        /// <param name="Rights">Desired file system rights</param>
        /// <param name="ControlType">Access control type</param>
        public static void DirectoryAddSecurity(string Path, string Account, FileSystemRights Rights, AccessControlType ControlType)
        {
            // Create a new DirectoryInfo object
            DirectoryInfo dInfo = new DirectoryInfo(Path);
            // Get a DirectorySecurity object that represents the current security settings
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            // Add the FileSystemAccessRule to the security settings
            dSecurity.AddAccessRule(new FileSystemAccessRule(Account, Rights, ControlType));
            // Set the new access settings
            dInfo.SetAccessControl(dSecurity);
        }

        /// <summary>
        /// Get access rules for a folder
        /// </summary>
        /// 
        /// <param name="Path">Folder path</param>
        /// <param name="Account">UNC path to user profile</param>
        /// 
        /// <returns>Rule collection [AuthorizationRuleCollection]</returns>
        public static AuthorizationRuleCollection DirectoryGetAccessRules(string Path, string Account)
        {
            DirectoryInfo dInfo = new DirectoryInfo(Path);
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            return dSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
        }

        /// <summary>
        /// Remove a file system right to a directory
        /// </summary>
        /// 
        /// <param name="FileName">Full path to directory</param>
        /// <param name="Account">UNC path to user profile</param>
        /// <param name="Rights">Desired file system rights</param>
        /// <param name="ControlType">Access control type</param>
        public static void DirectoryRemoveSecurity(string FileName, string Account, FileSystemRights Rights, AccessControlType ControlType)
        {
            // Create a new DirectoryInfo object.
            DirectoryInfo dInfo = new DirectoryInfo(FileName);
            // Get a DirectorySecurity object that represents the current security settings  
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            // Add the FileSystemAccessRule to the security settings
            dSecurity.RemoveAccessRule(new FileSystemAccessRule(Account, Rights, ControlType));
            // Set the new access settings
            dInfo.SetAccessControl(dSecurity);
        }
        #endregion

        #region File Tools
        /// <summary>
        /// Safely create a full path
        /// </summary>
        /// 
        /// <param name="DirectoryPath">Directory path</param>
        /// <param name="FileName">File name</param>
        /// 
        /// <returns>Full path to file</returns>
        public static string FileJoinPaths(string DirectoryPath, string FileName)
        {
            const string slash = @"\";

            if (string.IsNullOrEmpty(DirectoryPath)) return string.Empty;
            if (string.IsNullOrEmpty(FileName)) return string.Empty;

            if (!DirectoryPath.EndsWith(slash))
                DirectoryPath += slash;

            if (FileName.StartsWith(slash))
                FileName = FileName.Substring(1);

            return DirectoryPath + FileName;
        }

        /// <summary>
        /// Test a file for create file access permissions
        /// </summary>
        /// 
        /// <param name="FilePath">Full path to file</param>
        /// <param name="AccessRight">File System right tested</param>
        /// 
        /// <returns>State</returns>
        public static bool FileHasPermission(string FilePath, FileSystemRights AccessRight)
        {
            if (string.IsNullOrEmpty(FilePath)) return false;

            try
            {
                AuthorizationRuleCollection rules = File.GetAccessControl(FilePath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
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
                return false;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Get the size of  file
        /// </summary>
        /// 
        /// <param name="FilePath">Full path to file</param>
        /// 
        /// <returns>File length</returns>
        public static long FileGetSize(string FilePath)
        {
            try
            {
                return File.Exists(FilePath) ? new FileInfo(FilePath).Length : 0;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Adds an extension to a file unique to the directory
        /// </summary>
        /// 
        /// <param name="FullPath">Full file path</param>
        /// 
        /// <returns>Unique filename in original path</returns>
        public static string FileGetUniqueName(string FullPath)
        {
            if (!IsValidFilePath(FullPath)) return string.Empty;
            if (!DirectoryExists(DirectoryGetPath(FullPath))) return string.Empty;

            string folderPath = DirectoryGetPath(FullPath);
            string fileName = Path.GetFileNameWithoutExtension(FullPath);
            string fileExtension = Path.GetExtension(FullPath);

            string filePath = Path.Combine(folderPath, fileName + fileExtension);

            for (int i = 1; i < 10240; i++)
            {
                // test unique names
                if (File.Exists(filePath))
                    filePath = Path.Combine(folderPath, fileName + " " + i.ToString() + fileExtension);
                else
                    break;
            }

            return filePath;
        }

        /// <summary>
        /// File is readable
        /// </summary>
        /// 
        /// <param name="FilePath">Full path to file</param>
        /// 
        /// <returns>Success</returns>
        public static bool FileIsReadable(string FilePath)
        {
            try
            {
                if (!File.Exists(FilePath)) return false;
                using (FileStream fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read)) { }
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Test a file to see if it is readonly
        /// </summary>
        /// 
        /// <param name="FilePath">Full path to file</param>
        /// 
        /// <returns>Read only</returns>
        public static bool FileIsReadOnly(string FilePath)
        {
            if (!IsValidFilePath(FilePath)) return false;
            if (!File.Exists(FilePath)) return false;

            FileAttributes fa = File.GetAttributes(FilePath);
            return (fa.ToString().IndexOf(FileAttributes.ReadOnly.ToString()) > -1);
        }

        /// <summary>
        /// Test if file name is valid [has extension]
        /// </summary>
        /// 
        /// <param name="FileName">File name</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValidFileName(string FileName)
        {
            try
            {
                return (!string.IsNullOrEmpty(FileName) ? !string.IsNullOrEmpty(Path.GetExtension(FileName)) : false);
            }
            catch 
            { 
                return false;
            }
        }

        /// <summary>
        /// Test path to see if directory exists and file name has proper format
        /// </summary>
        /// 
        /// <param name="FilePath">Full path to file</param>
        /// 
        /// <returns>Valid</returns>
        public static bool IsValidFilePath(string FilePath)
        {
            if (DirectoryExists(DirectoryGetPath(FilePath)))
                if (IsValidFileName(FilePath))
                    return true;

            return false;
        }
        #endregion

        #region Utilities
        /// <summary>
        /// Format bytes into larger sizes
        /// </summary>
        /// 
        /// <param name="bytes">Length in bytes</param>
        /// 
        /// <returns>Size string</returns>
        public static string FormatBytes(long bytes)
        {
            if (bytes < 0) return string.Empty;

            const int scale = 1024;
            string[] orders = new string[] { "TB", "GB", "MB", "KB", "Bytes" };
            long max = (long)Math.Pow(scale, orders.Length - 1);

            foreach (string order in orders)
            {
                if (bytes > max)
                    return string.Format("{0:##.#} {1}", Decimal.Divide(bytes, max), order);

                max /= scale;
            }

            return string.Empty;
        }

        /// <summary>
        /// Get the local profile path
        /// </summary>
        /// 
        /// <returns>Profile path</returns>
        public static string GetLocalProfile()
        {
            return Environment.UserDomainName + "\\" + Environment.UserName;
        }
        #endregion
    }
}
