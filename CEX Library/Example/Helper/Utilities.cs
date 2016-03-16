using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using VTDev.Libraries.CEXEngine.Crypto.Digest;

namespace VTDev.Projects.CEX
{
    internal static class Utilities
    {
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

        public static string GetComputerName()
        {
            return Environment.MachineName;
        }

        public static byte[] GetCredentials()
        {
            // unique credential should be at least these symbols; comp-name, sid, app-code
            // obscure the code and shift in file; make it hard to find
            string user = GetComputerName() + GetUserSid() + "x0024b88t72:im@vtc#s1d1";

            using (Keccak256 digest = new Keccak256())
                return digest.ComputeHash(Encoding.UTF8.GetBytes(user));
        }

        public static byte[] GetDomainId()
        {
            string domain = GetDomainName();
            if (string.IsNullOrEmpty(domain))
                domain = GetComputerName();

            int blockSize = domain.Length < 32 ? 32 : domain.Length;
            byte[] data = new byte[blockSize];
            byte[] name = Encoding.UTF8.GetBytes(domain);
            Buffer.BlockCopy(name, 0, data, 0, name.Length);

            using (Keccak256 digest = new Keccak256())
                return digest.ComputeHash(Encoding.UTF8.GetBytes(domain));
        }

        public static string GetDomainName()
        {
            try
            {
                // domain
                string domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
                // workgroup
                if (string.IsNullOrEmpty(domain))
                    domain = Environment.UserDomainName;

                if (Environment.MachineName.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    domain = String.Empty;

                return domain;
            }
            catch
            {
                return String.Empty;
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

        public static string GetUserName()
        {
            return Environment.UserName;
        }

        public static byte[] GetOriginId()
        {
            string user = GetUserName() + GetUserSid();
            byte[] hash;

            using (Keccak256 digest = new Keccak256())
                hash = digest.ComputeHash(Encoding.UTF8.GetBytes(user));

            byte[] id = new byte[16];
            for (int i = 0, j = 16; i < 16; i++, j++)
                id[i] = (byte)(hash[i] ^ hash[j]);

            return id;
        }

        public static string GetUserSid()
        {
            try
            {
                return WindowsIdentity.GetCurrent().User.AccountDomainSid.ToString();
            }
            catch
            {
                return string.Empty;
            }
        }

        public static bool HostAlive(string Address)
        {
            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply reply = ping.Send(Address);
                    return reply.Status == IPStatus.Success;
                }
            }
            catch (PingException)
            {
                return false;
            }
        }

        public static bool IsAdmin()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);

                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}
