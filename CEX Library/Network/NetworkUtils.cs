using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Network
{
    public static class NetworkUtils
    {
        public static bool IsValidIP(string Host)
        {
            IPAddress result = null;
            return !String.IsNullOrEmpty(Host) && IPAddress.TryParse(Host, out result);
        }

        public static IPAddress GetLocalIP()
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus == OperationalStatus.Up &&
                    adapter.Supports(NetworkInterfaceComponent.IPv4) &&
                    adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    IPInterfaceProperties props = adapter.GetIPProperties();

                    foreach (var address in props.UnicastAddresses)
                    {
                        if (address.Address.AddressFamily == AddressFamily.InterNetwork)
                            return address.Address;
                    }
                }
            }

            return IPAddress.None;
        }

        public static IPAddress ResolveName(string Host)
        {
            if (IsValidIP(Host))
            {
                IPAddress ip = IPAddress.None;
                IPAddress.TryParse(Host, out ip);

                return ip;
            }
            else
            {
                IPAddress[] ips = Dns.GetHostAddresses(Host);
                if (ips.Length > 0)
                    return ips[ips.Length - 1];
            }

            return IPAddress.None;
        }
    }
}
