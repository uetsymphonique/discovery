using System;
using System.DirectoryServices;
using System.IO;
using System.Management;
using System.Security.Principal;
using Microsoft.Win32;

namespace WNetHelper
{
    static class Diag
    {
        public static bool Verbose = false;
        public static void Log(string section, string msg)
        {
            if (Verbose)
                Console.WriteLine("  [v:" + section + "] " + msg);
        }
    }

    static class SystemProfile
    {
        public static void Run()
        {
            Console.WriteLine("[PROFILE]");
            try
            {
                Diag.Log("prof", "reading environment properties");
                Console.WriteLine("  Hostname     : " + Environment.MachineName);
                Console.WriteLine("  Domain       : " + Environment.UserDomainName);
                Console.WriteLine("  OS Version   : " + Environment.OSVersion);
                Console.WriteLine("  Processors   : " + Environment.ProcessorCount);
                Console.WriteLine("  64-bit OS    : " + Environment.Is64BitOperatingSystem);

                Diag.Log("prof", "querying WMI for OS details");
                using (var searcher = new ManagementObjectSearcher("SELECT Caption, BuildNumber FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        Console.WriteLine("  OS Caption   : " + obj["Caption"]);
                        Console.WriteLine("  OS Build     : " + obj["BuildNumber"]);
                        Diag.Log("prof", "WMI returned Caption='" + obj["Caption"] + "' Build='" + obj["BuildNumber"] + "'");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  Error: " + ex.Message);
                Diag.Log("prof", "exception: " + ex.ToString());
            }
            Console.WriteLine();
        }
    }

    static class SessionInfo
    {
        public static void Run()
        {
            Console.WriteLine("[SESSION]");
            try
            {
                Diag.Log("sess", "reading current identity");
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    Console.WriteLine("  User         : " + identity.Name);
                    Console.WriteLine("  Auth Type    : " + identity.AuthenticationType);
                    Diag.Log("sess", "identity=" + identity.Name + " auth=" + identity.AuthenticationType);

                    var principal = new WindowsPrincipal(identity);
                    bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                    Console.WriteLine("  Is Admin     : " + isAdmin);
                    Diag.Log("sess", "admin role check=" + isAdmin);

                    Console.WriteLine("  Groups:");
                    if (identity.Groups != null)
                    {
                        Diag.Log("sess", "group count=" + identity.Groups.Count);
                        foreach (var g in identity.Groups)
                        {
                            try
                            {
                                string name = g.Translate(typeof(NTAccount)).Value;
                                Console.WriteLine("    " + name);
                            }
                            catch
                            {
                                Console.WriteLine("    " + g.Value);
                                Diag.Log("sess", "failed to translate SID " + g.Value);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  Error: " + ex.Message);
                Diag.Log("sess", "exception: " + ex.ToString());
            }
            Console.WriteLine();
        }
    }

    static class ProcessCounter
    {
        public static void Run()
        {
            Console.WriteLine("[TASKS]");
            try
            {
                Diag.Log("task", "collecting performance entries");
                var entries = PerfCounter.Collect();
                Diag.Log("task", "received " + entries.Count + " entries");
                Console.WriteLine(String.Format("  {0,-8} {1}", "PID", "Name"));
                Console.WriteLine(String.Format("  {0,-8} {1}", "---", "----"));
                foreach (var p in entries)
                {
                    Console.WriteLine(String.Format("  {0,-8} {1}", p[0], p[1]));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  Error: " + ex.Message);
                Diag.Log("task", "exception: " + ex.ToString());
            }
            Console.WriteLine();
        }
    }

    static class ServiceRegistry
    {
        public static void Run()
        {
            Console.WriteLine("[SERVICES]");
            try
            {
                Diag.Log("svc", "opening registry key");
                using (RegistryKey services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                {
                    if (services == null)
                    {
                        Console.WriteLine("  Unable to open registry key");
                        Diag.Log("svc", "OpenSubKey returned null");
                        return;
                    }

                    string[] names = services.GetSubKeyNames();
                    Diag.Log("svc", "found " + names.Length + " subkeys");

                    Console.WriteLine(String.Format("  {0,-40} {1,-6} {2}", "DisplayName", "Start", "ImagePath"));
                    Console.WriteLine(String.Format("  {0,-40} {1,-6} {2}", "---", "---", "---"));

                    int count = 0;
                    foreach (string name in names)
                    {
                        try
                        {
                            using (RegistryKey svc = services.OpenSubKey(name))
                            {
                                if (svc == null) continue;

                                object typeObj = svc.GetValue("Type");
                                if (typeObj == null) continue;
                                int type = (int)typeObj;
                                if ((type & 0x30) == 0) continue;

                                object startObj = svc.GetValue("Start");
                                string start = startObj != null ? startObj.ToString() : "?";

                                object dispObj = svc.GetValue("DisplayName");
                                string display = dispObj != null ? dispObj.ToString() : name;

                                object pathObj = svc.GetValue("ImagePath");
                                string path = pathObj != null ? pathObj.ToString() : "";

                                if (display.Length > 38) display = display.Substring(0, 38) + "~";
                                if (path.Length > 60) path = path.Substring(0, 60) + "~";

                                Console.WriteLine(String.Format("  {0,-40} {1,-6} {2}", display, start, path));
                                count++;
                            }
                        }
                        catch
                        {
                            Diag.Log("svc", "failed to read subkey '" + name + "'");
                        }
                    }
                    Diag.Log("svc", "listed " + count + " matching entries out of " + names.Length + " total");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  Error: " + ex.Message);
                Diag.Log("svc", "exception: " + ex.ToString());
            }
            Console.WriteLine();
        }
    }

    static class GroupMembership
    {
        public static void Run()
        {
            Console.WriteLine("[MEMBERS]");
            try
            {
                string machine = Environment.MachineName;
                Diag.Log("grp", "binding to local directory for " + machine);
                using (var computer = new DirectoryEntry("WinNT://" + machine + ",computer"))
                {
                    int groupCount = 0;
                    foreach (DirectoryEntry child in computer.Children)
                    {
                        if (!string.Equals(child.SchemaClassName, "Group", StringComparison.OrdinalIgnoreCase))
                            continue;

                        Console.WriteLine("  " + child.Name + ":");
                        groupCount++;
                        try
                        {
                            object members = child.Invoke("Members");
                            int memberCount = 0;
                            foreach (object member in (System.Collections.IEnumerable)members)
                            {
                                using (var memberEntry = new DirectoryEntry(member))
                                {
                                    Console.WriteLine("    " + memberEntry.Name);
                                    memberCount++;
                                }
                            }
                            Diag.Log("grp", "group '" + child.Name + "' has " + memberCount + " members");
                        }
                        catch
                        {
                            Console.WriteLine("    (access denied)");
                            Diag.Log("grp", "access denied reading members of '" + child.Name + "'");
                        }
                        child.Dispose();
                    }
                    Diag.Log("grp", "enumerated " + groupCount + " groups");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  Error: " + ex.Message);
                Diag.Log("grp", "exception: " + ex.ToString());
            }
            Console.WriteLine();
        }
    }

    static class PathEnumerator
    {
        public static void Run()
        {
            Console.WriteLine("[FILES]");
            try
            {
                string[] paths = new string[]
                {
                    @"C:\Users",
                    @"C:\Windows\Temp",
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };

                foreach (string dir in paths)
                {
                    if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
                    {
                        Diag.Log("file", "skipping '" + (dir ?? "(null)") + "' (not found)");
                        continue;
                    }

                    Console.WriteLine("  " + dir + ":");
                    try
                    {
                        string[] entries = Directory.GetFileSystemEntries(dir);
                        Diag.Log("file", "'" + dir + "' contains " + entries.Length + " entries");
                        foreach (string entry in entries)
                        {
                            Console.WriteLine("    " + Path.GetFileName(entry));
                        }
                    }
                    catch
                    {
                        Console.WriteLine("    (access denied)");
                        Diag.Log("file", "access denied on '" + dir + "'");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  Error: " + ex.Message);
                Diag.Log("file", "exception: " + ex.ToString());
            }
            Console.WriteLine();
        }
    }
}
