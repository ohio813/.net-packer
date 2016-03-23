using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Vestris.ResourceLib;

namespace managedcrypter.USG
{
    public class ResourceGen
    {
        private static Random R = new Random(Guid.NewGuid().GetHashCode());

        public static void CreateHeurIconSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_GROUP_ICON].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_GROUP_ICON])
                                {
                                    rc.SaveTo(FilePath);
                                }

                                //var rc = ri[Kernel32.ResourceTypes.RT_GROUP_ICON].FirstOrDefault();
                                //rc.SaveTo(FilePath);
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurMenuSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_MENU].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_MENU])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurDialogSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {

                            if (ri[Kernel32.ResourceTypes.RT_DIALOG].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_DIALOG])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurAcceleratorSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_ACCELERATOR].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_ACCELERATOR])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurCursorSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_CURSOR].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_CURSOR])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurStringSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_STRING].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_STRING])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurBitmapSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {

                            if (ri[Kernel32.ResourceTypes.RT_BITMAP].Count > 0)
                            {
                                int j = 0;
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_BITMAP])
                                {
                                    if (j < 12)
                                        rc.SaveTo(FilePath);
                                    j++;
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {

            }
        }
    }
}
