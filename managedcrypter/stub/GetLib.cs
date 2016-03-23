using System;
using System.IO;
using System.Reflection;

namespace stub
{
    class GetLib
    {
        static string lib_name = "[LIB_RESOURCE_NAME]";

        public static byte[] GetExe(Assembly asm)
        {
            byte[] b = null;

            using (Stream stream = asm.GetManifestResourceStream(lib_name))
            {
                using (StreamReader rdr = new StreamReader(stream))
                {
                    b = Convert.FromBase64String(rdr.ReadToEnd());
                }
            }

            return b;
        }
    }
}
