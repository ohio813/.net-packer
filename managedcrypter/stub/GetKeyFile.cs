using System.IO;
using System.Reflection;

namespace stub
{
    class KeyFile
    {
        static string key_name = "[KEY_LIB_RESOURCE_NAME]";

        public static byte[] GetKeyFile(Assembly asm)
        {
            byte[] b = null;

            using (Stream stream = asm.GetManifestResourceStream(key_name))
            {
                using (BinaryReader rdr = new BinaryReader(stream))
                    b = rdr.ReadBytes((int)stream.Length);
            }

            return b;
        }
    }
}
