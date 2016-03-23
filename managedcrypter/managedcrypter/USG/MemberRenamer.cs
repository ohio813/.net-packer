using Mono.Cecil;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace managedcrypter.USG
{
    public class MemberRenamer
    {
        public static void RenameMembers(string LibraryPath, string StubClassPath)
        {
            AssemblyDefinition assemblyDef = AssemblyDefinition.ReadAssembly(LibraryPath);

            string className = GenSpecialStr();
            string methodName = GenSpecialStr();

            TypeDefinition tDef = assemblyDef.MainModule.GetType("class1");
            MethodDefinition mDef = tDef.Methods.Where(Mtd => Mtd.Name == "method1").First();

            tDef.Name = className;
            mDef.Name = methodName;

            assemblyDef.Write(LibraryPath);

            string stubFile = File.ReadAllText(StubClassPath);
            stubFile = stubFile.Replace("class1", className);
            stubFile = stubFile.Replace("method1", methodName);

            File.WriteAllText(StubClassPath, stubFile);
        }

        private static Random Rand = new Random();
        private static string GenSpecialStr()
        {
            byte[] lpBuffer = new byte[32];
            Rand.NextBytes(lpBuffer);
            return new UnicodeEncoding().GetString(lpBuffer);
        }
    }
}
