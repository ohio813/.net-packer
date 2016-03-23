using managedcrypter.IO;
using Microsoft.CSharp;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;

namespace managedcrypter.Compiler
{
    class GenericCompiler : IDisposable
    {
        CSharpCodeProvider csharpProvider;
        CompilerParameters cmpParams;

        public GenericCompiler()
        {
            var pOptions = new Dictionary<string, string>();
            pOptions.Add("CompilerVersion", "v2.0");

            csharpProvider = new CSharpCodeProvider(pOptions);
            cmpParams = new CompilerParameters();

            setDefaultParameters();
        }

        void setDefaultParameters()
        {
            cmpParams.ReferencedAssemblies.Add("System.dll");

            cmpParams.CompilerOptions = "/optimize+ /debug- /platform:x86";

            cmpParams.GenerateInMemory = false;
            cmpParams.IncludeDebugInformation = false;

            /* set non-default location for compiling the source */
            cmpParams.TempFiles = new TempFileCollection(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), false);

            cmpParams.TreatWarningsAsErrors = false;
        }

        public bool CompileSource(GenericDirectory Directory, CompilerInfo cInfo)
        {
            foreach (string asmReference in cInfo.ReferencedAssemblies)
                cmpParams.ReferencedAssemblies.Add(asmReference);

            if (cInfo.EmbeddedResources.Count > 0)
                cmpParams.EmbeddedResources.AddRange(cInfo.EmbeddedResources.ToArray());

            if (cInfo.GenerateExe)
            {
                cmpParams.CompilerOptions += string.Concat(" ", "/target:winexe", " ");
                cmpParams.GenerateExecutable = true;
            }

            if (cInfo.GenerateLibrary)
            {
                cmpParams.CompilerOptions += string.Concat(" ", "/target:library", " ");
                cmpParams.GenerateExecutable = false;
            }

            if (cInfo.ExCompilerOptions.Count > 0)
                foreach (string cmpSwitch in cInfo.ExCompilerOptions)
                    cmpParams.CompilerOptions += string.Concat(" ", cmpSwitch, " ");

            if (!string.IsNullOrEmpty(cInfo.IconPath))
                cmpParams.CompilerOptions += string.Concat(" \"/win32icon:", cInfo.IconPath, "\" ");

            cmpParams.OutputAssembly = cInfo.OutputDestination;

            CompilerResults cmpResults = csharpProvider.CompileAssemblyFromFile(
                cmpParams,
                new List<string>(Directory.Source.Files.Values).ToArray());

#if DEBUG
            if (cmpResults.Errors.HasErrors)
                foreach (var err in cmpResults.Errors)
                    Console.WriteLine(err.ToString());
#endif

            if (cmpResults.NativeCompilerReturnValue != 0)
                return false;

            return true;
        }

        void IDisposable.Dispose()
        {
            csharpProvider.Dispose();
        }
    }
}
