using System.Collections.Generic;

namespace managedcrypter.Compiler
{
    class CompilerInfo
    {
        public CompilerInfo()
        {
            EmbeddedResources = new List<string>();
            ExCompilerOptions = new List<string>();
            ReferencedAssemblies = new List<string>();
            IconPath = string.Empty;
            OutputDestination = string.Empty;
            GenerateExe = false;
            GenerateLibrary = false;
        }

        public bool GenerateLibrary { get; set; }
        public bool GenerateExe { get; set; }
        public List<string> EmbeddedResources { get; set; }
        public List<string> ExCompilerOptions { get; set; }
        public List<string> ReferencedAssemblies { get; set; }
        public string IconPath { get; set; }
        public string OutputDestination { get; set; }
    }

}
