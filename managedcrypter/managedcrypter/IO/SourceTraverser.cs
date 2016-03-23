using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace managedcrypter.IO
{
    class SourceTraverser
    {
        private string Root;
        public Dictionary<string, string> Files;

        public SourceTraverser(string rootDirectory)
        {
            Root = rootDirectory;
            Files = new Dictionary<string, string>();

            SetSourceFiles();
            RelocateSource();
            SetSourceFiles();
        }

        void RelocateSource()
        {
            string updatedRoot = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Root = updatedRoot;

            Directory.CreateDirectory(updatedRoot);

            foreach (var srcEntry in Files)
            {
                File.Copy(srcEntry.Value,
                    Path.Combine(updatedRoot,
                    string.Concat(srcEntry.Key, ".cs")));
            }
        }

        void SetSourceFiles()
        {
            Files.Clear();

            var csFiles = Directory.GetFiles(Root).Where(
              f => Path.GetExtension(f) == ".cs");
            foreach (var csFile in csFiles)
                Files.Add(Path.GetFileNameWithoutExtension(csFile), csFile);
        }

        public void Clean()
        {
            Directory.Delete(Root, true);
        }
    }
}
