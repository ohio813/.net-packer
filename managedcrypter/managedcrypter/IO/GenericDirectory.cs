using System;
using System.IO;

namespace managedcrypter.IO
{
    class GenericDirectory
    {
        public string DirectoryPath { get; private set; }
        public FileTraverser Workspace { get; private set; }
        public SourceTraverser Source { get; private set; }

        public GenericDirectory(string rootDirectory)
        {
            DirectoryPath = rootDirectory;
            Workspace = new FileTraverser();
            Source = new SourceTraverser(rootDirectory);
        }

        public void CreateWorkspaceDirectory()
        {
            string folderID = Guid.NewGuid().ToString();
            string writePath = Path.Combine(DirectoryPath, folderID);
            Workspace = new FileTraverser(writePath);
        }
    }
}
