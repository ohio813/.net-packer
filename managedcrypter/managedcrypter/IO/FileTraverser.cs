using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace managedcrypter.IO
{
    public class FileTraverser
    {
        /// <summary>
        /// Parent Directory Path
        /// </summary>
        public string Parent;

        /// <summary>
        /// Key = ID, Value = Path
        /// </summary>
        public Dictionary<string, string> Children;

        /// <summary>
        /// Key = Child ID, Value = Anonymous Value
        /// </summary>
        public Dictionary<string, string> AnonymousChildren;

        public FileTraverser()
        {
            Parent = string.Empty;
            Children = new Dictionary<string, string>();
            AnonymousChildren = new Dictionary<string, string>();
        }

        public FileTraverser(string _Parent)
        {
            Parent = _Parent;
            Children = new Dictionary<string, string>();
            AnonymousChildren = new Dictionary<string, string>();

            if (!Directory.Exists(Parent))
                Directory.CreateDirectory(Parent);
        }

        public void AnonymizeChildren()
        {
            foreach (string child in Children.Keys)
                AnonymousChildren.Add(child, Utils.GenerateRandomString(16));
        }

        public void AddChild(string childName)
        {
            Children.Add(childName, string.Concat(Parent, "\\", childName));
        }

        public void RemoveChild(string childName)
        {
            Children.Remove(childName);
        }

        public void Write(string childName, byte[] childData)
        {
            if (File.Exists(Children[childName]))
                File.Delete(Children[childName]);

            File.WriteAllBytes(Children[childName], childData);
        }

        public void WriteAnonymous(string anonymousName, byte[] anonymousData)
        {
            string deAnonymizedPath = Children[AnonymousChildren.FirstOrDefault(C => C.Value == anonymousName).Key];

            if (File.Exists(deAnonymizedPath))
                File.Delete(deAnonymizedPath);

            string anonymousWritePath = string.Concat(
                Path.GetDirectoryName(deAnonymizedPath),
                "\\",
                anonymousName);

            if (File.Exists(anonymousWritePath))
                File.Delete(anonymousWritePath);

            File.WriteAllBytes(anonymousWritePath, anonymousData);
        }

        public string GetAnonymousPath(string anonymousName)
        {
            return Path.Combine(Parent, anonymousName);
        }

        public void Clear()
        {
            Children.Clear();
            Directory.Delete(Parent, true);
            Parent = string.Empty;
        }
    }
}
