using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;

namespace managedcrypter.USG
{
    class MethodGen
    {
        public MethodGen()
        {
            AvailableTypes = new Dictionary<Type, string>();
            setAvailableTypes();
        }

        public string RandMethod()
        {
            return string.Concat(constructMethodHead(), constructMethodBody());
        }

        string constructMethodBody()
        {
            string begin = "{";
            string end = "}";

            int mtd_lines = Rand.Next(1,20);
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(begin);

            for (int i = 0; i < mtd_lines; i++)
            {
                sb.AppendLine(buildMethodLine());
            }

            sb.AppendLine(end);
            return sb.ToString();
        }



        string buildMethodLine()
        {
            int mtdCase = new Random(Guid.NewGuid().GetHashCode()).Next(1, 2); //exclusive i know :)
            string ret = string.Empty;

            switch (mtdCase)
            {
                case 1:
                    {

                    __startover:
                        // {type} {name} = new {type} {contructor args}
                        Type t = selectRandomTypeType();
                        string type = t.FullName;
                        string name = Utils.GenerateRandomString(3, 8);
                        string eq = "= new";
                        string open = "(";
                        string close = ");";
                        List<string> param_str = new List<string>();

                        ConstructorInfo ctor = t.GetConstructors()[Rand.Next(0, t.GetConstructors().Length)];
                        ParameterInfo[] pInfo = ctor.GetParameters();

                        string s_param = string.Empty;

                        if (pInfo.Length > 0)
                        {
                            foreach (ParameterInfo param in pInfo)
                            {
                                Type param_t = param.ParameterType;

                                if (param_t == typeof(string))
                                {
                                    param_str.Add('"' + Utils.GenerateRandomString(3, 18) + '"');
                                }
                                else if (param_t == typeof(int))
                                {
                                    param_str.Add(Rand.Next().ToString());
                                }
                                else if (param_t == typeof(short))
                                {
                                    param_str.Add(((short)Rand.Next(short.MinValue, short.MaxValue)).ToString());
                                }
                                else if (param_t == typeof(long))
                                {
                                    param_str.Add(Rand.Next().ToString());
                                }
                                else if (param_t == typeof(object))
                                {
                                    param_str.Add(Rand.Next().ToString());
                                }
                                else
                                {
                                    Type pt = param.ParameterType;
                                    ConstructorInfo ctor2 = pt.GetConstructors().FirstOrDefault();
                                    if (pt.FullName.Contains("+"))
                                        goto __startover;
                                    if (null == ctor2 || ctor2.GetParameters().Length > 0)
                                    {
                                        goto __startover;
                                    }
                                    else
                                    {
                                        param_str.Add("new " + pt.FullName + "()");
                                    }

                                }
                            }

                            for (int i = 0; i < param_str.Count; i++)
                                s_param += param_str[i] + ", ";

                            s_param = s_param.TrimEnd(',', ' ');
                        }

                        ret = string.Join(" ",
                           new string[] {
                            type,
                            name,
                            eq,
                            type,
                            open,
                            s_param,
                            close
                           });
                    }
                    break;
                case 2:
                    {   // {type} {name} = {type2}.{method}({params});
                    __startover:
                        Type t = selectRandomTypeType();
                        string type1 = t.FullName;
                        string name = Utils.GenerateRandomString(6, 10);
                        string eq = "=";
                        MethodInfo mtd = getRandomMethodWithReturnType(t);

                        if (null == mtd)
                            goto __startover;

                        string t2 = mtd.DeclaringType.FullName;
                        string prd = ".";
                        string mtd_name = mtd.Name;

                        ParameterInfo[] pInfo = mtd.GetParameters();
                        string s_param = string.Empty;
                        List<string> param_str = new List<string>();

                        if (pInfo.Length > 0)
                        {
                            foreach (ParameterInfo param in pInfo)
                            {
                                Type param_t = param.ParameterType;

                                if (param_t == typeof(string))
                                {
                                    param_str.Add('"' + Utils.GenerateRandomString(3, 18) + '"');
                                }
                                else if (param_t == typeof(int))
                                {
                                    param_str.Add(Rand.Next().ToString());
                                }
                                else if (param_t == typeof(short))
                                {
                                    param_str.Add(((short)Rand.Next(short.MinValue, short.MaxValue)).ToString());
                                }
                                else if (param_t == typeof(long))
                                {
                                    param_str.Add(Rand.Next().ToString());
                                }
                                else if (param_t == typeof(object))
                                {
                                    param_str.Add(Rand.Next().ToString());
                                }
                                else
                                {
                                    Type pt = param.ParameterType;
                                    ConstructorInfo ctor2 = pt.GetConstructors().FirstOrDefault();
                                    if (pt.FullName.Contains("+"))
                                        goto __startover;

                                    if (null == ctor2 || ctor2.GetParameters().Length > 0)
                                    {
                                        goto __startover;
                                    }
                                    else
                                    {
                                        param_str.Add("new " + pt.FullName + "()");
                                    }
                                }
                            }

                            for (int i = 0; i < param_str.Count; i++)
                                s_param += param_str[i] + ", ";

                            s_param = s_param.TrimEnd(',', ' ');
                        }

                        ret += string.Join(" ",
                            new string[]
                            {
                                type1,
                                name,
                                eq
                            });

                        ret += " " + t2 + prd + mtd_name + "(" + s_param + ");";
                    }
                    break;
                case 3:
                    {

                    }
                    break;
            }

            return ret;
        }

        MethodInfo getRandomMethodWithReturnType(Type T)
        {
            MethodInfo mi = null;
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

            foreach (var asm in asms2)
            {
                foreach (var type in asm.GetExportedTypes())
                {
                    if (type.IsVisible && type.IsPublic && type.IsClass && !type.IsGenericType && !type.IsAbstract && !type.IsInterface)
                    {
                        foreach (var mtd in type.GetMethods())
                        {
                            if (mtd.IsStatic && mtd.IsPublic && !mtd.IsSpecialName && mtd.ReturnType.FullName == T.FullName && !T.FullName.Contains("+") && !mtd.Name.Contains("+"))
                                return mtd;
                        }
                    }
                }
            }
            return mi;
        }


        string constructMethodHead()
        {
            // {identifier} {return type} {methodname} {parameters}
            string[] a = { "public", "private", "static", "" };
            string ret_type = "void";// selectRandomTypeName();
            string mtd_name = Utils.GenerateRandomString(3, 8);
            string mtd_params = buildParams();
            string ret = string.Join(" ",
                new string[] {
                a[Rand.Next(0, a.Length)],
                ret_type,
                mtd_name,
                mtd_params
                });
            return ret;
        }

        string buildParams()
        {
            int numParams = Rand.Next(0, 6);

            if (numParams == 0)
                return "()";

            StringBuilder sb = new StringBuilder();
            sb.Append("( ");

            for (int i = 0; i < numParams - 1; i++)
                sb.AppendFormat("{0} {1}, ", selectRandomTypeName(), Utils.GenerateRandomString(3, 8));

            sb.AppendFormat("{0} {1}", selectRandomTypeName(), Utils.GenerateRandomString(3, 8));

            sb.Append(")");
            return sb.ToString();
        }

        string selectRandomTypeName()
        {
            return AvailableTypes.Values.OrderBy(RR => Rand.Next()).Take(1).FirstOrDefault();
        }

        Type selectRandomTypeType()
        {
            return AvailableTypes.Keys.OrderBy(RR => Rand.Next()).Take(1).FirstOrDefault();
        }

        private Random Rand = new Random(Guid.NewGuid().GetHashCode());

        private Dictionary<Type, string> AvailableTypes;

        void setAvailableTypes()
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

            foreach (var asm in asms2)
            {
                foreach (var type in asm.GetExportedTypes())
                {
                    if (type.IsVisible && type.IsPublic && type.IsClass && !type.IsGenericType && !type.IsAbstract && !type.IsInterface && !type.FullName.Contains("+") && !type.IsSpecialName && type.GetConstructors().Length > 0)
                    {
                        AvailableTypes.Add(type, type.FullName);
                    }
                }
            }
        }

    }
}
