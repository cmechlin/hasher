using System;
using System.IO;
using System.Reflection;
using System.Linq;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Hasher
{
    class Program
    {
        static int Main(string[] args)
        {

            if(args.Length == 0)
            {   
                Help();
                LogError("Invalid arguments");
                return 1;
            }
            if(args[0].Length == 2){
                switch (args[0])
                {
                    case "-h":
                        Help();
                        break;
                    default:
                        Help();
                        LogError("Invalid arguments");
                        return 1;
                }
            }
            else
            {
                if (!File.Exists(args[0]))
                {
                    Help();
                    LogError("File " + args[0] + " is not valid");
                    return 1;                 
                }
                Hash(args[0]);
            }

            Console.WriteLine("\npress any key to exit...");
            Console.ReadKey();
            return 0;
        }

        static void Help()
        {
            Console.WriteLine("****************************************************************************");
            Console.WriteLine(Process.GetCurrentProcess().ProcessName + " v" + Assembly.GetEntryAssembly().GetName().Version + " Help");
            Console.WriteLine("C. Mechling, 2021");
            Console.WriteLine("****************************************************************************");
            Console.WriteLine("usage: " + Process.GetCurrentProcess().ProcessName + ".exe <file to be hashed path>");
            Console.WriteLine(" ");
            Console.WriteLine("  options:");
            Console.WriteLine("    -h\t This Help.");

        }

        static void Hash(string path)
        {
            try
            {
                FileStream fs = File.OpenRead(path);
                string sha1 = BitConverter.ToString(SHA1.Create().ComputeHash(fs)).Replace("-", "");
                string md5 = BitConverter.ToString(MD5.Create().ComputeHash(fs)).Replace("-", "");
                Console.WriteLine("Hashing " + path + "...");
                Console.WriteLine("SHA-1: " + sha1);
                Console.WriteLine("MD5: " + md5);
                WriteLog(path, sha1, md5);
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("The file or directory cannot be found.");
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("The file or directory cannot be found.");
            }
            catch (DriveNotFoundException)
            {
                Console.WriteLine("The drive specified in 'path' is invalid.");
            }
            catch (PathTooLongException)
            {
                Console.WriteLine("'path' exceeds the maxium supported path length.");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("You do not have permission to create this file.");
            }
            catch (IOException e) when ((e.HResult & 0x0000FFFF) == 32)
            {
                Console.WriteLine("File " + path + " is open by another application.\n\nPlease close the file and try again.");
            }
            catch (IOException e) when ((e.HResult & 0x0000FFFF) == 80)
            {
                Console.WriteLine("The file already exists.");
            }
            catch (IOException e)
            {
                Console.WriteLine($"An exception occurred:\nError code: " +
                                  $"{e.HResult & 0x0000FFFF}\nMessage: {e.Message}");
            }         
        }

        static void LogError(string msg)
        {
            Console.WriteLine("\n" + msg + "!!!");
            Console.WriteLine("\npress any key to exit...");
            Console.ReadKey();
        }

        static void WriteLog(string path, string sha1, string md5)
        {
            //"Current Date, Current Time, Path, File Name, Creation DateTime, Modified DateTime, MD5 Hash, SHA-1 Hash"
            string d = DateTime.Now.ToString("MM/dd/yy");
            string t = DateTime.Now.ToString("hh:mm:ss");
            string f = Path.GetFileName(path);
            string[] Separator = { "PLC" };
            string logFilename = f.Split(Separator, StringSplitOptions.None).First() + "log";
            string p = Path.GetDirectoryName(path);
            string fcreated = File.GetCreationTime(path).ToString();
            string fmodified = File.GetLastWriteTime(path).ToString();
            string s = String.Format("{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}\n", d, t, p, f, fcreated, fmodified, md5, sha1);
            path = @Path.Combine(p, Path.ChangeExtension(logFilename, ".csv"));
            if (!File.Exists(path))
            {
                File.AppendAllText(path, "Current Date, Current Time, Path, File Name, Creation DateTime, Modified DateTime, MD5 Hash, SHA-1 Hash\n");
            }
            File.AppendAllText(path, s);
        }
    }
}
