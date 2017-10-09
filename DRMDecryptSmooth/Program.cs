/*

Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT License.

 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace DRMDecryptSmooth
{
    // This application demonstrates how to use bento4 to decrypt a Smooth Streaming PlayReady asset.
     
    class Program
    {
        // Location of mp4decrypt from Bento4
        const string mp4decrypt = @"C:\Temp\Bento4-SDK-1-5-1-620.x86-microsoft-win32-vs2010\bin\mp4decrypt.exe";

        static void Main(string[] args)
        {
            // MANTATORY: Please insert here the key seed in base64 format. Example : "XVBovsmzhP9gRIZxWfFta3VVRPzVEWmJsazEJ46I"
            string keySeed = "";

            // MANTATORY: Please insert here the key id in guid format. Example : "8d080fae-2b52-4427-9f2c-f2ea93141b45"
            string keyId = "";

            // Folder where is the asset to process
            string inputAsset = @"C:\source";

            // Folder where the decrypted asset will be copied (folder must exist)
            string outputAsset = inputAsset + @"\decrypted";
            Directory.CreateDirectory(outputAsset);

            // let's calculate the key
            string key = ByteArrayToHexString(GeneratePlayReadyContentKey(Convert.FromBase64String(keySeed), new Guid(keyId)));

            var files = Directory.GetFiles(inputAsset);

            foreach (var filePath in files)
            {
                string ext = Path.GetExtension(filePath).ToLower();

                if (ext == ".isma" || ext == ".ismv")
                {
                    // we need to decrypt the PIFF file
                    string keyArg = " --key {0}:{1}";
                    string arguments = "--show-progress";
                    var piffFilesCount = files.Where(f => Path.GetExtension(f).ToLower() == ".isma" || Path.GetExtension(f).ToLower() == ".ismv").Count();
                    for (int i = 1; i <= piffFilesCount; i++)
                    {
                        arguments += string.Format(keyArg, i, key);
                    }
                    arguments += " " + filePath + " " + outputAsset + @"\" + Path.GetFileName(filePath);
                    Console.WriteLine($"Decrypting {Path.GetFileName(filePath)}");
                    ExecuteCommandSync(mp4decrypt + " " + arguments);
                }
                else if (ext == ".ismc")
                {
                    // let remove the Playready part in the manifest
                    var manifest = XDocument.Load(filePath);
                    var smoothmedia = manifest.Element("SmoothStreamingMedia");
                    var videotrack = smoothmedia.Element("Protection");
                    videotrack.Remove();
                    Console.WriteLine($"Modifying {Path.GetFileName(filePath)}");
                    manifest.Save(outputAsset + @"\" + Path.GetFileName(filePath));
                }
                else
                {
                    File.Copy(filePath, outputAsset + @"\" + Path.GetFileName(filePath), true);
                }
            }
        }

        static public void ExecuteCommandSync(object command)
        {
            try
            {
                // create the ProcessStartInfo using "cmd" as the program to be run,
                // and "/c " as the parameters.
                // Incidentally, /c tells cmd that we want it to execute the command that follows,
                // and then exit.
                System.Diagnostics.ProcessStartInfo procStartInfo =
                    new System.Diagnostics.ProcessStartInfo("cmd", "/c " + command);

                // The following commands are needed to redirect the standard output.
                // This means that it will be redirected to the Process.StandardOutput StreamReader.
                procStartInfo.RedirectStandardOutput = true;
                procStartInfo.UseShellExecute = false;
                // Do not create the black window.
                procStartInfo.CreateNoWindow = true;
                // Now we create a process, assign its ProcessStartInfo and start it
                System.Diagnostics.Process proc = new System.Diagnostics.Process();
                proc.StartInfo = procStartInfo;
                proc.Start();
                // Get the output into a string
                string result = proc.StandardOutput.ReadToEnd();
                // Display the command output.
                Console.WriteLine(result);
            }
            catch ()
            {
                // Log the exception
            }
        }

        public static byte[] GeneratePlayReadyContentKey(byte[] keySeed, Guid keyId)
        {
            const int DRM_AES_KEYSIZE_128 = 16;
            byte[] contentKey = new byte[DRM_AES_KEYSIZE_128];
            //
            // Truncate the key seed to 30 bytes, key seed must be at least 30 bytes long.
            //
            byte[] truncatedKeySeed = new byte[30];
            Array.Copy(keySeed, truncatedKeySeed, truncatedKeySeed.Length);
            //
            // Get the keyId as a byte array
            //
            byte[] keyIdAsBytes = keyId.ToByteArray();
            //
            // Create sha_A_Output buffer. It is the SHA of the truncatedKeySeed and the keyIdAsBytes
            //
            SHA256Managed sha_A = new SHA256Managed();
            sha_A.TransformBlock(truncatedKeySeed, 0, truncatedKeySeed.Length, truncatedKeySeed, 0);
            sha_A.TransformFinalBlock(keyIdAsBytes, 0, keyIdAsBytes.Length);
            byte[] sha_A_Output = sha_A.Hash;
            //
            // Create sha_B_Output buffer. It is the SHA of the truncatedKeySeed, the keyIdAsBytes, and
            // the truncatedKeySeed again.
            //
            SHA256Managed sha_B = new SHA256Managed();
            sha_B.TransformBlock(truncatedKeySeed, 0, truncatedKeySeed.Length, truncatedKeySeed, 0);
            sha_B.TransformBlock(keyIdAsBytes, 0, keyIdAsBytes.Length, keyIdAsBytes, 0);
            sha_B.TransformFinalBlock(truncatedKeySeed, 0, truncatedKeySeed.Length);
            byte[] sha_B_Output = sha_B.Hash;
            //
            // Create sha_C_Output buffer. It is the SHA of the truncatedKeySeed, the keyIdAsBytes,
            // the truncatedKeySeed again, and the keyIdAsBytes again.
            //
            SHA256Managed sha_C = new SHA256Managed();
            sha_C.TransformBlock(truncatedKeySeed, 0, truncatedKeySeed.Length, truncatedKeySeed, 0);
            sha_C.TransformBlock(keyIdAsBytes, 0, keyIdAsBytes.Length, keyIdAsBytes, 0);
            sha_C.TransformBlock(truncatedKeySeed, 0, truncatedKeySeed.Length, truncatedKeySeed, 0);
            sha_C.TransformFinalBlock(keyIdAsBytes, 0, keyIdAsBytes.Length);
            byte[] sha_C_Output = sha_C.Hash;
            for (int i = 0; i < DRM_AES_KEYSIZE_128; i++)
            {
                contentKey[i] = Convert.ToByte(sha_A_Output[i] ^ sha_A_Output[i + DRM_AES_KEYSIZE_128]
                ^ sha_B_Output[i] ^ sha_B_Output[i + DRM_AES_KEYSIZE_128]
                ^ sha_C_Output[i] ^ sha_C_Output[i + DRM_AES_KEYSIZE_128]);
            }
            return contentKey;
        }

        public static string ByteArrayToHexString(byte[] bytes)
        {
            return string.Join(string.Empty, Array.ConvertAll(bytes, b => b.ToString("X2")));
        }
    }
}
