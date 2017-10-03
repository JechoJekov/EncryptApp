using EncryptApp.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;

namespace EncryptApp.Loader
{
    /// <summary>
    /// Provides a method to load an encrypted application.
    /// </summary>
    static class ApplicationLoader
    {
        /// <summary>
        /// Loads the current application.
        /// </summary>
        /// <param name="password"></param>
        /// <exception cref="ApplicationLoaderException">An error occurred during the decryption or while starting the application.</exception>
        public static void Load(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            var exePath = Assembly.GetExecutingAssembly().Location;
            var mainAssemblyPath = Path.ChangeExtension(exePath, SharedConstants.EncryptedExeFileExtension);

            if (false == File.Exists(mainAssemblyPath))
            {
                throw new ApplicationLoaderException("The main assembly was not found.");
            }

            #region Decrypt files

            byte[] mainAssembly;
            try
            {
                mainAssembly = DecryptFile(mainAssemblyPath, password);
            }
            catch (Exception exc)
            {
                throw new ApplicationLoaderException("Error loading the main assembly.", exc);
            }

            var applicationPath = Path.GetDirectoryName(exePath);

            var libFileList = Directory.GetFiles(applicationPath, "*" + SharedConstants.EncryptedLibFileExtension);

            var assemblyDict = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);

            var mainAssemblyName = Path.GetFileNameWithoutExtension(exePath);

            assemblyDict.Add(mainAssemblyName, mainAssembly);

            foreach (var filePath in libFileList)
            {
                var assemblyName = Path.GetFileNameWithoutExtension(filePath);

                try
                {
                    var binaryAssembly = DecryptFile(filePath, password);
                    assemblyDict[assemblyName] = binaryAssembly;
                }
                catch (Exception exc)
                {
                    throw new ApplicationLoaderException($"Error loading assembly '{assemblyName}'.", exc);
                }
            }

            #endregion

            #region Load application

            {
                var decryptedAppDomain = AppDomain.CreateDomain(mainAssemblyName, AppDomain.CurrentDomain.Evidence, AppDomain.CurrentDomain.SetupInformation);

                var assemblyResolver = new AssemblyResolver(assemblyDict, decryptedAppDomain);

                var thread = new Thread(() =>
                {
                    // Start the application
                    decryptedAppDomain.ExecuteAssemblyByName(mainAssemblyName);
                });
                thread.SetApartmentState(ApartmentState.STA); // Required by WPF applications
                thread.Start();
            }

#if DEPRECATED
            {
                AppDomain decryptedAppDomain;
                Assembly mainAssembly;

                try
                {
                    var applcationName = Path.GetFileNameWithoutExtension(exePath);
                    decryptedAppDomain = AppDomain.CreateDomain(applcationName, AppDomain.CurrentDomain.Evidence, AppDomain.CurrentDomain.SetupInformation);

                    mainAssembly = decryptedAppDomain.Load(mainAssemblyStream.ToArray());
                    foreach (var item in libStreamDict.Values)
                    {
                        decryptedAppDomain.Load(item.ToArray());
                    }
                }
                catch (Exception exc)
                {
                    throw new ApplicationLoaderException("An error occurred while loading assemblies in the new AppDomain.", exc);
                }

                try
                {
                    decryptedAppDomain.ExecuteAssemblyByName(mainAssembly.GetName());
                }
                catch (Exception exc)
                {
                    throw new ApplicationLoaderException("An error occurred while starting the application in the new AppDomain.", exc);
                }
            }
#endif

            #endregion
        }

        /// <summary>
        /// Decrypts the specified file.
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="password"></param>
        /// <returns>
        /// <c>true</c> on success; <c>false</c> if the decryption failed.
        /// </returns>
        static byte[] DecryptFile(string filePath, string password)
        {
            var bufferSize = (int)new FileInfo(filePath).Length + 64 * 1024;

            using (var inputStream = File.OpenRead(filePath))
            {
                var outputStream = new MemoryStream(bufferSize);

                StreamCryptoUtils.DecryptStream(inputStream, outputStream, password);

                return outputStream.ToArray();
            }
        }

        /// <summary>
        /// The type must be serializable since it is serialized and deserialized when transfered to the new domain. This occurs
        /// at the moment when subscribing to the event (the instance to which the event handler belongs is serialized and then
        /// deserialized in the new domain).
        /// </summary>
        [Serializable]
        class AssemblyResolver
        {
            IDictionary<string, byte[]> _assemblyDict;

            public AssemblyResolver(IDictionary<string, byte[]> assemblies, AppDomain appDomain)
            {
                if (assemblies == null)
                {
                    throw new ArgumentNullException(nameof(assemblies));
                }
                if (appDomain == null)
                {
                    throw new ArgumentNullException(nameof(appDomain));
                }

                this._assemblyDict = assemblies;
                appDomain.AssemblyResolve += AppDomain_AssemblyResolve;
            }

            private Assembly AppDomain_AssemblyResolve(object sender, ResolveEventArgs args)
            {
                var assemblyName = args.Name.Split(new char[] { ',' }, 2)[0];

                byte[] binaryAssembly;
                if (_assemblyDict.TryGetValue(assemblyName, out binaryAssembly))
                {
                    return Assembly.Load(binaryAssembly);
                }
                else
                {
                    return null;
                }
            }
        }
    }
}
