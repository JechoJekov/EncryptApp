using EncryptApp.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace EncryptApp
{
    /// <summary>
    /// Provides a method to encrypt an application.
    /// </summary>
    static class Encryptor
    {
        const string ExeFileExtension = ".exe";
        const string LibFileExtension = ".dll";

        /// <summary>
        /// Checks if the specified directory contains any application files.
        /// </summary>
        /// <param name="applicationPath"></param>
        public static bool IsApplication(string applicationPath)
        {
            if (string.IsNullOrEmpty(applicationPath))
            {
                throw new ArgumentNullException(nameof(applicationPath));
            }

            // An application must have at least one runnable program file
            return Directory.GetFiles(applicationPath).Any(x => GetFileType(x) == ExecutableFileType.Program);
        }

        /// <summary>
        /// Checks if the specified directory contains an encrypted application.
        /// </summary>
        /// <param name="applicationPath"></param>
        public static bool IsEncryptedApplication(string applicationPath)
        {
            if (string.IsNullOrEmpty(applicationPath))
            {
                throw new ArgumentNullException(nameof(applicationPath));
            }

            return Directory.GetFiles(applicationPath).Any(x =>
            {
                var extension = Path.GetExtension(x);
                return extension.Equals(SharedConstants.EncryptedExeFileExtension, StringComparison.OrdinalIgnoreCase)
                    || extension.Equals(SharedConstants.EncryptedLibFileExtension, StringComparison.OrdinalIgnoreCase);
            });
        }

        /// <summary>
        /// Encrypts the specified application in place.
        /// </summary>
        /// <param name="applicationPath"></param>
        /// <param name="loaderPath"></param>
        /// <returns>The list of encrypted files.</returns>
        public static IList<string> Encrypt(
            string applicationPath,
            string loaderPath,
            string password
            )
        {
            if (string.IsNullOrEmpty(applicationPath))
            {
                throw new ArgumentNullException(nameof(applicationPath));
            }
            if (string.IsNullOrEmpty(loaderPath))
            {
                throw new ArgumentNullException(nameof(loaderPath));
            }

            applicationPath = Path.GetFullPath(applicationPath);
            loaderPath = Path.GetFullPath(loaderPath);

            if (false == Directory.Exists(applicationPath))
            {
                throw new ArgumentException($"Application directory '{applicationPath}' not found.", "applicationPath");
            }
            if (false == File.Exists(loaderPath))
            {
                throw new ArgumentException($"Loader not found. Expected location: '{loaderPath}'.", "loaderPath");
            }

            var exeList = Directory.GetFiles(applicationPath, "*" + ExeFileExtension);
            var libList = Directory.GetFiles(applicationPath, "*" + LibFileExtension);

            var encryptedFilesList = new List<string>();

            EncryptFiles(exeList, loaderPath, password, encryptedFilesList);

            if (encryptedFilesList.Count == 0)
            {
                // No .NET application found
                return encryptedFilesList;
            }

            EncryptFiles(libList, loaderPath, password, encryptedFilesList);

            // The loader file must be present in the application's folder as is since it is loaded by the new AppDomain created
            // by the application loader. The "AppDomain" type tries to resolve the loader by using its original executable name
            // (stored inside the assembly). Therefore, the original file must be copied to the application's folder.
            // Due to the way .NET searches for assemblies the extension can be changed from .exe to .dll to avoid confusing the
            // users.
            var outputLoaderPath = Path.Combine(applicationPath, Path.ChangeExtension(Path.GetFileName(loaderPath), LibFileExtension));
            File.Delete(outputLoaderPath);
            File.Copy(loaderPath, outputLoaderPath);

            return encryptedFilesList;
        }

        /// <summary>
        /// Encrypts the specified list of files.
        /// </summary>
        /// <param name="fileList">A collection to which to add the list of files to encrypt. Files names are appended
        /// to the collection.</param>
        /// <param name="loaderPath">Path to the loader application.</param>
        /// <param name="encryptedFilesList">The list of encrypted files. Can be different from <paramref name="fileList"/>
        /// since the method encrypts only .NET assemblies.</param>
        /// <returns>The number of encrypted files.</returns>
        static int EncryptFiles(IList<string> fileList, string loaderPath, string password, IList<string> encryptedFiles)
        {
            var count = 0;
            foreach (var filePath in fileList)
            {
                if (EncryptFile(filePath, loaderPath, password))
                {
                    encryptedFiles.Add(filePath);
                    count++;
                }
            }
            return count;
        }

        /// <summary>
        /// Encrypts the specified file.
        /// </summary>
        /// <param name="filePath">Path to the file to encrypt.</param>
        /// <param name="loaderPath">Path to the loader application.</param>
        /// <returns>
        /// <c>true</c> if the file has been encrypted; <c>false</c> if the file is not a .NET assembly or otherwise, cannot be encrypted.
        /// </returns>
        static bool EncryptFile(string filePath, string loaderPath, string password)
        {
            if (false == IsValidAssembly(filePath))
            {
                return false;
            }

            var fileType = GetFileType(filePath);

            string outputExtension;

            switch (fileType)
            {
                default:
                case ExecutableFileType.None:
                    return false;
                case ExecutableFileType.Program:
                    outputExtension = SharedConstants.EncryptedExeFileExtension;
                    break;
                case ExecutableFileType.Library:
                    outputExtension = SharedConstants.EncryptedLibFileExtension;
                    break;
            }

            var outputFilePath = Path.ChangeExtension(filePath, outputExtension);

            using (var inputStream = File.OpenRead(filePath))
            {
                using (var outputStream = File.Create(outputFilePath))
                {
                    StreamCryptoUtils.EncryptStream(inputStream, outputStream, password);
                }
            }

            // Remove the original file
            File.Delete(filePath);

            // Replace the original file with the loader if it is an .exe
            if (fileType == ExecutableFileType.Program)
            {
                File.Copy(loaderPath, filePath);
            }

            return true;
        }

        /// <summary>
        /// Checks if the specified file is a valid .NET assembly.
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        static bool IsValidAssembly(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException(nameof(path));
            }

            try
            {
                AssemblyName.GetAssemblyName(path);
                return true;
            }
            catch (Exception exc) when (exc is ArgumentException || exc is BadImageFormatException || exc is FileLoadException)
            {
                return false;
            }
        }

        /// <summary>
        /// Returns the type of an executable file.
        /// </summary>
        /// <param name="path">Path to the file.</param>
        /// <returns></returns>
        static ExecutableFileType GetFileType(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException(nameof(path));
            }

            var extension = Path.GetExtension(path);
            if (extension.Equals(ExeFileExtension, StringComparison.OrdinalIgnoreCase))
            {
                return ExecutableFileType.Program;
            }
            else if (extension.Equals(LibFileExtension, StringComparison.OrdinalIgnoreCase))
            {
                return ExecutableFileType.Library;
            }
            else
            {
                return ExecutableFileType.None;
            }
        }

        #region Inner types

        /// <summary>
        /// Specifies the type of an executable file.
        /// </summary>
        enum ExecutableFileType
        {
            /// <summary>
            /// Not an executable file.
            /// </summary>
            None,
            /// <summary>
            /// .exe
            /// </summary>
            Program,
            /// <summary>
            /// .dll
            /// </summary>
            Library,
        }

        #endregion
    }
}
