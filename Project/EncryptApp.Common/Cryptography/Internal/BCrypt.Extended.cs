using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace BCrypt.Net
{
    partial class BCrypt
    {
                /// <summary>
        /// Calculates the hash of the specified password.
        /// </summary>
        /// <param name="password">Password (1 - 72 bytes).</param>
        /// <param name="salt">Salt (16 bytes).</param>
        /// <param name="workLoad">Workload (4 - 31).</param>
        /// <returns>Hash.</returns>
        public static byte[] Crypt(string password, byte[] salt, int workLoad)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            return Crypt(Encoding.UTF8.GetBytes(password), salt, workLoad);
        }

        /// <summary>
        /// Calculates the hash of the specified password.
        /// </summary>
        /// <param name="password">Password (1 - 72 bytes).</param>
        /// <param name="salt">Salt (16 bytes).</param>
        /// <param name="workLoad">Workload (4 - 31).</param>
        /// <returns>Hash.</returns>
        public static byte[] Crypt(byte[] password, byte[] salt, int workLoad)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            if (salt == null)
            {
                throw new ArgumentNullException("salt");
            }
            if (password.Length < 1 || password.Length > 72)
            {
                throw new ArgumentOutOfRangeException("password", password, "Must be between 1 and 72 bytes long.");
            }
            if (salt.Length != 16)
            {
                throw new ArgumentOutOfRangeException("salt", salt, "Must be 16 bytes long.");
            }
            if (workLoad < 4 || workLoad > 31)
            {
                throw new ArgumentOutOfRangeException("workLoad", workLoad, "Must be between 4 and 31.");
            }

            var crypt = new BCrypt();
            return crypt.CryptRaw(password, salt, workLoad);
        }
    }
}
