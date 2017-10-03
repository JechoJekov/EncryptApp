using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace EncryptApp.Cryptography
{
    /// <summary>
    /// Specifies the kind of error that occured.
    /// </summary>
    [Serializable]
    public enum StreamCryptoError
    {
        None = 0,
        /// <summary>
        /// An error occured during encryption. Can be caused by error in the input stream.
        /// </summary>
        EncryptionError,
        /// <summary>
        /// An error occured during decryption. Can be caused by error in the input stream, tampered data or an invalid password.
        /// </summary>
        DecryptionError,
        /// <summary>
        /// The checksum does not match. Can be caused by tampered data or an invalid password.
        /// </summary>
        IntegrityCheckFailed,
        /// <summary>
        /// The stream is not encrypted.
        /// </summary>
        NotEncrypted,
    }
}
