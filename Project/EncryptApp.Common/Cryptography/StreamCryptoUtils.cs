using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using BC = BCrypt.Net.BCrypt;
using System.Security.Cryptography;

namespace EncryptApp.Cryptography
{
    /// <summary>
    /// Provides methods to encrypt and decrypt streams.
    /// </summary>
    public static class StreamCryptoUtils
    {
        #region Constants

        /// <summary>
        /// Magic bytes that marks the beginning of a header.
        /// </summary>
        static byte[] HeaderMagicBytes = { 0x4b, 0xae, 0xc3, 0xfc, 0x55, 0xac, 0x49, 0xa1 };

        /// <summary>
        /// Magic bytes that marks the beginning of a footer.
        /// </summary>
        static byte[] FooterMagicBytes = { 0x46, 0x81, 0x1F, 0xDB, 0x26, 0x22, 0x4D, 0x58, 0x8A, 0xBA, 0x4C, 0xA0, 0x53, 0x3C, 0x23, 0xF1 };

        /// <summary>
        /// The current version of the set of algorithms used.
        /// </summary>
        const int CurrentVersion = 1;

        /// <summary>
        /// The size of the AES key to use;
        /// </summary>
        const int AesKeySize = 256;

        #endregion

        /// <summary>
        /// Encrypts the specified stream.
        /// </summary>
        /// <param name="input">A method to call to write to the encrypted output stream.</param>
        /// <param name="outputStream">The output stream.</param>
        /// <param name="password">The password.</param>
        /// <param name="workload">The workload.</param>
        /// <exception cref="System.ArgumentNullException">
        /// inputStream
        /// or
        /// outputStream
        /// </exception>
        /// <exception cref="Common.Cryptography.IO.StreamCryptoException"></exception>
        /// <remarks>
        /// <para>
        /// This method encrypts all content written by the <see cref="input"/> delegate to the <see cref="Stream"/>
        /// passed to the delegate.
        /// </para>
        /// <para>
        /// This method uses the following algorithms:
        /// AES-256 - encryption
        /// bcrypt  - key derivation
        /// PBKDF2 on HMACSHA1 - key derivation (deriving 256 bit key for AES from 192 bit bcrypt output)
        /// SHA-256 - integrity check
        /// </para>
        /// </remarks>
        public static void EncryptStream(Action<Stream> input, Stream outputStream, string password)
        {
            EncryptStream(input, outputStream, password, 10);
        }

        /// <summary>
        /// Encrypts the specified stream.
        /// </summary>
        /// <param name="input">A method to call to write to the encrypted output stream.</param>
        /// <param name="outputStream">The output stream.</param>
        /// <param name="password">The password.</param>
        /// <param name="workload">The workload.</param>
        /// <exception cref="System.ArgumentNullException">
        /// inputStream
        /// or
        /// outputStream
        /// </exception>
        /// <exception cref="Common.Cryptography.IO.StreamCryptoException"></exception>
        /// <remarks>
        /// <para>
        /// This method encrypts all content written by the <see cref="output"/> delegate to the <see cref="Stream"/>
        /// passed to the delegate.
        /// </para>
        /// <para>
        /// This method uses the following algorithms:
        /// AES-256 - encryption
        /// bcrypt  - key derivation
        /// PBKDF2 on HMACSHA1 - key derivation (deriving 256 bit key for AES from 192 bit bcrypt output)
        /// SHA-256 - integrity check
        /// </para>
        /// </remarks>
        public static void EncryptStream(Action<Stream> input, Stream outputStream, string password, int workload)
        {
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }
            if (outputStream == null)
            {
                throw new ArgumentNullException("outputStream");
            }

            var header = new EncryptionHeader(CurrentVersion, workload);
            var key = DeriveKey(header, password, AesKeySize);

            using (var aes = CreateAes(key))
            {
                using (var hash = SHA256.Create())
                {
                    using (var cryptor = aes.CreateEncryptor())
                    {
                        // Do NOT dispose to avoid closing the output stream
                        var cryptoStream = new CryptoStream(outputStream, cryptor, CryptoStreamMode.Write);
                        // Do NOT dispose to avoid closing the output stream
                        var hashStream = new CryptoStream(cryptoStream, hash, CryptoStreamMode.Write);

                        try
                        {
                            header.WriteTo(outputStream);
                            input(hashStream);

                            // "FlushFinalBlock" can be called only on the outermost stream. It is automatically called on the inner stream
                            // if it is a "CryptoStream". Calling it explicitly on an inner stream causes an exception.
                            if (false == cryptoStream.HasFlushedFinalBlock)
                            {
                                cryptoStream.FlushFinalBlock();
                            }
                            if (false == hashStream.HasFlushedFinalBlock)
                            {
                                hashStream.FlushFinalBlock();
                            }
                        }
                        catch (Exception exc)
                        {
                            throw new StreamCryptoException(StreamCryptoError.EncryptionError, exc.Message, exc);
                        }

                        // Write footer
                        outputStream.Write(FooterMagicBytes, 0, FooterMagicBytes.Length);
                        var hashBytes = hash.Hash;
                        outputStream.Write(hashBytes, 0, hashBytes.Length);
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts the specified stream.
        /// </summary>
        /// <param name="inputStream">The input stream.</param>
        /// <param name="outputStream">The output stream.</param>
        /// <remarks>
        /// This method uses the following algorithms:
        /// AES-256 - encryption
        /// bcrypt  - key derivation
        /// PBKDF2 on HMACSHA1 - key derivation (deriving 256 bit key for AES from 192 bit bcrypt output)
        /// SHA-256 - integrity check
        /// </remarks>
        public static void EncryptStream(Stream inputStream, Stream outputStream, string password)
        {
            EncryptStream(inputStream, outputStream, password, 10);
        }

        /// <summary>
        /// Encrypts the specified stream.
        /// </summary>
        /// <param name="inputStream">The input stream.</param>
        /// <param name="outputStream">The output stream.</param>
        /// <param name="password">The password.</param>
        /// <param name="workload">The workload.</param>
        /// <exception cref="System.ArgumentNullException">
        /// inputStream
        /// or
        /// outputStream
        /// </exception>
        /// <exception cref="Common.Cryptography.IO.StreamCryptoException"></exception>
        /// <remarks>
        /// This method uses the following algorithms:
        /// AES-256 - encryption
        /// bcrypt  - key derivation
        /// PBKDF2 on HMACSHA1 - key derivation (deriving 256 bit key for AES from 192 bit bcrypt output)
        /// SHA-256 - integrity check
        /// </remarks>
        public static void EncryptStream(Stream inputStream, Stream outputStream, string password, int workload)
        {
            if (inputStream == null)
            {
                throw new ArgumentNullException("inputStream");
            }
            if (outputStream == null)
            {
                throw new ArgumentNullException("outputStream");
            }

            EncryptStream(x => inputStream.CopyTo(x), outputStream, password, workload);
        }

        /// <summary>
        /// Decrypts the specified stream.
        /// </summary>
        /// <param name="inputStream">The input stream.</param>
        /// <param name="output">The method to call to handle the decrypted data.</param>
        /// <param name="password">The password.</param>
        /// <exception cref="System.ArgumentNullException">inputStream
        /// or
        /// outputStream</exception>
        /// <exception cref="StreamCryptoException">
        /// Integrity check failed.
        /// </exception>
        /// <exception cref="Common.Cryptography.IO.StreamCryptoException">Integrity check failed.</exception>
        /// <remarks>
        /// <para>
        /// This method calls the <see cref="output"/> delegate with a stream of decrypted data.
        /// </para>
        /// <para>
        /// This method uses the following algorithms:
        /// AES-256 - encryption
        /// bcrypt  - key derivation
        /// PBKDF2 on HMACSHA1 - key derivation (deriving 256 bit key for AES from 192 bit bcrypt output)
        /// SHA-256 - integrity check
        /// </para>
        /// </remarks>
        public static void DecryptStream(Stream inputStream, Action<Stream> output, string password)
        {
            if (inputStream == null)
            {
                throw new ArgumentNullException("inputStream");
            }
            if (output == null)
            {
                throw new ArgumentNullException("output");
            }

            var header = EncryptionHeader.ReadFrom(inputStream);
            var key = DeriveKey(header, password, AesKeySize);

            using (var aes = CreateAes(key))
            {
                using (var hash = SHA256.Create())
                {
                    using (var cryptor = aes.CreateDecryptor())
                    {
                        // Do NOT dispose to avoid closing the input stream
                        // This stream stops reading when the footer is reached
                        var decryptionStream = new DecryptionStream(inputStream);
                        // Do NOT dispose to avoid closing the input stream
                        var cryptoStream = new CryptoStream(decryptionStream, cryptor, CryptoStreamMode.Read);
                        // Do NOT dispose to avoid closing the input stream
                        var hashStream = new CryptoStream(cryptoStream, hash, CryptoStreamMode.Read);

                        try
                        {
                            output(hashStream);

                            // "FlushFinalBlock" can be called only on the outermost stream. It is automatically called on the inner stream
                            // if it is a "CryptoStream". Calling it explicitly on an inner stream causes an exception.
                            if (false == cryptoStream.HasFlushedFinalBlock)
                            {
                                cryptoStream.FlushFinalBlock();
                            }
                            if (false == hashStream.HasFlushedFinalBlock)
                            {
                                hashStream.FlushFinalBlock();
                            }
                        }
                        catch (Exception exc)
                        {
                            throw new StreamCryptoException(StreamCryptoError.DecryptionError, exc.Message, exc);
                        }

                        var hashBytes = hash.Hash;

                        // Read the hash stored after the footer's magic bytes
                        var reader = new BinaryReader(inputStream);
                        var streamHashBytes = reader.ReadBytes(hashBytes.Length);

                        if (false == EqualArrays(streamHashBytes, hashBytes))
                        {
                            throw new StreamCryptoException(StreamCryptoError.IntegrityCheckFailed, "Integrity check failed.");
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts the specified stream.
        /// </summary>
        /// <param name="inputStream">The input stream.</param>
        /// <param name="outputStream">The output stream.</param>
        /// <param name="password">The password.</param>
        /// <exception cref="System.ArgumentNullException">
        /// inputStream
        /// or
        /// outputStream
        /// </exception>
        /// <exception cref="Common.Cryptography.IO.StreamCryptoException">
        /// Integrity check failed.
        /// </exception>
        /// <remarks>
        /// This method uses the following algorithms:
        /// AES-256 - encryption
        /// bcrypt  - key derivation
        /// PBKDF2 on HMACSHA1 - key derivation (deriving 256 bit key for AES from 192 bit bcrypt output)
        /// SHA-256 - integrity check
        /// </remarks>
        public static void DecryptStream(Stream inputStream, Stream outputStream, string password)
        {
            if (outputStream == null)
            {
                throw new ArgumentNullException("outputStream");
            }

            DecryptStream(
                inputStream,
                x => x.CopyTo(outputStream),
                password
                );
        }

        #region Inner types

        #region Header

        /// <summary>
        /// Represents an encryption header.
        /// </summary>
        class EncryptionHeader
        {
            int _version;
            int _workload;
            byte[] _bCryptSalt;
            byte[] _pbkdf2Salt;

            public int Version
            {
                get
                {
                    return _version;
                }
            }

            public int Workload
            {
                get
                {
                    return _workload;
                }
            }

            public byte[] BCryptSalt
            {
                get
                {
                    return _bCryptSalt;
                }
            }

            public byte[] PBKDF2Salt
            {
                get
                {
                    return _pbkdf2Salt;
                }
            }

            EncryptionHeader() { }

            public EncryptionHeader(int version, int workload)
            {
                if (version <= 0)
                {
                    throw new ArgumentOutOfRangeException("version", version, "Must be a positive number.");
                }
                if (workload < 4 || workload > 31)
                {
                    throw new ArgumentOutOfRangeException("workload", workload, "Must be between 4 and 31.");
                }

                _version = version;
                _workload = workload;

                using (var random = RandomNumberGenerator.Create())
                {
                    _bCryptSalt = new byte[16];
                    _pbkdf2Salt = new byte[16];
                    random.GetBytes(_bCryptSalt);
                    random.GetBytes(_pbkdf2Salt);
                }
            }

            public void WriteTo(Stream stream)
            {
                if (stream == null)
                {
                    throw new ArgumentNullException("stream");
                }

                // Do NOT dispose the writer to avoid disposing the stream
                var writer = new BinaryWriter(stream);
                writer.Write(HeaderMagicBytes); // 8 bytes
                writer.Write(_version); // 4 bytes
                writer.Write(_workload); // 4 bytes
                writer.Write(_bCryptSalt); // 16 bytes
                writer.Write(_pbkdf2Salt); // 16 bytes
                // No need to flush since "BinaryWriter" does not store any bytes in its buffer
                //writer.Flush(); // Flush bytes that remain in the buffer
                // Total: 48 bytes
            }

            public static EncryptionHeader ReadFrom(Stream stream)
            {
                if (stream == null)
                {
                    throw new ArgumentNullException("stream");
                }

                var reader = new BinaryReader(stream);
                var newMagicBytes = reader.ReadBytes(HeaderMagicBytes.Length); // 8 bytes
                // Validate magic bytes
                if (false == EqualArrays(HeaderMagicBytes, newMagicBytes))
                {
                    throw new StreamCryptoException(StreamCryptoError.NotEncrypted, "Header not found at the beginning of the stream.");
                }
                var result = new EncryptionHeader();
                result._version = reader.ReadInt32(); // 4 bytes
                result._workload = reader.ReadInt32(); // 4 bytes
                result._bCryptSalt = reader.ReadBytes(16); // 16 bytes
                result._pbkdf2Salt = reader.ReadBytes(16); // 16 bytes
                // Total: 48 bytes
                // Ensure the complete header is read
                if (result._pbkdf2Salt.Length != 16)
                {
                    // EOS reached
                    throw new ArgumentException("End of stream reached.", "stream");
                }
                return result;
            }
        }

        #endregion

        #region Decryption stream

        class DecryptionStream : Stream
        {
            Stream _stream;
            bool _eos;

            public DecryptionStream(Stream stream)
            {
                _stream = stream;
            }

            public override void Close()
            {
                base.Close();

                _stream.Close();
            }

            public override bool CanRead
            {
                get { return _stream.CanRead; }
            }

            public override bool CanSeek
            {
                get { return _stream.CanSeek; }
            }

            public override bool CanWrite
            {
                get { return _stream.CanWrite; }
            }

            public override void Flush()
            {
                _stream.Flush();
            }

            public override long Length
            {
                get { return _stream.Length; }
            }

            public override long Position
            {
                get
                {
                    return _stream.Position;
                }
                set
                {
                    _stream.Position = value;
                }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_eos)
                {
                    // EOS reached
                    return 0;
                }

                if (count < FooterMagicBytes.Length)
                {
                    // This should never happen as all algorithms use at least 128-bit block size

                    return _stream.Read(buffer, offset, count);
                }
                else
                {
                    count = FooterMagicBytes.Length;

                    var result = 0;
                    while (result < count)
                    {
                        var readCount = _stream.Read(buffer, offset + result, count - result);
                        if (readCount <= 0)
                        {
                            // EOS reached
                            break;
                        }
                        result += readCount;
                    }

                    // Debug
                    //Console.WriteLine("{1}: Reading {0} bytes.", count, GetType().Name);

                    if (result >= FooterMagicBytes.Length && EqualArrays(FooterMagicBytes, 0, buffer, offset, FooterMagicBytes.Length))
                    {
                        // EOS reached
                        _eos = true;
                        return 0;
                    }
                    else
                    {
                        return result;
                    }
                }
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                return _stream.Seek(offset, origin);
            }

            public override void SetLength(long value)
            {
                _stream.SetLength(value);
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                _stream.Write(buffer, offset, count);
            }
        }

        #endregion

        #endregion

        #region Helper methods

        /// <summary>
        /// Creates an AES algorithm instance for encryption and decryption.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        static Aes CreateAes(byte[] key)
        {
            var aes = Aes.Create();
            aes.Key = key;
            aes.IV = new byte[aes.BlockSize >> 3]; // There is no need of IV since the key is always unique
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.ISO10126;
            return aes;
        }

        #region Derive key

        /// <summary>
        /// Derives an key from the specified password.
        /// </summary>
        /// <param name="header">A file header.</param>
        /// <param name="password">The password.</param>
        /// <param name="keySize">The size of the key to derive (bits).</param>
        /// <returns>
        /// Key.
        /// </returns>
        /// <exception cref="System.ArgumentNullException">header</exception>
        static byte[] DeriveKey(EncryptionHeader header, string password, int keySize)
        {
            if (header == null)
            {
                throw new ArgumentNullException("header");
            }

            return DeriveKey(
                header.Version,
                password,
                header.BCryptSalt,
                header.PBKDF2Salt,
                header.Workload,
                keySize
                );
        }

        /// <summary>
        /// Derives an key from the specified password.
        /// </summary>
        /// <param name="version">Key derivation schema version.</param>
        /// <param name="password">The password.</param>
        /// <param name="bcryptSalt">bCrypt salt (16 bytes).</param>
        /// <param name="pbkdf2Salt">PBKDF2 salt (min 8 bytes)</param>
        /// <param name="workload">bCrypt workload (4 - 31).</param>
        /// <param name="keySize">The size of the key to derive (bits).</param>
        /// <returns>Key.</returns>
        static byte[] DeriveKey(int version, string password, byte[] bcryptSalt, byte[] pbkdf2Salt, int workload, int keySize)
        {
            switch (version)
            {
                case 1:
                    return DeriveKeyV1(password, bcryptSalt, pbkdf2Salt, workload, keySize);
                default:
                    throw new NotSupportedException(string.Format("Version {0} is not supported.", version));
            }
        }

        /// <summary>
        /// Version 1: Derives an key from the specified password.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="bcryptSalt">bCrypt salt (16 bytes).</param>
        /// <param name="pbkdf2Salt">PBKDF2 salt (min 8 bytes)</param>
        /// <param name="workload">bCrypt workload (4 - 31).</param>
        /// <param name="keySize">The size of the key to derive (bits).</param>
        /// <returns>Key.</returns>
        static byte[] DeriveKeyV1(string password, byte[] bcryptSalt, byte[] pbkdf2Salt, int workload, int keySize)
        {
            var bcryptKey = BC.Crypt(password, bcryptSalt, workload);
            using (var deriveKey = new Rfc2898DeriveBytes(bcryptKey, pbkdf2Salt, 10000))
            {
                return deriveKey.GetBytes(keySize >> 3);
            }
        }

        #endregion

        #region Arrays

        /// <summary>
        /// Determines if two bye arrays contain the same bytes.
        /// </summary>
        /// <param name="a">The first array.</param>
        /// <param name="b">The second array.</param>
        /// <returns>
        /// 	<c>true</c> if the arrays are equal; otherwise <c>false</c>.
        /// </returns>
        static bool EqualArrays(byte[] a, byte[] b)
        {
            if (a == null)
            {
                throw new ArgumentNullException("a");
            }

            if (b == null)
            {
                throw new ArgumentNullException("b");
            }

            if (a.Length != b.Length)
            {
                return false;
            }

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Determines if two bye arrays contain the same bytes.
        /// </summary>
        /// <param name="a">The first array.</param>
        /// <param name="aIndex">The position in the first array from with to begin.</param>
        /// <param name="b">The second array.</param>
        /// <param name="bIndex">The position in the second array from with to begin.</param>
        /// <param name="count">The number of bytes to compare.</param>
        /// <returns>
        /// 	<c>true</c> if the compared portions of the arrays are equal; otherwise <c>false</c>.
        /// </returns>
        static bool EqualArrays(byte[] a, int aIndex, byte[] b, int bIndex, int count)
        {
            if (a == null)
            {
                throw new ArgumentNullException("a");
            }
            if (aIndex < 0)
            {
                throw new ArgumentOutOfRangeException("aIndex", "Must be a non-negative number.");
            }
            if (b == null)
            {
                throw new ArgumentNullException("b");
            }
            if (bIndex < 0)
            {
                throw new ArgumentOutOfRangeException("bIndex", "Must be a non-negative number.");
            }
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException("count", "Must be a non-negative number.");
            }
            if (aIndex + count > a.Length)
            {
                throw new ArgumentOutOfRangeException("Invalid index and/or number of elements for the first array.");
            }
            if (bIndex + count > b.Length)
            {
                throw new ArgumentOutOfRangeException("Invalid index and/or number of elements for the second array.");
            }

            for (int i = 0; i < count; i++)
            {
                if (a[aIndex + i] != b[bIndex + i])
                {
                    return false;
                }
            }

            return true;
        }

        #endregion

        #endregion
    }
}
