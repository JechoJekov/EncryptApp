# EncryptApp
Provides a way to protected a WPF application with a password. All managed assemblies (.exe and .dll) and encrypted with AES-256. The encryption key is derived from the password by using BCrypt (work factor 10) and then PBKDF2 is used to derive a 256 bit key from the 192 output returned by the BCrypt algorithm.

.NET assemblies are decrypted at runtime in memory and loaded in a newly created application domain. This provides a level of protection though it is possible to obtain the original assembly from memory by using reverse engineering tools.
