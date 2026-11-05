using System;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

/// <summary>
/// This class is responsible for hashing passwords, and encrypting them, ready for storage in the password manager at a later date.
/// </summary>
public class HashPasswords()
{
    private const int SaltSize = 16; // The salt size set to 16 is equivalent to 128 bits.
    private const int HashSize = 32; // The hash size is equivalent to 256 bits.
    private const int ThreadCount = 5; // The amount of Central Processor Unit threads the password hasher will use.
    private const int HashIterationCount = 3; // The number of times the hashing will iterate itself (in this case, 3).
    private const int MemorySize = 256 * 1024; // Memory Size is equal to 256 megabytes, as opposed to one gigabyte.

    /// <summary>
    /// This function hashes passwords using the parameter accepted by the variable acceptedPassword.
    /// </summary>
    /// <param name="acceptedPassword"></param>
    /// <returns></returns>
    public String HashConstructor(string acceptedPassword)
    {
        // First, generate a random salt each time for a password to use.
        byte[] passwordSalt = new byte[SaltSize]; // Make a new byte array passing SaltSize as the accepted parameter.
        using (var RNG = RandomNumberGenerator.Create()) // Using RNG as a variable, create a new random number generator.
        {
            RNG.GetBytes(passwordSalt); // Tell the random number generator to get the number of bytes as dictated by passwordSalt.
        }

        // Construct a byte array hash using the HashConstructor method, taking acceptedPassword and passwordSalt as accepted parameters.
        byte[] hashPass = HashConstructor(acceptedPassword, passwordSalt);

        var combinedByteVals = new byte[passwordSalt.Length + hashPass.Length]; // Easier to combine variables together as opposed to leaving them separate.
        Array.Copy(passwordSalt, 0, combinedByteVals, 0, passwordSalt.Length); // Copies the two byte arrays together
        Array.Copy(hashPass, 0, combinedByteVals, 0, hashPass.Length); // Copies the two hash arrays together

        // Turns the bytes into a readable string
        // NOTE TO SELF: Adapt function for use in VALKYRIE - This is just a dummy function for now.
        return Convert.ToBase64String(combinedByteVals);
    }

    // Using the reference from the String version, create a new HashConstructor using byte arrays.
    private byte[] HashConstructor(string acceptedPassword, byte[] passwordSalt)
    {
        // Use the ARGON2 algorithm to get the bytes of the value "acceptedPassword"
        var ARGON2 = new Argon2id(Encoding.UTF8.GetBytes(acceptedPassword)) 
        {
            Salt = passwordSalt,
            DegreeOfParallelism = ThreadCount,
            Iterations = HashIterationCount,
            MemorySize = MemorySize
        };

        return ARGON2.GetBytes(HashSize); // Return ARGON2.GetBytes using HashSize.
    }

    /// <summary>
    /// After turning the bytes into a string, it then turns it into a value that can be read from the computer.
    /// </summary>
    /// <param name="acceptedPassword"></param>
    /// <param name="hashedPassword"></param>
    /// <returns></returns>
    public bool PasswordVerification(string acceptedPassword, string hashedPassword)
    {
        byte[] combinedByteVals = Convert.FromBase64String(hashedPassword); // Get the values from the combinedBytesVals variable.

        byte[] extractedSalt = new byte[SaltSize];
        byte[] extractedHash = new byte[HashSize];

        Array.Copy(combinedByteVals, 0, extractedSalt, 0, SaltSize);
        Array.Copy(combinedByteVals, 0, extractedHash, 0, HashSize);

        byte[] newHash = HashConstructor(acceptedPassword, extractedSalt);

        return CryptographicOperations.FixedTimeEquals(extractedHash, newHash);
    }
}
