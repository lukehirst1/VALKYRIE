using System;
using System.Collections.Generic;
using System.Text;

public class ICryptographyServiceTest
{
    /// <summary>
    /// To test whether the script works or not.
    /// </summary>
    public static void TestConsole()
    {
        var passwordHasher = new ICryptographyService.HashPasswords(); // Access the HashPasswords class from ICryptographyService.cs.

        // Hash a test password.
        string testPassword = "Pa$$w0rdT3st"; // Dummy password for testing.
        string hashedPassword = passwordHasher.HashConstructor(testPassword); // Hash the test password using the HashConstructor method.
        Console.WriteLine($"Hashed password is: {hashedPassword}"); // Output the result to the console.

        // Verify the password.
        bool isPasswordValid = passwordHasher.PasswordVerification(testPassword, hashedPassword); // Verify the test password against the hashed password.
        Console.WriteLine($"Is this password valid? {isPasswordValid}"); // Output the result to the console.
    }
}
