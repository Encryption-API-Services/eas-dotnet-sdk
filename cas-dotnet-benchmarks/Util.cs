using System.Security.Cryptography;

namespace cas_dotnet_benchmarks
{
    public static class Util
    {
        public static string GeneratePassword(int length)
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()";
            char[] passwordChars = new char[length];

            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] randomBytes = new byte[length];
                rng.GetBytes(randomBytes);

                for (int i = 0; i < length; i++)
                {
                    passwordChars[i] = validChars[randomBytes[i] % validChars.Length];
                }
            }

            return new string(passwordChars);
        }
    }
}
