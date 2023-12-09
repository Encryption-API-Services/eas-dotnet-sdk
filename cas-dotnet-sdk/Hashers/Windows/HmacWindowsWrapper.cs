﻿using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class HmacWindowsWrapper
    {

        [DllImport("performant_encryption.dll")]
        public static extern IntPtr hmac_sign(string key, string message);
        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool hmac_verify(string key, string message, string signature);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
