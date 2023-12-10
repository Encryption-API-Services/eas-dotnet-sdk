﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static CasDotnetSdk.Symmetric.AESWrapper;

namespace CasDotnetSdk.Symmetric.Windows
{
    internal static class AESWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern AesEncryptStruct aes256_encrypt_string(string nonceKey, string dataToEncrypt);
        [DllImport("cas_core_lib.dll")]
        public static extern AesEncryptStruct aes128_encrypt_string(string nonceKey, string dataToEncrypt);
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr aes256_decrypt_string(string nonceKey, string key, string dataToDecrypt);
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr aes_256_key();
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr aes_128_key();
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr aes256_encrypt_string_with_key(string nonceKey, string key, string dataToEncrypt);
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr aes_128_encrypt_string_with_key(string nonceKey, string key, string dataToEncrypt);
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr aes128_decrypt_string(string nonceKey, string key, string dataToEncrypt);

        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}