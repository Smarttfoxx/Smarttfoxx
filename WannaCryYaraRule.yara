rule WannaCry {
    meta:
        last_updated = "2024-05-06"
        author = "Sm4rtF0x"
        description = "Basic Yara rule for detecting WannaCry"
        
    strings:
        // Strings inside the first stage payload
        $killswitch_url = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" ascii
        $executable_1 = "tasksche.exe"
        $executable_2 = "mssecsvc.exe"
        $crypt_string1 = "CryptAcquireContextA"
        $crypt_string2 = "CryptGenRandom"
        $crypt_string3 = "CryptEncrypt"
        $c_strings1 = "%s -m security"
        $c_strings2 = "C:\\%s\\qeriuwjhrf"
        $c_strings3 = "C:\\%s\\%s"
        $wana_strings1 = "WanaCrypt0r"
        $wana_strings2 = "WNcry@2ol7"
        $wana_strings3 = "WANACRY!"
        $wana_strings4 = "gcrY1"
        $wana_strings5 = "*cRy"
        $wana_strings6 = "wnry"
        $PE_byte = { 4D 5A } // "MZ" in hex
        
    condition:
        // Conditions to identify WannaCry
        $PE_byte at 0 and
        ($executable_1 or $killswitch_url or $executable_2 or $c_strings1) and
        ($crypt_string1 or $crypt_string2 or $crypt_string3) and
        ($wana_strings1 or $wana_strings2 or $wana_strings3 or $wana_strings4 or $wana_strings5 or $wana_strings6 or $c_strings2 or $c_strings3)
}
