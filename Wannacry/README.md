Wannacry YARA Rule:
```
rule WannaCry_Ransomware

{
    meta:
        description = "Detects WannaCry ransomware based on known indicators"
        author = "James Harrington"
        date = "2025-03-15"
        reference = "https://www.wannacry.com"
        malware_family = "Ransom.WannaCry"
    
    strings:
        $s1 = "WannaDecryptor" nocase
        $s2 = "WNcry@2ol7" nocase
        $s3 = "Please Read Me.txt" nocase
        $s4 = "Ooops, your files have been encrypted!" nocase
        $s5 = "bprv.dll"  // Component used by WannaCry
        $s6 = "tasksche.exe" // WannaCry process name
        $s7 = "mssecsvc.exe" // Exploit component
        
        // Hex patterns
        $h1 = { 57 6F 72 6C 64 20 62 61 63 6B 75 70 20 64 65 63 72 79 70 74 6F 72 }
        $h2 = { 77 63 72 79 70 74 2E 64 65 63 }

    condition:
        any of ($s*) or any of ($h*)
}
```
