rule BackSwap
{
  meta:
    author = "psrok/des"
    module = "BackSwap"
  strings:
    $api_routine = { B8 07 00 00 00 F7 ?? 8B ?? 0F B6 ?? 03 ?? 47 80 ?? ?? 75 EC }
    $api_loadlib = { E4 5A 57 5A }
    $api_getmodulehandle = { 27 D4 2B C0 }
    $rcxor = { 80 74 01 FF 08
    80 74 01 FF 07
    80 74 01 FF 06 }
    $str1 = "RespectMyAuthority"
    $str2 = "MozillaWindowClass"
    $get_urls_to_inject = { 50 FF [1-5] 8D 83 [4] FF D0 85 C0 74 [1] E8 }
    
  condition:
    all of ($api*) or ( ( all of ($str*) or $get_urls_to_inject ) and $rcxor )
}
