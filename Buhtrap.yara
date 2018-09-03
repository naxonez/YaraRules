rule buhtrapknock {

meta:

 author = "Curt Wilson"
 org    = "Arbor Networks ASERT"
 hash   = "a0c428ae70bfc7fff66845698fb8ce045bffb3114dde4ea2eac19561a619c6c8"
 desc   = "connects to C2 and issues HTTP client request for knock.html"

strings:

 $s1 = "C:\\Users\\dev\\Documents\\Visual Studio 2015\\Projects\\knock\\Release\\knock.pdb" ascii wide
 $s2 = "User-Agent: Mozilla/5.0 (compatible; MSIE 273.0; Windows NT 6.1; WOW64; Trident/5.0; MASP)" ascii wide
 $s3 = "/knock.html" ascii wide

condition:

uint16(0) == 0x5a4d and 2 of ($s*)

}

rule buhtrapkey {

meta:

 author = "Curt Wilson"
 hash   = "97f80175fb58cc514bdcb79d11fe1bcec1b74422171d9493d179a90dcacd7d93"
 desc   = "Buhtrap Related Malcode"

strings:

 $s1 = "1A59D5ABEBFD652D826A976C3C81CC6C"
 $s2 = "ReturnValue" ascii wide

condition:

uint16(0) == 0x5a4d and all of ($s*)
}
