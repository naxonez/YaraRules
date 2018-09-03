rule KariusBankerSecondVersion
{
	strings:
		$string1 = "temp.bin"
		$string2 = "gateway.php"
		$string3 = "\"url\":"
		$string4 = "\"key\":"
		$string5 = ".cfg"
		$string6 = "attrib -a -s -h -r %Module%"

	condition:
		all of them
}


rule KariusBankerFirstVersion
{
	strings:
		$string1 = "\"host\":"
		$string2 = "\"data\":"
		$string4 = "\"inject\":"
		$string5 = "\"before\":"
		$string6 = "\"after\":"
		$string7 = "temp.bin"
		$string8 = "gateway.php"

	condition:
		all of them
}
