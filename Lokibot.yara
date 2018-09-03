rule LokiBot
{
	strings:
		$string1 = "aPLib"
		$string2 = "MAC=%02X%02X%02XINSTALL=%08X%08Xk"
		$string3 = "moz_logins"
		$string4 = "Fuckav.ru"
		$string5 = "password_value"
		$string6 = "username_value"
		$string7 = "ibsensoftware.com"

	condition:
		all of them
}
