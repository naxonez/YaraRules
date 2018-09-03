rule LokiBotMobile
{
	strings:
		$string1 = "android.permission.BIND_DEVICE_ADMIN"
		$string2 = "android.permission.SYSTEM_ALERT_WINDOW"
        $string3 = "and your's device will reboot and"
        $string4 = "This action will RESET ALL YOUR DATA."
        $string5 = "Please, wait"
        $string6 = "AndroidManifest.xml"

	condition:
		all of them
}

rule LokiBotMobile1
{
	strings:
		$string1 = "Domian1"
		$string2 = "Domian2"
		$string3 = "Domian3"		
		$string4 = "Domian4"
		$string5 = "Domian5"
		$string6 = "android.permission.BIND_DEVICE_ADMIN"
		$string7 = "android.permission.SYSTEM_ALERT_WINDOW"
		$string8 = "android.permission.SYSTEM_OVERLAY_WINDOW"
		
	condition:
		all of them
}
