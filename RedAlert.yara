rule redalertJAR {

	strings:
		$string_1 = /http:\/\/\S+:7878/
		$string_2 = "twitter.com"
		$string_4 = "Enable security protection"
		$string_5 = "timeapi.org"
	condition:
		all of ($string_*)
}


rule readAlertNEW {
	strings:
		$string_1 = "twwitter.com"
		$string_2 = /http:\/\/\S+:7878/
		$string_4 = "utc/now?%5CD"
	condition:
		all of ($string_*)
}
