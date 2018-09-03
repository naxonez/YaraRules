rule Anubis{
	strings:
		$string_0 = "/private/add_inj.php"
		$string_1 = "/private/add_log.php"
		$string_2 = "/private/checkPanel.php"
		$string_3 = "/private/datakeylogger.php"
		$string_4 = "/private/getDataCJ.php"
		$string_5 = "/private/getSettingsAll.php"
		$string_6 = "/private/getfiles.php"
		$string_7 = "/private/locker.php"
		$string_8 = "/private/playprot.php"
		$string_9 = "/private/ratgate.php"
		$string_10 = "/private/setAllSettings.php"
		$string_11 = "/private/setDataCJ.php"
		$string_12 = "/private/set_data.php"
		$string_13 = "/private/set_location.php"
		$string_14 = "/private/settings.php"
		$string_15 = "/private/sound.php"
		$string_16 = "/private/spam.php"
		$string_17 = "/private/tuk_tuk.php"
		$string_18 = "https://twitter.com/"

	condition:
		all of ($string_*)
}
