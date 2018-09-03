rule MysteryBot_Unpacked {
	strings:
		$string_1 = "This action will RESET ALL YOUR DATA"
		$string_2 = "key_overlay"
		$string_3 = "SYSTEM_OVERLAY_WINDOW"
		$string_4 = "PACKAGE_USAGE_STATS"
		$string_5 ="inj.zip"
		$string_6 = "/site/"

	condition:
		all of ($string_*)
}
