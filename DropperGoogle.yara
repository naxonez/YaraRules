rule DropperGoogle {

	strings:
		$string_0 = "gate.php"
		$string_1 = "**pE2**"
		
	condition:
		all of ($string_*)
}
