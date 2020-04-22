rule Weevely3_Webshell {
	meta:
		description = "Weevely 3.4 - 4.0.1 Webshell - Generic Rule - heavily scrambled tiny web shell"
		author = "Peter Matkovski"
		reference = "https://github.com/petermat/weevely-webshell-yara"
		date = "2020/04/22"
		score = 60
	strings:
		$php = "<?php" ascii
		$var1 = "$kf" ascii
		$var2 = "$kh" ascii
		$s0 = /\$[A-Za-z]{1,2}=\'[\w();$\*\.=\-\[\],\" #%@+\/{}\~^`<>&\|_:\!\?]{50,120}\';/ ascii
		$s1 = /\$[A-Za-z]{1,2}=str_replace\('\w+','','[\w]+'\);/ ascii
	    $s2 = /\$[A-Za-z]{1,2}=str_replace\('.{1,2}','',(\$[A-Za-z]{1,2}\.){3,10}\$[A-Za-z]{1,2}\);/ ascii
		$s4 = /\$[A-Za-z]{1,2}=\$\w+\('',\$[A-Za-z]{1,2}\);\$[A-Za-z]{1,2}\(\);/ ascii
	condition:
		$php and ($var1 or $var2) and all of ($s*)
}


