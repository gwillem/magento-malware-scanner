# Javascript Skimmer Callback URLs from Compromised Sites

## Results
The URLs listed in indicators.md were parsed from one of the many compromised domains that had one of the Javascript skimmer varieties listed [here](https://github.com/gwillem/magento-malware-collection) running on their website.  These indicators are the URLs to which stolen credit card data is sent once it is skimmed from a website.

There are two lists of indicators in indicators.md.  It is highly probable or, in some cases, confirmed that the indicators in the first list are malicious.  Indicators in the second list are more likely to be false positives.  I am conducting further analysis of these indicators in ThreatConnect [here](https://app.threatconnect.com/auth/incident/incident.xhtml?incident=2642112).

## Background
On Tuesday, October 4, Willem de Groot [reported](https://gwillem.gitlab.io/2016/10/04/how-republicans-send-your-credit-card-to-russia/) that the National Republican Senatorial Committee's website had a Javascript skimmer running on it that was collecting credit card numbers and other information from anyone who purchased an item from the site.  He did some further analysis that uncovered many other domains that had some variation of the Javascript skimmer running on their site.  Willem de Groot created a snippet [here](https://gitlab.com/gwillem/public-snippets/snippets/28813) providing a list of sites compromised with some form of this malware.  I have attempted to identify all of the URLs to which the skimmers submit stolen information.  Continue to the next section to read my methodology.

## Methodology
Shortly after Willem de Groot released the list of sites running a form of the malicious code, I collected the html from each infected domain.  I then went through each of the skimmer variants that could be easily deobfuscated and developed a regex to parse out the callback URL used in each instance of that variant.  Here are the regexes I used to parse callback URLs along with the [name of the variant](https://github.com/gwillem/magento-malware-collection/tree/master/malware/frontend) for which the regex was developed:

```
{
    "amasty.biz": "104,116,116,112,46,111,112,101,110,40,34,80,79,83,84,34,44,34,(.*?),34",
    "amasty.biz.js": "frrnq#1?--(.*?)#00#0Arpsc",
    "americanwineclub.se.js": "\('\\x3c\\x73\\x63\\x72'\+'\\x69\\x70\\x74 \\x74\\x79\\x70\\x65\\x3d\\x22\\x74\\x65\\x78\\x74\\x2f\\x6a\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74\\x22 \\x73\\x72\\x63\\x3d\\x22(.*?)\\x22\\x3e\\x3c\\x2f\\x73\\x63\\x72'\+'\\x69\\x70\\x74\\x3e'\)",
    "cloudfusion.me.js": "\"<div />\"\)\.html\(\"(.*?)\"\)\.text\(\),",
    "gate.php.js": "jQuery.ajax\({url:'(.*?)',crossDomain:false",
    "grelos_v.js": "var _0xc188=\[\"(.*?)\",",
    "grelos_v_simple.js": "Glink:.?'(.*?)',",
    "infopromo.biz.js": "http\.open\(\"POST\",\"(.*?)\",true\)",
    "jquery-code.su-charcode.js": "115,114,99,61,(.*?),34,62,60,47,115,99,114,39,43,39,105,112,116,62,39,41,59,10,125,59",
    "js-save.link.js": "\\x3C\\x73\\x63\\x72\\x69\\x70\\x74\\x20\\x73\\x72\\x63\\x3D(.*?)\\x3E\\x3C\\x2F\\x73\\x63\\x72\\x69\\x70\\x74\\x3E",
    "mage-cdn.link.js": ",\"(\\x68\\x74\\x74\\x70.*?)\"",
    "megalith-games.com.js": "frm_fill\(\"(.*?)\"\+n\),"
}
```


Here are some statistics on the number of variants I was able to identify from my dataset of 4829 infected html samples:

- amasty.biz: 1
- amasty.biz.js: 0
- americanwineclub.se.js: 0
- cloudfusion.me.js: 13
- gate.php.js: 15
- grelos_v.js: 1
- grelos_v_simple.js: 42
- infopromo.biz.js: 12
- jquery-code.su-charcode.js: 3
- js-save.link.js: 2625
- mage-cdn.link.js: 88
- megalith-games.com.js: 3
