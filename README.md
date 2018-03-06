
# Magento Malware Scanner

Magento is a profitable target for hackers. Since 2015, I have identified more than 20.000 compromised stores. In most cases, malware is inserted that will a) intercept customer data, b) divert payments or c) uses your customers for cryptojacking.

This project contains both a **fast scanner** to quickly find malware, and a collection of Magento **malware signatures**. They are [recommended by Magento](https://magento.com/security/best-practices/detect-malware-new-discovery-rules) and used by the [US Department of Homeland Security](https://www.dhs.gov/topic/cybersecurity), the [Magento Marketplace](https://twitter.com/jason_c_cochran/status/850043415194685441), [Magereport](https://www.magereport.com), the [Mage Security Council](https://magesec.org) and [many others](docs/who-is-using.md).

# March 2018: update your package/URL

Because the signatures have moved over to S3, you need to update your URL (if you use grep) or package (if you use mwscan). [More info here](https://github.com/gwillem/magento-malware-scanner/issues/149).

# Need help?

If you have a compromised store and are stuck, do [get in touch](mailto:gwillem@gmail.com), I am sure I can help you out!

# Scan your site in 30 seconds

On a standard Linux or Mac OSX server, run two commands to find infected files:

```bash
wget mwscan.s3.amazonaws.com/mwscan.txt
grep -Erlf mwscan.txt /path/to/magento
```

(if no files are shown, then nothing was found!)

![mwscan](https://buq.eu/stuff/mwscan2018.png)

# Advanced scanner for sysadmins: mwscan

Features:

1. Automatically download latest malware signatures.
1. Incremental scans: only display hits for new files. Plus, normal scanning may use lots of server power. So only scanning new files is a great optimization.
1. Faster scanning: using Yara is 4-20x times faster than grep. 
1. Efficient whitelisting: some extension vendors have obfuscated their code so that it looks exactly like malware. We maintain a list of bad-looking-but-good-code to save you some false alarms. 
1. Extension filtering: most of the time, it is useless to scan image files, backups etc. So the default mode for the Malware Scanner is to only scan web code documents (html, js, php).

See [advanced usage](docs/usage.md).

# Test coverage

[![Build Status](https://travis-ci.org/gwillem/magento-malware-scanner.svg?branch=master)](https://travis-ci.org/gwillem/magento-malware-scanner)

Travis-CI verifies:

- that all samples are detected 
- all signatures match at least one sample
- Magento releases do not trigger false positives
