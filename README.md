HashBot
------
Willie module for sending hashes to hashcat to be cracked. As soon as a hash is cracked, HashBot will PM the invoker with the cracked hash and plaintext.


####Usage

.hash [hashmode] [ruleset] [hash] [hash] ...

.hash 0 best64.rule 8743b52063cd84097a65d1633f5c74f5

You may replace the hashcat hash mode number with the following common types: sha1, md5, kerberos, ntlm, netntlmv2, netntlmv1, sha512. Type .rules to see all the rules options or just enter some random characters in the ruleset argument spot and it'll default to passwordspro.rule.

[List of hashcat hash modes](http://hashcat.net/wiki/doku.php?id=example_hashes)

.kill [sessionname]
