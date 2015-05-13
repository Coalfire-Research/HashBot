HashBot
------
Willie module for sending hashes to hashcat to be cracked. As soon as a hash is cracked, HashBot will PM the invoker with the cracked hash and plaintext.


####Usage

.hash [hashmode] [ruleset] [hash] [hash] ...

The hashmode must be the corresponding number of the type of hash you wish to crack. A complete list can be found here: [List of hashcat hash modes](http://hashcat.net/wiki/doku.php?id=example_hashes)

You may also replace the hashmode number with one of the following types: sha1, md5, kerberos, ntlm, netntlmv2, netntlmv1, sha512

If no ruleset is given, Hashbot will default to best64.rule. All the examples below are equivalent (md5 hashmode number is 0):

```.hash md5 best64.rule 8743b52063cd84097a65d1633f5c74f5```

```.hash 0 best64.rule 8743b52063cd84097a65d1633f5c74f5```

```.hash md5 8743b52063cd84097a65d1633f5c74f5```


####IRC Commands

See all currently active sessions

.sessions


Kill a session

.kill [sessionname]


Help

.help
