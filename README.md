# claymore web scan
This script allows you to query shodan and check returned list for acces.
It can be:
RO [-]
RW [+]
RW with no password [++]

How to scan:

python claymore.py -a <shodan tocken> "shodan://ETH - Total Speed"

Output:

[claymore.py -             <module>() ][    INFO] --start--
Total Results: 100

ETH - Total Speed: 153.950 Mh/s
[claymore.py -             <module>() ][    INFO] [-] RO target: 59.17.177.101:3001
ETH - Total Speed: 57.694 Mh/s
[claymore.py -             <module>() ][    INFO] [-] RO target: 5.166.226.237:3001
ETH - Total Speed: 186.405 Mh/s
[claymore.py -             <module>() ][    INFO] [+] password protected target: 72.143.75.170:3001
ETH - Total Speed: 31.934 Mh/s
[claymore.py -             <module>() ][    INFO] [+] password protected target: 217.112.4.189:8009
