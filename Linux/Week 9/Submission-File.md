### Mission 1  
nslookup -type=mx starwars.com
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
starwars.com	mail exchanger = 1 aspmx.l.google.com.
starwars.com	mail exchanger = 10 aspmx3.googlemail.com.
starwars.com	mail exchanger = 10 aspmx2.googlemail.com.
starwars.com	mail exchanger = 5 alt2.aspmx.l.google.com.
starwars.com	mail exchanger = 5 alt1.aspx.l.google.com.

The Resistance isn’t able to receive any emails because the URLs of the mail exchanger servers are incorrect.

### Mission 2
nslookup -type=txt theforce.net
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
theforce.net	text = "v=spf1 a mx mx:smtp.secureserver.net include:aspmx.googlemail.com ip4:104.156.250.80 ip4:45.63.15.159 ip4:45.63.4.215"
theforce.net	text = "google-site-verification=XTU_We07Cux-6WCSOItl0c_WS29hzo92jPE341ckbOQ"
theforce.net	text = "google-site-verification=ycgY7mtk2oUZMagcffhFL_Qaf8Lc9tMRkZZSuig0d6w"

The IP address of their mail server (45.23.176.21) doesn’t match the range of IPs on the SPF records of theforce.net. This explains why the Force’s emails are going to spam due to the failed verification of the SPF record. 

The correct DNS record should be aspmx.googlemail.com with IP addresses 45.63.15.159 or 45.63.4.215.

### Mission 3
nslookup -type=cname www.theforce.net
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
www.theforce.net	canonical name = theforce.net.

The CNAME of www.theforce.net is theforce.net, and when perform a nslookup command for resistance.theforce.net


### Mission 4
nslookup -type=ns princessleia.site
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
princessleia.site	nameserver = ns26.domaincontrol.com.
princessleia.site	nameserver = ns25.domaincontrol.com.

In order to have access to the site in case of a future attack, I would add the backup server “ns2.galaxybackup.com” to the DNS record, under nameserver=

### Mission 5
The OSPF shortest path from Batuu to Jedha, excluding Planet N
	Batuu – D – C – E – F – J – I – L – Q – T – V – Jedha 

### Mission 6
Using Aircrack-ng with the rockyou.txt wordlist
aircrack-ng Darkside.pcap -w /usr/share/wordlists/rockyou.txt
 

Sender:
Cisco-Li_e3:e4:01 (00:0f:66:e3:e4:01)
Sender:
172.16.0.1
Target:
IntelCor_55:98:ef (00:13:ce:55:98:ef)
Target:
172.16.0.101



### Mission 7
nslookup -type=txt princessleia.site
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
princessleia.site	text = "Run the following in a command line: telnet towel.blinkenlights.nl or as a backup access in a browser: www.asciimation.co.nz"
 
![image](https://user-images.githubusercontent.com/94209591/161421020-af80ba81-d240-429e-88d8-b228bd15eb1a.png)
