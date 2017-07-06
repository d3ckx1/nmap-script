# nmap-script
IPFire 2.19 漏洞

以kali linux为例，下载即使用方法：

cd /usr/share/nmap/scripts/

git clone https://github.com/d3ckx1/nmap-script.git

sudo nmap --script-updatedb

nmap -v --script=IPFire-vuln -p 444 192.169.1.1
