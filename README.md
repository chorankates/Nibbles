# [01 - Nibbles](https://app.hackthebox.com/machines/Nibbles)

![Nibbles.png](Nibbles.png)

## description
> 10.10.10.75

## walkthrough

### recon

```

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

## flag
```
user:
root:
```
