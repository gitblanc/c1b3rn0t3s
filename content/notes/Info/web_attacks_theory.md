---
title: Web Attacks 🐊
tags:
  - Theory
  - CBBH
---
>*Credits to [HTB Academy](https://academy.hackthebox.com/module/134/section/1158)*

# Introduction to Web Attacks

As web applications are becoming very common and being utilized for most businesses, the importance of protecting them against malicious attacks also becomes more critical. As modern web applications become more complex and advanced, so do the types of attacks utilized against them. This leads to a vast attack surface for most businesses today, which is why web attacks are the most common types of attacks against companies. Protecting web applications is becoming one of the top priorities for any IT department.

Attacking external-facing web applications may result in compromise of the businesses' internal network, which may eventually lead to stolen assets or disrupted services. It may potentially cause a financial disaster for the company. Even if a company has no external facing web applications, they likely utilize internal web applications, or external facing API endpoints, both of which are vulnerable to the same types of attacks and can be leveraged to achieve the same goals.

While other HTB Academy modules covered various topics about web applications and various types of web exploitation techniques, in this module, we will cover three other web attacks that can be found in any web application, which may lead to compromise. We will discuss how to detect, exploit, and prevent each of these three attacks.

## Web Attacks

#### HTTP Verb Tampering

The first web attack discussed in this module is [HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering). An HTTP Verb Tampering attack exploits web servers that accept many HTTP verbs and methods. This can be exploited by sending malicious requests using unexpected methods, which may lead to bypassing the web application's authorization mechanism or even bypassing its security controls against other web attacks. HTTP Verb Tampering attacks are one of many other HTTP attacks that can be used to exploit web server configurations by sending malicious HTTP requests.

#### Insecure Direct Object References (IDOR)

The second attack discussed in this module is [Insecure Direct Object References (IDOR)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References). IDOR is among the most common web vulnerabilities and can lead to accessing data that should not be accessible by attackers. What makes this attack very common is essentially the lack of a solid access control system on the back-end. As web applications store users' files and information, they may use sequential numbers or user IDs to identify each item. Suppose the web application lacks a robust access control mechanism and exposes direct references to files and resources. In that case, we may access other users' files and information by simply guessing or calculating their file IDs.

#### XML External Entity (XXE) Injection

The third and final web attack we will discuss is [XML External Entity (XXE) Injection](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_\(XXE\)_Processing). Many web applications process XML data as part of their functionality. Suppose a web application utilizes outdated XML libraries to parse and process XML input data from the front-end user. In that case, it may be possible to send malicious XML data to disclose local files stored on the back-end server. These files may be configuration files that may contain sensitive information like passwords or even the source code of the web application, which would enable us to perform a Whitebox Penetration Test on the web application to identify more vulnerabilities. XXE attacks can even be leveraged to steal the hosting server's credentials, which would compromise the entire server and allow for remote code execution.

# Intro to HTTP Verb Tampering

The `HTTP` protocol works by accepting various HTTP methods as `verbs` at the beginning of an HTTP request. Depending on the web server configuration, web applications may be scripted to accept certain HTTP methods for their various functionalities and perform a particular action based on the type of the request.

While programmers mainly consider the two most commonly used HTTP methods, `GET` and `POST`, any client can send any other methods in their HTTP requests and then see how the web server handles these methods. Suppose both the web application and the back-end web server are configured only to accept `GET` and `POST` requests. In that case, sending a different request will cause a web server error page to be displayed, which is not a severe vulnerability in itself (other than providing a bad user experience and potentially leading to information disclosure). On the other hand, if the web server configurations are not restricted to only accept the HTTP methods required by the web server (e.g. `GET`/`POST`), and the web application is not developed to handle other types of HTTP requests (e.g. `HEAD`, `PUT`), then we may be able to exploit this insecure configuration to gain access to functionalities we do not have access to, or even bypass certain security controls.

## HTTP Verb Tampering

To understand `HTTP Verb Tampering`, we must first learn about the different methods accepted by the HTTP protocol. HTTP has [9 different verbs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) that can be accepted as HTTP methods by web servers. Other than `GET` and `POST`, the following are some of the commonly used HTTP verbs:

|Verb|Description|
|---|---|
|`HEAD`|Identical to a GET request, but its response only contains the `headers`, without the response body|
|`PUT`|Writes the request payload to the specified location|
|`DELETE`|Deletes the resource at the specified location|
|`OPTIONS`|Shows different options accepted by a web server, like accepted HTTP verbs|
|`PATCH`|Apply partial modifications to the resource at the specified location|

As you can imagine, some of the above methods can perform very sensitive functionalities, like writing (`PUT`) or deleting (`DELETE`) files to the webroot directory on the back-end server. As discussed in the [Web Requests](https://academy.hackthebox.com/course/preview/web-requests) module, if a web server is not securely configured to manage these methods, we can use them to gain control over the back-end server. However, what makes HTTP Verb Tampering attacks more common (and hence more critical), is that they are caused by a misconfiguration in either the back-end web server or the web application, either of which can cause the vulnerability.

## Insecure Configurations

Insecure web server configurations cause the first type of HTTP Verb Tampering vulnerabilities. A web server's authentication configuration may be limited to specific HTTP methods, which would leave some HTTP methods accessible without authentication. For example, a system admin may use the following configuration to require authentication on a particular web page:

```xml
<Limit GET POST>
    Require valid-user
</Limit>
```

As we can see, even though the configuration specifies both `GET` and `POST` requests for the authentication method, an attacker may still use a different HTTP method (like `HEAD`) to bypass this authentication mechanism altogether, as will see in the next section. This eventually leads to an authentication bypass and allows attackers to access web pages and domains they should not have access to.

## Insecure Coding

Insecure coding practices cause the other type of HTTP Verb Tampering vulnerabilities (though some may not consider this Verb Tampering). This can occur when a web developer applies specific filters to mitigate particular vulnerabilities while not covering all HTTP methods with that filter. For example, if a web page was found to be vulnerable to a SQL Injection vulnerability, and the back-end developer mitigated the SQL Injection vulnerability by the following applying input sanitization filters:

```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```

We can see that the sanitization filter is only being tested on the `GET` parameter. If the GET requests do not contain any bad characters, then the query would be executed. However, when the query is executed, the `$_REQUEST["code"]` parameters are being used, which may also contain `POST` parameters, `leading to an inconsistency in the use of HTTP Verbs`. In this case, an attacker may use a `POST` request to perform SQL injection, in which case the `GET` parameters would be empty (will not include any bad characters). The request would pass the security filter, which would make the function still vulnerable to SQL Injection.

While both of the above vulnerabilities are found in public, the second one is much more common, as it is due to mistakes made in coding, while the first is usually avoided by secure web server configurations, as documentation often cautions against it. In the coming sections, we will see examples of both types and how to exploit them.

# Bypassing Basic Authentication

Exploiting HTTP Verb Tampering vulnerabilities is usually a relatively straightforward process. We just need to try alternate HTTP methods to see how they are handled by the web server and the web application. While many automated vulnerability scanning tools can consistently identify HTTP Verb Tampering vulnerabilities caused by insecure server configurations, they usually miss identifying HTTP Tampering vulnerabilities caused by insecure coding. This is because the first type can be easily identified once we bypass an authentication page, while the other needs active testing to see whether we can bypass the security filters in place.

The first type of HTTP Verb Tampering vulnerability is mainly caused by `Insecure Web Server Configurations`, and exploiting this vulnerability can allow us to bypass the HTTP Basic Authentication prompt on certain pages.

## Identify

When we start the exercise at the end of this section, we see that we have a basic `File Manager` web application, in which we can add new files by typing their names and hitting `enter`:

![](Pasted%20image%2020250316231536.png)

However, suppose we try to delete all files by clicking on the red `Reset` button. In that case, we see that this functionality seems to be restricted for authenticated users only, as we get the following `HTTP Basic Auth` prompt:

![](Pasted%20image%2020250316231544.png)

As we do not have any credentials, we will get a `401 Unauthorized` page:

![](Pasted%20image%2020250316231552.png)

So, let's see whether we can bypass this with an HTTP Verb Tampering attack. To do so, we need to identify which pages are restricted by this authentication. If we examine the HTTP request after clicking the Reset button or look at the URL that the button navigates to after clicking it, we see that it is at `/admin/reset.php`. So, either the `/admin` directory is restricted to authenticated users only, or only the `/admin/reset.php` page is. We can confirm this by visiting the `/admin` directory, and we do indeed get prompted to log in again. This means that the full `/admin` directory is restricted.

## Exploit

To try and exploit the page, we need to identify the HTTP request method used by the web application. We can intercept the request in Burp Suite and examine it:

![](Pasted%20image%2020250316231603.png)

As the page uses a `GET` request, we can send a `POST` request and see whether the web page allows `POST` requests (i.e., whether the Authentication covers `POST` requests). To do so, we can right-click on the intercepted request in Burp and select `Change Request Method`, and it will automatically change the request into a `POST` request:

![](Pasted%20image%2020250316231611.png)

Once we do so, we can click `Forward` and examine the page in our browser. Unfortunately, we still get prompted to log in and will get a `401 Unauthorized` page if we don't provide the credentials:

![](Pasted%20image%2020250316231620.png)

So, it seems like the web server configurations do cover both `GET` and `POST` requests. However, as we have previously learned, we can utilize many other HTTP methods, most notably the `HEAD` method, which is identical to a `GET` request but does not return the body in the HTTP response. If this is successful, we may not receive any output, but the `reset` function should still get executed, which is our main target.

To see whether the server accepts `HEAD` requests, we can send an `OPTIONS` request to it and see what HTTP methods are accepted, as follows:

```shell
gitblanc@htb[/htb]$ curl -i -X OPTIONS http://SERVER_IP:PORT/

HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

As we can see, the response shows `Allow: POST,OPTIONS,HEAD,GET`, which means that the web server indeed accepts `HEAD` requests, which is the default configuration for many web servers. So, let's try to intercept the `reset` request again, and this time use a `HEAD` request to see how the web server handles it:

![](Pasted%20image%2020250316231638.png)

Once we change `POST` to `HEAD` and forward the request, we will see that we no longer get a login prompt or a `401 Unauthorized` page and get an empty output instead, as expected with a `HEAD` request. If we go back to the `File Manager` web application, we will see that all files have indeed been deleted, meaning that we successfully triggered the `Reset` functionality without having admin access or any credentials:

![](Pasted%20image%2020250316231650.png)

>[!Example]
>The Academy's exercise for this section

I captured the RESET request:

![](Pasted%20image%2020250316232239.png)

I'll try to find out which verbs are accepted by the website:

```shell
curl -I -X OPTIONS http://http://94.237.55.96:50974/

HTTP/1.1 200 OK
Date: Sun, 16 Mar 2025 22:24:20 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1108
Content-Type: text/html; charset=UTF-8
```

So as it doesn't say anything, I'll try all of them. It worked with `PATCH`:

![](Pasted%20image%2020250316232718.png)

![](Pasted%20image%2020250316232730.png)

# Bypassing Security Filters

The other and more common type of HTTP Verb Tampering vulnerability is caused by `Insecure Coding` errors made during the development of the web application, which lead to web application not covering all HTTP methods in certain functionalities. This is commonly found in security filters that detect malicious requests. For example, if a security filter was being used to detect injection vulnerabilities and only checked for injections in `POST` parameters (e.g. `$_POST['parameter']`), it may be possible to bypass it by simply changing the request method to `GET`.

## Identify

In the `File Manager` web application, if we try to create a new file name with special characters in its name (e.g. `test;`), we get the following message:

![](Pasted%20image%2020250316232813.png)

This message shows that the web application uses certain filters on the back-end to identify injection attempts and then blocks any malicious requests. No matter what we try, the web application properly blocks our requests and is secured against injection attempts. However, we may try an HTTP Verb Tampering attack to see if we can bypass the security filter altogether.

## Exploit

To try and exploit this vulnerability, let's intercept the request in Burp Suite (Burp) and then use `Change Request Method` to change it to another method:

![](Pasted%20image%2020250316232825.png)

This time, we did not get the `Malicious Request Denied!` message, and our file was successfully created:

![](Pasted%20image%2020250316232833.png)

To confirm whether we bypassed the security filter, we need to attempt exploiting the vulnerability the filter is protecting: a Command Injection vulnerability, in this case. So, we can inject a command that creates two files and then check whether both files were created. To do so, we will use the following file name in our attack (`file1; touch file2;`):

![](Pasted%20image%2020250316232841.png)

Then, we can once again change the request method to a `GET` request:

![](Pasted%20image%2020250316232853.png)

Once we send our request, we see that this time both `file1` and `file2` were created:

![](Pasted%20image%2020250316232909.png)

This shows that we successfully bypassed the filter through an HTTP Verb Tampering vulnerability and achieved command injection. Without the HTTP Verb Tampering vulnerability, the web application may have been secure against Command Injection attacks, and this vulnerability allowed us to bypass the filters in place altogether.

>[!Example]
>The Academy's exercise for this section

If we try to read the flag with a `GET` petition we get a `Malicious Request Denied!` message:

![](Pasted%20image%2020250316233408.png)

I'll try to change the request to `POST`:

![](Pasted%20image%2020250316233515.png)

It wasn't blocked, so I'll use the following payload:

```shell
file; cat /flag.txt
# URL encoded
file;cat%20%2Fflag.txt
```

![](Pasted%20image%2020250316233713.png)



