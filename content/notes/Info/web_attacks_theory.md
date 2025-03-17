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

# Intro to IDOR

`Insecure Direct Object References (IDOR)` vulnerabilities are among the most common web vulnerabilities and can significantly impact the vulnerable web application. IDOR vulnerabilities occur when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects. If any user can access any resource due to the lack of a solid access control system, the system is considered to be vulnerable.

Building a solid access control system is very challenging, which is why IDOR vulnerabilities are pervasive. In addition, automating the process of identifying weaknesses in access control systems is also quite difficult, which may lead to these vulnerabilities going unidentified until they reach production.

For example, if users request access to a file they recently uploaded, they may get a link to it such as (`download.php?file_id=123`). So, as the link directly references the file with (`file_id=123`), what would happen if we tried to access another file (which may not belong to us) with (`download.php?file_id=124`)? If the web application does not have a proper access control system on the back-end, we may be able to access any file by sending a request with its `file_id`. In many cases, we may find that the `id` is easily guessable, making it possible to retrieve many files or resources that we should not have access to based on our permissions.

## What Makes an IDOR Vulnerability

Just exposing a direct reference to an internal object or resource is not a vulnerability in itself. However, this may make it possible to exploit another vulnerability: a `weak access control system`. Many web applications restrict users from accessing resources by restricting them from accessing the pages, functions, and APIs that can retrieve these resources. However, what would happen if a user somehow got access to these pages (e.g., through a shared/guessed link)? Would they still be able to access the same resources by simply having the link to access them? If the web application did not have an access control system on the back-end that compares the user's authentication to the resource's access list, they might be able to.

There are many ways of implementing a solid access control system for web applications, like having a Role-Based Access Control ([RBAC](https://en.wikipedia.org/wiki/Role-based_access_control)) system. The main takeaway is that `an IDOR vulnerability mainly exists due to the lack of an access control on the back-end`. If a user had direct references to objects in a web application that lacks access control, it would be possible for attackers to view or modify other users' data.

Many developers ignore building an access control system; hence, most web applications and mobile applications are left unprotected on the back-end. In such applications, all users may have arbitrary access to all other user's data on the back-end. The only thing stopping users from accessing other user's data would be the front-end implementation of the application, which is designed to only show the user's data. In such cases, manually manipulating HTTP requests may reveal that all users have full access to all data, leading to a successful attack.

All of this makes IDOR vulnerabilities among the most critical vulnerabilities for any web or mobile application, not only due to exposing direct object references but mainly due to a lack of a solid access control system. Even a basic access control system can be challenging to develop. A comprehensive access control system covering the entire web application without interfering with its functions might be an even more difficult task. This is why IDOR/Access Control vulnerabilities are found even in very large web applications, like [Facebook](https://infosecwriteups.com/disclose-private-attachments-in-facebook-messenger-infrastructure-15-000-ae13602aa486), [Instagram](https://infosecwriteups.com/add-description-to-instagram-posts-on-behalf-of-other-users-6500-7d55b4a24c5a), and [Twitter](https://medium.com/@kedrisec/publish-tweets-by-any-other-user-6c9d892708e3).

## Impact of IDOR Vulnerabilities

As mentioned earlier, IDOR vulnerabilities can have a significant impact on web applications. The most basic example of an IDOR vulnerability is accessing private files and resources of other users that should not be accessible to us, like personal files or credit card data, which is known as `IDOR Information Disclosure Vulnerabilities`. Depending on the nature of the exposed direct reference, the vulnerability may even allow the modification or deletion of other users' data, which may lead to a complete account takeover.

Once an attacker identifies the direct references, which may be database IDs or URL parameters, they can start testing specific patterns to see whether they can gain access to any data and may eventually understand how to extract or modify data for any arbitrary user.

IDOR vulnerabilities may also lead to the elevation of user privileges from a standard user to an administrator user, with `IDOR Insecure Function Calls`. For example, many web applications expose URL parameters or APIs for admin-only functions in the front-end code of the web application and disable these functions for non-admin users. However, if we had access to such parameters or APIs, we may call them with our standard user privileges. Suppose the back-end did not explicitly deny non-admin users from calling these functions. In that case, we may be able to perform unauthorized administrative operations, like changing users' passwords or granting users certain roles, which may eventually lead to a total takeover of the entire web application.

# Identifying IDORs

## URL Parameters & APIs

The very first step of exploiting IDOR vulnerabilities is identifying Direct Object References. Whenever we receive a specific file or resource, we should study the HTTP requests to look for URL parameters or APIs with an object reference (e.g. `?uid=1` or `?filename=file_1.pdf`). These are mostly found in URL parameters or APIs but may also be found in other HTTP headers, like cookies.

In the most basic cases, we can try incrementing the values of the object references to retrieve other data, like (`?uid=2`) or (`?filename=file_2.pdf`). We can also use a fuzzing application to try thousands of variations and see if they return any data. Any successful hits to files that are not our own would indicate an IDOR vulnerability.

## AJAX Calls

We may also be able to identify unused parameters or APIs in the front-end code in the form of JavaScript AJAX calls. Some web applications developed in JavaScript frameworks may insecurely place all function calls on the front-end and use the appropriate ones based on the user role.

For example, if we did not have an admin account, only the user-level functions would be used, while the admin functions would be disabled. However, we may still be able to find the admin functions if we look into the front-end JavaScript code and may be able to identify AJAX calls to specific end-points or APIs that contain direct object references. If we identify direct object references in the JavaScript code, we can test them for IDOR vulnerabilities.

This is not unique to admin functions, of course, but can also be any functions or calls that may not be found through monitoring HTTP requests. The following example shows a basic example of an AJAX call:

```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

The above function may never be called when we use the web application as a non-admin user. However, if we locate it in the front-end code, we may test it in different ways to see whether we can call it to perform changes, which would indicate that it is vulnerable to IDOR. We can do the same with back-end code if we have access to it (e.g., open-source web applications).

## Understand Hashing/Encoding

Some web applications may not use simple sequential numbers as object references but may encode the reference or hash it instead. If we find such parameters using encoded or hashed values, we may still be able to exploit them if there is no access control system on the back-end.

Suppose the reference was encoded with a common encoder (e.g. `base64`). In that case, we could decode it and view the plaintext of the object reference, change its value, and then encode it again to access other data. For example, if we see a reference like (`?filename=ZmlsZV8xMjMucGRm`), we can immediately guess that the file name is `base64` encoded (from its character set), which we can decode to get the original object reference of (`file_123.pdf`). Then, we can try encoding a different object reference (e.g. `file_124.pdf`) and try accessing it with the encoded object reference (`?filename=ZmlsZV8xMjQucGRm`), which may reveal an IDOR vulnerability if we were able to retrieve any data.

On the other hand, the object reference may be hashed, like (`download.php?filename=c81e728d9d4c2f636f067f89cc14862c`). At a first glance, we may think that this is a secure object reference, as it is not using any clear text or easy encoding. However, if we look at the source code, we may see what is being hashed before the API call is made:

```javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

In this case, we can see that code uses the `filename` and hashing it with `CryptoJS.MD5`, making it easy for us to calculate the `filename` for other potential files. Otherwise, we may manually try to identify the hashing algorithm being used (e.g., with hash identifier tools) and then hash the filename to see if it matches the used hash. Once we can calculate hashes for other files, we may try downloading them, which may reveal an IDOR vulnerability if we can download any files that do not belong to us.

## Compare User Roles

If we want to perform more advanced IDOR attacks, we may need to register multiple users and compare their HTTP requests and object references. This may allow us to understand how the URL parameters and unique identifiers are being calculated and then calculate them for other users to gather their data.

For example, if we had access to two different users, one of which can view their salary after making the following API call:

```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

The second user may not have all of these API parameters to replicate the call and should not be able to make the same call as `User1`. However, with these details at hand, we can try repeating the same API call while logged in as `User2` to see if the web application returns anything. Such cases may work if the web application only requires a valid logged-in session to make the API call but has no access control on the back-end to compare the caller's session with the data being called.

If this is the case, and we can calculate the API parameters for other users, this would be an IDOR vulnerability. Even if we could not calculate the API parameters for other users, we would still have identified a vulnerability in the back-end access control system and may start looking for other object references to exploit.

# Mass IDOR Enumeration

Exploiting IDOR vulnerabilities is easy in some instances but can be very challenging in others. Once we identify a potential IDOR, we can start testing it with basic techniques to see whether it would expose any other data. As for advanced IDOR attacks, we need to better understand how the web application works, how it calculates its object references, and how its access control system works to be able to perform advanced attacks that may not be exploitable with basic techniques.

Let's start discussing various techniques of exploiting IDOR vulnerabilities, from basic enumeration to mass data gathering, to user privilege escalation.

## Insecure Parameters

Let's start with a basic example that showcases a typical IDOR vulnerability. The exercise below is an `Employee Manager` web application that hosts employee records:

![](Pasted%20image%2020250317104653.png)

Our web application assumes that we are logged in as an employee with user id `uid=1` to simplify things. This would require us to log in with credentials in a real web application, but the rest of the attack would be the same. Once we click on `Documents`, we are redirected to `/documents.php`:

![](Pasted%20image%2020250317104706.png)

When we get to the `Documents` page, we see several documents that belong to our user. These can be files uploaded by our user or files set for us by another department (e.g., HR Department). Checking the file links, we see that they have individual names:

```html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

We see that the files have a predictable naming pattern, as the file names appear to be using the user `uid` and the month/year as part of the file name, which may allow us to fuzz files for other users. This is the most basic type of IDOR vulnerability and is called `static file IDOR`. However, to successfully fuzz other files, we would assume that they all start with `Invoice` or `Report`, which may reveal some files but not all. So, let's look for a more solid IDOR vulnerability.

We see that the page is setting our `uid` with a `GET` parameter in the URL as (`documents.php?uid=1`). If the web application uses this `uid` GET parameter as a direct reference to the employee records it should show, we may be able to view other employees' documents by simply changing this value. If the back-end end of the web application `does` have a proper access control system, we will get some form of `Access Denied`. However, given that the web application passes as our `uid` in clear text as a direct reference, this may indicate poor web application design, leading to arbitrary access to employee records.

When we try changing the `uid` to `?uid=2`, we don't notice any difference in the page output, as we are still getting the same list of documents, and may assume that it still returns our own documents:

![](Pasted%20image%2020250317104725.png)

However, `we must be attentive to the page details during any web pentest` and always keep an eye on the source code and page size. If we look at the linked files, or if we click on them to view them, we will notice that these are indeed different files, which appear to be the documents belonging to the employee with `uid=2`:

```html
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```

This is a common mistake found in web applications suffering from IDOR vulnerabilities, as they place the parameter that controls which user documents to show under our control while having no access control system on the back-end. Another example is using a filter parameter to only display a specific user's documents (e.g. `uid_filter=1`), which can also be manipulated to show other users' documents or even completely removed to show all documents at once.

## Mass Enumeration

We can try manually accessing other employee documents with `uid=3`, `uid=4`, and so on. However, manually accessing files is not efficient in a real work environment with hundreds or thousands of employees. So, we can either use a tool like `Burp Intruder` or `ZAP Fuzzer` to retrieve all files or write a small bash script to download all files, which is what we will do.

We can click on `CTRL+SHIFT+C` in Firefox to enable the `element inspector`, and then click on any of the links to view their HTML source code, and we will get the following:

```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

We can pick any unique word to be able to `grep` the link of the file. In our case, we see that each link starts with `<li class='pure-tree_link'>`, so we may `curl` the page and `grep` for this line, as follows:

```shell
gitblanc@htb[/htb]$ curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

As we can see, we were able to capture the document links successfully. We may now use specific bash commands to trim the extra parts and only get the document links in the output. However, it is a better practice to use a `Regex` pattern that matches strings between `/document` and `.pdf`, which we can use with `grep` to only get the document links, as follows:

```shell
gitblanc@htb[/htb]$ curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

Now, we can use a simple `for` loop to loop over the `uid` parameter and return the document of all employees, and then use `wget` to download each document link:

```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

When we run the script, it will download all documents from all employees with `uids` between 1-10, thus successfully exploiting the IDOR vulnerability to mass enumerate the documents of all employees. This script is one example of how we can achieve the same objective. Try using a tool like Burp Intruder or ZAP Fuzzer, or write another Bash or PowerShell script to download all documents.

>[!Example]
>The Academy's exercise for this section

I captured the request with CAIDO:

![](Pasted%20image%2020250317110042.png)

I automated it to see the first 20 employees:

![](Pasted%20image%2020250317110232.png)

![](Pasted%20image%2020250317110304.png)

I got the flag with:

```shell
wget -q "http://94.237.54.116:55129/documents$(curl -X POST "http://94.237.54.116:55129/documents.php" -H "Content-Type: application/x-www-form-urlencoded" -d "uid=15" | grep -oP '/flag.*?\.txt')"

HTB{4ll_f1l35_4r3_m1n3}
```

- *NOTE: I found that the flag was inside `documents` by manually searching it with CAIDO*

# Bypassing Encoded References

In the previous section, we saw an example of an IDOR that uses employee uids in clear text, making it easy to enumerate. In some cases, web applications make hashes or encode their object references, making enumeration more difficult, but it may still be possible.

Let's go back to the `Employee Manager` web application to test the `Contracts` functionality:

![](Pasted%20image%2020250317111647.png)

If we click on the `Employment_contract.pdf` file, it starts downloading the file. The intercepted request in Burp looks as follows:

![](Pasted%20image%2020250317111653.png)

We see that it is sending a `POST` request to `download.php` with the following data:

```php
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

Using a `download.php` script to download files is a common practice to avoid directly linking to files, as that may be exploitable with multiple web attacks. In this case, the web application is not sending the direct reference in cleartext but appears to be hashing it in an `md5` format. Hashes are one-way functions, so we cannot decode them to see their original values.

We can attempt to hash various values, like `uid`, `username`, `filename`, and many others, and see if any of their `md5` hashes match the above value. If we find a match, then we can replicate it for other users and collect their files. For example, let's try to compare the `md5` hash of our `uid`, and see if it matches the above hash:

```shell
gitblanc@htb[/htb]$ echo -n 1 | md5sum

c4ca4238a0b923820dcc509a6f75849b -
```

Unfortunately, the hashes do not match. We can attempt this with various other fields, but none of them matches our hash. In advanced cases, we may also utilize `Burp Comparer` and fuzz various values and then compare each to our hash to see if we find any matches. In this case, the `md5` hash could be for a unique value or a combination of values, which would be very difficult to predict, making this direct reference a `Secure Direct Object Reference`. However, there's one fatal flaw in this web application.

## Function Disclosure

As most modern web applications are developed using JavaScript frameworks, like `Angular`, `React`, or `Vue.js`, many web developers may make the mistake of performing sensitive functions on the front-end, which would expose them to attackers. For example, if the above hash was being calculated on the front-end, we can study the function and then replicate what it's doing to calculate the same hash. Luckily for us, this is precisely the case in this web application.

If we take a look at the link in the source code, we see that it is calling a JavaScript function with `javascript:downloadContract('1')`. Looking at the `downloadContract()` function in the source code, we see the following:

```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

This function appears to be sending a `POST` request with the `contract` parameter, which is what we saw above. The value it is sending is an `md5` hash using the `CryptoJS` library, which also matches the request we saw earlier. So, the only thing left to see is what value is being hashed.

In this case, the value being hashed is `btoa(uid)`, which is the `base64` encoded string of the `uid` variable, which is an input argument for the function. Going back to the earlier link where the function was called, we see it calling `downloadContract('1')`. So, the final value being used in the `POST` request is the `base64` encoded string of `1`, which was then `md5` hashed.

We can test this by `base64` encoding our `uid=1`, and then hashing it with `md5`, as follows:

```shell
gitblanc@htb[/htb]$ echo -n 1 | base64 -w 0 | md5sum

cdd96d3cc73d1dbdaffa03cc6cd7339b -
```

>[!Tip]
>We are using the `-n` flag with `echo`, and the `-w 0` flag with `base64`, to avoid adding newlines, in order to be able to calculate the `md5` hash of the same value, without hashing newlines, as that would change the final `md5` hash.

As we can see, this hash matches the hash in our request, meaning that we have successfully reversed the hashing technique used on the object references, turning them into IDOR's. With that, we can begin enumerating other employees' contracts using the same hashing method we used above. `Before continuing, try to write a script similar to what we used in the previous section to enumerate all contracts`.

## Mass Enumeration

Once again, let us write a simple bash script to retrieve all employee contracts. More often than not, this is the easiest and most efficient method of enumerating data and files through IDOR vulnerabilities. In more advanced cases, we may utilize tools like `Burp Intruder` or `ZAP Fuzzer`, but a simple bash script should be the best course for our exercise.

We can start by calculating the hash for each of the first ten employees using the same previous command while using `tr -d` to remove the trailing `-` characters, as follows:

```shell
gitblanc@htb[/htb]$ for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done

cdd96d3cc73d1dbdaffa03cc6cd7339b
0b7e7dee87b1c3b98e72131173dfbbbf
0b24df25fe628797b3a50ae0724d2730
f7947d50da7a043693a592b4db43b0a1
8b9af1f7f76daf0f02bd9c48c4a2e3d0
006d1236aee3f92b8322299796ba1989
b523ff8d1ced96cef9c86492e790c2fb
d477819d240e7d3dd9499ed8d23e7158
3e57e65a34ffcb2e93cb545d024f5bde
5d4aace023dc088767b4e08c79415dcd
```

Next, we can make a `POST` request on `download.php` with each of the above hashes as the `contract` value, which should give us our final script:

```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

With that, we can run the script, and it should download all contracts for employees 1-10:

```shell
gitblanc@htb[/htb]$ bash ./exploit.sh
gitblanc@htb[/htb]$ ls -1

contract_006d1236aee3f92b8322299796ba1989.pdf
contract_0b24df25fe628797b3a50ae0724d2730.pdf
contract_0b7e7dee87b1c3b98e72131173dfbbbf.pdf
contract_3e57e65a34ffcb2e93cb545d024f5bde.pdf
contract_5d4aace023dc088767b4e08c79415dcd.pdf
contract_8b9af1f7f76daf0f02bd9c48c4a2e3d0.pdf
contract_b523ff8d1ced96cef9c86492e790c2fb.pdf
contract_cdd96d3cc73d1dbdaffa03cc6cd7339b.pdf
contract_d477819d240e7d3dd9499ed8d23e7158.pdf
contract_f7947d50da7a043693a592b4db43b0a1.pdf
```

As we can see, because we could reverse the hashing technique used on the object references, we can now successfully exploit the IDOR vulnerability to retrieve all other users' contracts.

>[!Example]
>The Academy's exercise for this section

If we inspect the main function:

![](Pasted%20image%2020250317112611.png)

![](Pasted%20image%2020250317112638.png)

The function just encodes the uid in base64:

![](Pasted%20image%2020250317112743.png)

We can test it with:

```shell
echo -n 1 | base64 -w 0

MQ==
```

![](Pasted%20image%2020250317112901.png)

![](Pasted%20image%2020250317112913.png)

So now I'll create a script to download all the contracts of first 20 employees, first creating all the links:

```shell
for i in {1..20}; do echo -n $i | base64 -w 0 | jq -sRr @uri; done
MQ%3D%3D
Mg%3D%3D
Mw%3D%3D
NA%3D%3D
NQ%3D%3D
Ng%3D%3D
Nw%3D%3D
OA%3D%3D
OQ%3D%3D
MTA%3D
MTE%3D
MTI%3D
MTM%3D
MTQ%3D
MTU%3D
MTY%3D
MTc%3D
MTg%3D
MTk%3D
MjA%3D
```

```shell
#!/bin/bash

for i in {1..20}; do
    for hash in $(echo -n $i | base64 -w 0 | sed -E 's/\+/%2B/g; s/\//%2F/g; s/=/%3D/g'); do
        curl -sOJ -X POST "http://94.237.54.116:55129/download.php?contract=$hash"
    done
done
```

![](Pasted%20image%2020250317113938.png)

# IDOR in Insecure APIs

So far, we have only been using IDOR vulnerabilities to access files and resources that are out of our user's access. However, IDOR vulnerabilities may also exist in function calls and APIs, and exploiting them would allow us to perform various actions as other users.

While `IDOR Information Disclosure Vulnerabilities` allow us to read various types of resources, `IDOR Insecure Function Calls` enable us to call APIs or execute functions as another user. Such functions and APIs can be used to change another user's private information, reset another user's password, or even buy items using another user's payment information. In many cases, we may be obtaining certain information through an information disclosure IDOR vulnerability and then using this information with IDOR insecure function call vulnerabilities, as we will see later in the module.

## Identifying Insecure APIs

Going back to our `Employee Manager` web application, we can start testing the `Edit Profile` page for IDOR vulnerabilities:

![](Pasted%20image%2020250317114458.png)

When we click on the `Edit Profile` button, we are taken to a page to edit information of our user profile, namely `Full Name`, `Email`, and `About Me`, which is a common feature in many web applications:

![](Pasted%20image%2020250317114505.png)

We can change any of the details in our profile and click `Update profile`, and we'll see that they get updated and persist through refreshes, which means they get updated in a database somewhere. Let's intercept the `Update` request in Burp and look at it:

![](Pasted%20image%2020250317114514.png)

We see that the page is sending a `PUT` request to the `/profile/api.php/profile/1` API endpoint. `PUT` requests are usually used in APIs to update item details, while `POST` is used to create new items, `DELETE` to delete items, and `GET` to retrieve item details. So, a `PUT` request for the `Update profile` function is expected. The interesting bit is the JSON parameters it is sending:

```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

We see that the `PUT` request includes a few hidden parameters, like `uid`, `uuid`, and most interestingly `role`, which is set to `employee`. The web application also appears to be setting the user access privileges (e.g. `role`) on the client-side, in the form of our `Cookie: role=employee` cookie, which appears to reflect the `role` specified for our user. This is a common security issue. The access control privileges are sent as part of the client's HTTP request, either as a cookie or as part of the JSON request, leaving it under the client's control, which could be manipulated to gain more privileges.

So, unless the web application has a solid access control system on the back-end, `we should be able to set an arbitrary role for our user, which may grant us more privileges`. However, how would we know what other roles exist?

## Exploiting Insecure APIs

We know that we can change the `full_name`, `email`, and `about` parameters, as these are the ones under our control in the HTML form in the `/profile` web page. So, let's try to manipulate the other parameters.

There are a few things we could try in this case:

1. Change our `uid` to another user's `uid`, such that we can take over their accounts
2. Change another user's details, which may allow us to perform several web attacks
3. Create new users with arbitrary details, or delete existing users
4. Change our role to a more privileged role (e.g. `admin`) to be able to perform more actions

Let's start by changing our `uid` to another user's `uid` (e.g. `"uid": 2`). However, any number we set other than our own `uid` gets us a response of `uid mismatch`:

![](Pasted%20image%2020250317114531.png)

The web application appears to be comparing the request's `uid` to the API endpoint (`/1`). This means that a form of access control on the back-end prevents us from arbitrarily changing some JSON parameters, which might be necessary to prevent the web application from crashing or returning errors.

Perhaps we can try changing another user's details. We'll change the API endpoint to `/profile/api.php/profile/2`, and change `"uid": 2` to avoid the previous `uid mismatch`:

![](Pasted%20image%2020250317114538.png)

As we can see, this time, we get an error message saying `uuid mismatch`. The web application appears to be checking if the `uuid` value we are sending matches the user's `uuid`. Since we are sending our own `uuid`, our request is failing. This appears to be another form of access control to prevent users from changing another user's details.

Next, let's see if we can create a new user with a `POST` request to the API endpoint. We can change the request method to `POST`, change the `uid` to a new `uid`, and send the request to the API endpoint of the new `uid`:

![](Pasted%20image%2020250317114546.png)

We get an error message saying `Creating new employees is for admins only`. The same thing happens when we send a `Delete` request, as we get `Deleting employees is for admins only`. The web application might be checking our authorization through the `role=employee` cookie because this appears to be the only form of authorization in the HTTP request.

Finally, let's try to change our `role` to `admin`/`administrator` to gain higher privileges. Unfortunately, without knowing a valid `role` name, we get `Invalid role` in the HTTP response, and our `role` does not update:

![](Pasted%20image%2020250317114553.png)

So, `all of our attempts appear to have failed`. We cannot create or delete users as we cannot change our `role`. We cannot change our own `uid`, as there are preventive measures on the back-end that we cannot control, nor can we change another user's details for the same reason. `So, is the web application secure against IDOR attacks?`.

So far, we have only been testing the `IDOR Insecure Function Calls`. However, we have not tested the API's `GET` request for `IDOR Information Disclosure Vulnerabilities`. If there was no robust access control system in place, we might be able to read other users' details, which may help us with the previous attacks we attempted.

`Try to test the API against IDOR Information Disclosure vulnerabilities by attempting to get other users' details with GET requests`. If the API is vulnerable, we may be able to leak other users' details and then use this information to complete our IDOR attacks on the function calls.

>[!Example]
>The Academy's exercise for this section

I captured the update profile request with CAIDO:

![](Pasted%20image%2020250317115511.png)

As the exercise says, I'll try to change the request method to `GET` to get personal details of other users:

![](Pasted%20image%2020250317115608.png)

It works with me, so now I'll try other users ids until I find an admin:

![](Pasted%20image%2020250317120107.png)

Got the id `10` which has `staff_admin` role. So now I'll try to modify my role to it:

![](Pasted%20image%2020250317120231.png)

It worked! So now I'll try to read the details of user with id `5`:

![](Pasted%20image%2020250317120346.png)

# Chaining IDOR Vulnerabilities

Usually, a `GET` request to the API endpoint should return the details of the requested user, so we may try calling it to see if we can retrieve our user's details. We also notice that after the page loads, it fetches the user details with a `GET` request to the same API endpoint:

![](Pasted%20image%2020250317120408.png)

As mentioned in the previous section, the only form of authorization in our HTTP requests is the `role=employee` cookie, as the HTTP request does not contain any other form of user-specific authorization, like a JWT token, for example. Even if a token did exist, unless it was being actively compared to the requested object details by a back-end access control system, we may still be able to retrieve other users' details.

## Information Disclosure

Let's send a `GET` request with another `uid`:

![](Pasted%20image%2020250317120425.png)

As we can see, this returned the details of another user, with their own `uuid` and `role`, confirming an `IDOR Information Disclosure vulnerability`:

```json
{
    "uid": "2",
    "uuid": "4a9bd19b3b8676199592a346051f950c",
    "role": "employee",
    "full_name": "Iona Franklyn",
    "email": "i_franklyn@employees.htb",
    "about": "It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it."
}
```

This provides us with new details, most notably the `uuid`, which we could not calculate before, and thus could not change other users' details.

## Modifying Other Users' Details

Now, with the user's `uuid` at hand, we can change this user's details by sending a `PUT` request to `/profile/api.php/profile/2` with the above details along with any modifications we made, as follows:

![](Pasted%20image%2020250317120442.png)

We don't get any access control error messages this time, and when we try to `GET` the user details again, we see that we did indeed update their details:

![](Pasted%20image%2020250317120450.png)

In addition to allowing us to view potentially sensitive details, the ability to modify another user's details also enables us to perform several other attacks. One type of attack is `modifying a user's email address` and then requesting a password reset link, which will be sent to the email address we specified, thus allowing us to take control over their account. Another potential attack is `placing an XSS payload in the 'about' field`, which would get executed once the user visits their `Edit profile` page, enabling us to attack the user in different ways.

## Chaining Two IDOR Vulnerabilities

Since we have identified an IDOR Information Disclosure vulnerability, we may also enumerate all users and look for other `roles`, ideally an admin role. `Try to write a script to enumerate all users, similarly to what we did previously`.

Once we enumerate all users, we will find an admin user with the following details:

```json
{
    "uid": "X",
    "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
    "role": "web_admin",
    "full_name": "administrator",
    "email": "webadmin@employees.htb",
    "about": "HTB{FLAG}"
}
```

We may modify the admin's details and then perform one of the above attacks to take over their account. However, as we now know the admin role name (`web_admin`), we can set it to our user so we can create new users or delete current users. To do so, we will intercept the request when we click on the `Update profile` button and change our role to `web_admin`:

![](Pasted%20image%2020250317120509.png)

This time, we do not get the `Invalid role` error message, nor do we get any access control error messages, meaning that there are no back-end access control measures to what roles we can set for our user. If we `GET` our user details, we see that our `role` has indeed been set to `web_admin`:

```json
{
    "uid": "1",
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "web_admin",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

Now, we can refresh the page to update our cookie, or manually set it as `Cookie: role=web_admin`, and then intercept the `Update` request to create a new user and see if we'd be allowed to do so:

![](Pasted%20image%2020250317120523.png)

We did not get an error message this time. If we send a `GET` request for the new user, we see that it has been successfully created:

![](Pasted%20image%2020250317120530.png)

By combining the information we gained from the `IDOR Information Disclosure vulnerability` with an `IDOR Insecure Function Calls` attack on an API endpoint, we could modify other users' details and create/delete users while bypassing various access control checks in place. On many occasions, the information we leak through IDOR vulnerabilities can be utilized in other attacks, like IDOR or XSS, leading to more sophisticated attacks or bypassing existing security mechanisms.

With our new `role`, we may also perform mass assignments to change specific fields for all users, like placing XSS payloads in their profiles or changing their email to an email we specify. `Try to write a script that changes all users' email to an email you choose.`. You may do so by retrieving their `uuids` and then sending a `PUT` request for each with the new email.

>[!Example]
>The Academy's exercise for this section

In the previous example I explained how I got the `staff_admin` role and found out who as the admin (id `10`), so now I'll just modify his email to get the flag:

![](Pasted%20image%2020250317121210.png)

![](Pasted%20image%2020250317121305.png)

![](Pasted%20image%2020250317121434.png)

# Intro to XXE

`XML External Entity (XXE) Injection` vulnerabilities occur when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions. XXE vulnerabilities can cause considerable damage to a web application and its back-end server, from disclosing sensitive files to shutting the back-end server down, which is why it is considered one of the [Top 10 Web Security Risks](https://owasp.org/www-project-top-ten/) by OWASP.

## XML

`Extensible Markup Language (XML)` is a common markup language (similar to HTML and SGML) designed for flexible transfer and storage of data and documents in various types of applications. XML is not focused on displaying data but mostly on storing documents' data and representing data structures. XML documents are formed of element trees, where each element is essentially denoted by a `tag`, and the first element is called the `root element`, while other elements are `child elements`.

Here we see a basic example of an XML document representing an e-mail document structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```

The above example shows some of the key elements of an XML document, like:

|Key|Definition|Example|
|---|---|---|
|`Tag`|The keys of an XML document, usually wrapped with (`<`/`>`) characters.|`<date>`|
|`Entity`|XML variables, usually wrapped with (`&`/`;`) characters.|`&lt;`|
|`Element`|The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag.|`<date>01-01-2022</date>`|
|`Attribute`|Optional specifications for any element that are stored in the tags, which may be used by the XML parser.|`version="1.0"`/`encoding="UTF-8"`|
|`Declaration`|Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it.|`<?xml version="1.0" encoding="UTF-8"?>`|

Furthermore, some characters are used as part of an XML document structure, like `<`, `>`, `&`, or `"`. So, if we need to use them in an XML document, we should replace them with their corresponding entity references (e.g. `&lt;`, `&gt;`, `&amp;`, `&quot;`). Finally, we can write comments in XML documents between `<!--` and `-->`, similar to HTML documents.

## XML DTD

`XML Document Type Definition (DTD)` allows the validation of an XML document against a pre-defined document structure. The pre-defined document structure can be defined in the document itself or in an external file. The following is an example DTD for the XML document we saw earlier:

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

As we can see, the DTD is declaring the root `email` element with the `ELEMENT` type declaration and then denoting its child elements. After that, each of the child elements is also declared, where some of them also have child elements, while others may only contain raw data (as denoted by `PCDATA`).

The above DTD can be placed within the XML document itself, right after the `XML Declaration` in the first line. Otherwise, it can be stored in an external file (e.g. `email.dtd`), and then referenced within the XML document with the `SYSTEM` keyword, as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

It is also possible to reference a DTD through a URL, as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

This is relatively similar to how HTML documents define and reference JavaScript and CSS scripts.

## XML Entities

We may also define custom entities (i.e. XML variables) in XML DTDs, to allow refactoring of variables and reduce repetitive data. This can be done with the use of the `ENTITY` keyword, which is followed by the entity name and its value, as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

Once we define an entity, it can be referenced in an XML document between an ampersand `&` and a semi-colon `;` (e.g. `&company;`). Whenever an entity is referenced, it will be replaced with its value by the XML parser. Most interestingly, however, we can `reference External XML Entities` with the `SYSTEM` keyword, which is followed by the external entity's path, as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

>[!Note]
>We may also use the `PUBLIC` keyword instead of `SYSTEM` for loading external resources, which is used with publicly declared entities and standards, such as a language code (`lang="en"`). In this module, we'll be using `SYSTEM`, but we should be able to use either in most cases.

This works similarly to internal XML entities defined within documents. When we reference an external entity (e.g. `&signature;`), the parser will replace the entity with its value stored in the external file (e.g. `signature.txt`). `When the XML file is parsed on the server-side, in cases like SOAP (XML) APIs or web forms, then an entity can reference a file stored on the back-end server, which may eventually be disclosed to us when we reference the entity`.

In the next section, we will see how we can use External XML Entities to read local files or even perform more malicious actions.

