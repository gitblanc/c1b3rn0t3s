---
title: Broken Authentication Theory 🐛
tags:
  - Theory
  - CBBH
---
> *Credits to [HTB Academy](https://academy.hackthebox.com/module/80/section/767)*

# What is Authentication

Authentication is defined as "The process of verifying a claim that a system entity or system resource has a certain attribute value" in [RFC 4949](https://datatracker.ietf.org/doc/rfc4949/). In information security, authentication is the process of confirming an entity's identity, ensuring they are who they claim to be. On the other hand, authorization is an "approval that is granted to a system entity to access a system resource"; while this module will not cover authorization deeply, understanding the major difference between it and authentication is vital to approach this module with the appropriate mindset.

![](Pasted%20image%2020250314094918.png)

The most widespread authentication method in web applications is `login forms`, where users enter their username and password to prove their identity. Login forms can be found on many websites including email providers, online banking, and HTB Academy:

![](Pasted%20image%2020250314094926.png)

Authentication is probably the most widespread security measure and the first defense against unauthorized access. As web application penetration testers, we aim to verify if authentication is implemented securely. This module will focus on various exploitation methods and techniques against login forms to bypass authentication and gain unauthorized access.

## Common Authentication Methods

Information technology systems can implement different authentication methods. Typically, they can be divided into the following three major categories:

- Knowledge-based authentication
- Ownership-based authentication
- Inherence-based authentication

#### Knowledge

Authentication based on knowledge factors relies on something that the user knows to prove their identity. The user provides information such as passwords, passphrases, PINs, or answers to security questions.

#### Ownership

Authentication based on ownership factors relies on something the user possesses. The user proves their identity by proving the ownership of a physical object or device, such as ID cards, security tokens, or smartphones with authentication apps. 

#### Inherence

Lastly, authentication based on inherence factors relies on something the user is or does. This includes biometric factors such as fingerprints, facial patterns, and voice recognition, or signatures. Biometric authentication is highly effective since biometric traits are inherently tied to an individual user.

|Knowledge|Ownership|Inherence|
|---|---|---|
|Password|ID card|Fingerprint|
|PIN|Security Token|Facial Pattern|
|Answer to Security Question|Authenticator App|Voice Recognition|

## Single-Factor Authentication vs Multi-Factor Authentication

Single-factor authentication relies solely on a single methods. For instance, password authentication solely relies on knowledge of the password. As such, it is a single-factor authentication method.

On the other hand, multi-factor authentication (MFA) involves multiple authentication methods. For instance, if a web application requires a password and a time-based one-time password (TOTP), it relies on knowledge of the password and ownership of the TOTP device for authentication. In the particular case when exactly two factors are required, MFA is commonly referred to as 2-factor authentication (2FA).

# Attacks on Authentication

We will categorize attacks on authentication based on the three types of authentication methods discussed in the previous section.

## Attacking Knowledge-based Authentication

Knowledge-based authentication is prevalent and comparatively easy to attack. As such, we will mainly focus on knowledge-based authentication in this module. This authentication method suffers from reliance on static personal information that can be potentially obtained, guessed, or brute-forced. As cyber threats evolve, attackers have become adept at exploiting weaknesses in knowledge-based authentication systems through various means, including social engineering and data breaches.

## Attacking Ownership-based Authentication

One significant advantage of ownership-based authentication is its resistance to many common cyber threats, such as phishing or password-guessing attacks. Authentication methods based on physical possession, such as hardware tokens or smart cards, are inherently more secure. This is because physical items are more difficult for attackers to acquire or replicate compared to information that can be phished, guessed, or obtained through data breaches. However, challenges such as the cost and logistics of distributing and managing physical tokens or devices can sometimes limit the widespread adoption of ownership-based authentication, particularly in large-scale deployments.

Furthermore, systems using ownership-based authentication can be vulnerable to physical attacks, such as stealing or cloning the object, as well as cryptographic attacks on the algorithm it uses. For instance, cloning objects such as NFC badges in public places, like public transportation or cafés, is a feasible attack vector.

## Attacking Inherence-based Authentication

Inherence-based authentication provides convenience and user-friendliness. Users don't need to remember complex passwords or carry physical tokens; they simply provide biometric data, such as a fingerprint or facial scan, to gain access. This streamlined authentication process enhances user experience and reduces the likelihood of security breaches resulting from weak passwords or stolen tokens. However, inherence-based authentication systems must address concerns regarding privacy, data security, and potential biases in biometric recognition algorithms to ensure widespread adoption and trust among users.

However, inherence-based authentication systems can be irreversibly compromised in the event of a data breach. This is because users cannot change their biometric features, such as fingerprints. For instance, in 2019, threat actors [breached](https://www.vpnmentor.com/blog/report-biostar2-leak/) a company that builds biometric smart locks, which are managed via a mobile or web application, to identify authorized users using their fingerprints and facial patterns. The breach exposed all fingerprints and facial patterns, in addition to usernames and passwords, grants, and registered users' addresses. While affected users could have easily changed their passwords to mitigate this data breach if the smart locks had used knowledge-based authentication, this was not possible since they utilized inherence-based authentication.

# Enumerating Users

User enumeration vulnerabilities arise when a web application responds differently to registered/valid and invalid inputs for authentication endpoints. User enumeration vulnerabilities frequently occur in functions based on the user's username, such as user login, user registration, and password reset.

Web developers frequently overlook user enumeration vectors, assuming that information such as usernames is not confidential. However, usernames can be considered confidential if they are the primary identifier required for authentication in web applications. Moreover, users tend to use the same username across various services other than web applications, including FTP, RDP, and SSH. Since many web applications allow us to identify usernames, we can enumerate valid usernames and use them for further attacks on authentication. This is often possible because web applications typically consider a username or user's email address as the primary identifier of users.

## User Enumeration Theory

Protection against username enumeration attacks can have an impact on user experience. A web application revealing whether a username exists may help a legitimate user identify that they failed to type their username correctly. Still, the same applies to an attacker trying to determine valid usernames. Even well-known and mature applications, like WordPress, allow for user enumeration by default. For instance, if we attempt to login to WordPress with an invalid username, we get the following error message:

![](Pasted%20image%2020250314100011.png)

On the other hand, a valid username results in a different error message:

![](Pasted%20image%2020250314100018.png)

As we can see, user enumeration can be a security risk that a web application deliberately accepts to provide a service. As another example, consider a chat application enabling users to chat with others. This application might provide a functionality to search for users by their username. While this functionality can be used to enumerate all users on the platform, it is also essential to the service provided by the web application. As such, user enumeration is not always a security vulnerability. Nevertheless, it should be avoided if possible as a defense-in-depth measure. For instance, in our example web application user enumeration can be avoided by not using the username during login but an email address instead.

## Enumerating Users via Differing Error Messages

To obtain a list of valid users, an attacker typically requires a wordlist of usernames to test. Usernames are often far less complicated than passwords. They rarely contain special characters when they are not email addresses. A list of common users allows an attacker to narrow the scope of a brute-force attack or carry out targeted attacks (leveraging OSINT) against support employees or users. Also, a common password could be easily sprayed against valid accounts, often leading to a successful account compromise. Further ways of harvesting usernames are crawling a web application or using public information, such as company profiles on social networks. A good starting point is the wordlist collection [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Usernames). 

When we attempt to log in to the lab with an invalid username such as `abc`, we can see the following error message:

![](Pasted%20image%2020250314100031.png)

On the other hand, when we attempt to log in with a registered user such as `htb-stdnt` and an invalid password, we can see a different error:

![](Pasted%20image%2020250314100053.png)

Let us exploit this difference in error messages returned and use SecLists's wordlist `xato-net-10-million-usernames.txt` to enumerate valid users with `ffuf`. We can specify the wordlist with the `-w` parameter, the POST data with the `-d` parameter, and the keyword `FUZZ` in the username to fuzz valid users. Finally, we can filter out invalid users by removing responses containing the string `Unknown user`:

```shell
gitblanc@htb[/htb]$ ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"

<SNIP>

[Status: 200, Size: 3271, Words: 754, Lines: 103, Duration: 310ms]
    * FUZZ: consuelo
```

We successfully identified the valid username `consuelo`. We could now proceed by attempting to brute-force the user's password, as we will discuss in the following section.

## User Enumeration via Side-Channel Attacks

While differences in the web application's response are the simplest and most obvious way to enumerate valid usernames, we might also be able to enumerate valid usernames via side channels. Side-channel attacks do not directly target the web application's response but rather extra information that can be obtained or inferred from the response. An example of a side channel is the response timing, i.e., the time it takes for the web application's response to reach us. Suppose a web application does database lookups only for valid usernames. In that case, we might be able to measure a difference in the response time and enumerate valid usernames this way, even if the response is the same. User enumeration based on response timing is covered in the [Whitebox Attacks](https://academy.hackthebox.com/module/details/205) module.

>[!Example]
>The Academy's exercise for this section:

If I try combination `test:test` I get this error:

![](Pasted%20image%2020250314101026.png)

Then if I try `htb-stdnt:wrong` I get this one that contains "Invalid credentials":

![](Pasted%20image%2020250314101112.png)

So I can try to brute force to search for other users filtering by the petitions that doesn't contain "Unknown user":

```shell
ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -u http://94.237.53.146:33427/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"

[redacted]
cookster     [Status: 200, Size: 3271, Words: 754, Lines: 103, Duration: 701ms]
```

# Brute-Forcing Passwords

After successfully identifying valid users, password-based authentication relies on the password as a sole measure for authenticating the user. Since users tend to select an easy-to-remember password, attackers may be able to guess or brute-force it.

While password brute-forcing is not the focus of this module (it is covered in more detail in other modules referenced at the end of this section), we will still discuss an example of brute-forcing a password-based login form, as it is one of the most common examples of broken authentication.

## Brute-Forcing Passwords

Passwords remain one of the most common online authentication methods, yet they are plagued with many issues. One prominent issue is password reuse, where individuals use the same password across multiple accounts. This practice poses a significant security risk because if one account is compromised, attackers can potentially gain access to other accounts with the same credentials. This enables an attacker who obtained a list of passwords from a password leak to try the same passwords on other web applications ("Password Spraying"). Another issue is weak passwords based on typical phrases, dictionary words, or simple patterns. These passwords are vulnerable to brute-force attacks, where automated tools systematically try different combinations until they find the correct one, compromising the account's security.

When accessing the sample web application, we can see the following information on the login page:

![](Pasted%20image%2020250314101900.png)

The success of a brute-force attack entirely depends on the number of attempts an attacker can perform and the amount of time the attack takes. As such, ensuring that a good wordlist is used for the attack is crucial. If a web application enforces a password policy, we should ensure that our wordlist only contains passwords that match the implemented password policy. Otherwise, we are wasting valuable time with passwords that users cannot use on the web application, as the password policy does not allow them.

For instance, the popular password wordlist `rockyou.txt` contains more than 14 million passwords:

```shell
gitblanc@htb[/htb]$ wc -l /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt

14344391 /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```

Now, we can use `grep` to match only those passwords that match the password policy implemented by our target web application, which brings down the wordlist to about 150,000 passwords, a reduction of about 99%:

```shell
gitblanc@htb[/htb]$ grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt

gitblanc@htb[/htb]$ wc -l custom_wordlist.txt

151647 custom_wordlist.txt
```

To start brute-forcing passwords, we need a user or a list of users to target. Using the techniques covered in the previous section, we determine that admin is a username for a valid user, therefore, we will attempt brute-forcing its password.

However, first, let us intercept the login request to know the names of the POST parameters and the error message returned within the response:

Upon providing an incorrect username, the login response contains the message (substring) "Invalid username", therefore, we can use this information to build our `ffuf` command to brute-force the user's password:

```shell
gitblanc@htb[/htb]$ ffuf -w ./custom_wordlist.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username"

<SNIP>

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 4764ms]
    * FUZZ: Buttercup1
```

After some time, we can successfully obtain the admin user's password, enabling us to log in to the web application:

![](Pasted%20image%2020250314101936.png)

For more details on creating custom wordlists and attacking password-based authentication, check out the [Cracking Passwords with Hashcat](https://academy.hackthebox.com/module/details/20) and [Password Attacks](https://academy.hackthebox.com/module/details/147) modules. Further details on brute-forcing different variations of web application logins are provided in the [Login Brute Forcing](https://academy.hackthebox.com/module/details/57) module.

>[!Example]
>The Academy's exercise for this section

![](Pasted%20image%2020250314102501.png)

So I'll match the policy to `rockyou.txt`:

```shell
grep '[[:upper:]]' /usr/share/wordlists/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
```

If I try an invalid combination I get this error:

![](Pasted%20image%2020250314102822.png)

So I'll use it in **ffuf**:

```shell
ffuf -w ./custom_wordlist.txt -u http://83.136.251.75:57301/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username" -s

[redacted]
Ramirez120992
```

# Brute-Forcing Password Reset Tokens

Many web applications implement a password-recovery functionality if a user forgets their password. This password-recovery functionality typically relies on a one-time reset token, which is transmitted to the user, for instance, via SMS or E-Mail. The user can then authenticate using this token, enabling them to reset their password and access their account.

As such, a weak password-reset token may be brute-forced or predicted by an attacker to take over a victim's account.

## Identifying Weak Reset Tokens

Reset tokens (in the form of a code or temporary password) are secret data generated by an application when a user requests a password reset. The user can then change their password by presenting the reset token.

Since password reset tokens enable an attacker to reset an account's password without knowledge of the password, they can be leveraged as an attack vector to take over a victim's account if implemented incorrectly. Password reset flows can be complicated because they consist of several sequential steps; a basic password reset flow is shown below:

![](Pasted%20image%2020250314103123.png)

To identify weak reset tokens, we typically need to create an account on the target web application, request a password reset token, and then analyze it. In this example, let us assume we have received the following password reset e-mail:

```
Hello,

We have received a request to reset the password associated with your account. To proceed with resetting your password, please follow the instructions below:

1. Click on the following link to reset your password: Click

2. If the above link doesn't work, copy and paste the following URL into your web browser: http://weak_reset.htb/reset_password.php?token=7351

Please note that this link will expire in 24 hours, so please complete the password reset process as soon as possible. If you did not request a password reset, please disregard this e-mail.

Thank you.
```

As we can see, the password reset link contains the reset token in the GET-parameter `token`. In this example, the token is `7351`. Given that the token consists of only a 4-digit number, there can be only `10,000` possible values. This allows us to hijack users' accounts by requesting a password reset and then brute-forcing the token.

## Attacking Weak Reset Tokens

We will use `ffuf` to brute-force all possible reset tokens. First, we need to create a wordlist of all possible tokens from `0000` to `9999`, which we can achieve with `seq`:

```shell
gitblanc@htb[/htb]$ seq -w 0 9999 > tokens.txt
```

The `-w` flag pads all numbers to the same length by prepending zeroes, which we can verify by looking at the first few lines of the output file:

```shell
gitblanc@htb[/htb]$ head tokens.txt

0000
0001
0002
0003
0004
0005
0006
0007
0008
0009
```

Assuming that there are users currently in the process of resetting their passwords, we can try to brute-force all active reset tokens. If we want to target a specific user, we should send a password reset request for that user first to create a reset token. We can then specify the wordlist in `ffuf` to brute-force all active reset-tokens:

```shell
gitblanc@htb[/htb]$ ffuf -w ./tokens.txt -u http://weak_reset.htb/reset_password.php?token=FUZZ -fr "The provided token is invalid"

<SNIP>

[Status: 200, Size: 2667, Words: 538, Lines: 90, Duration: 1ms]
    * FUZZ: 6182
```

By specifying the reset token in the GET-parameter `token` in the `/reset_password.php` endpoint, we can reset the password of the corresponding account, enabling us to take over the account:

![](Pasted%20image%2020250314103155.png)

>[!Example]
>The Academy's exercise for this section

I'll generate a worlist of 4-digit tokens:

```shell
seq -w 0 9999 > tokens.txt
```

Then I tested for an invalid token to get the error message:

![](Pasted%20image%2020250314104420.png)

Now I'll fuzz the tokens:

```shell
ffuf -w ./tokens.txt -u http://94.237.54.44:45392/reset_password.php?token=FUZZ -fr "The provided token is invalid"

[redacted]
7048       [Status: 200, Size: 2920, Words: 596, Lines: 92, Duration: 45ms]
```

![](Pasted%20image%2020250314104557.png)

![](Pasted%20image%2020250314104616.png)

# Brute-Forcing 2FA Codes

Two-factor authentication (2FA) provides an additional layer of security to protect user accounts from unauthorized access. Typically, this is achieved by combining knowledge-based authentication (password) with ownership-based authentication (the 2FA device). However, 2FA can also be achieved by combining any other two of the major three authentication categories we discussed previously. Therefore, 2FA makes it significantly more difficult for attackers to access an account even if they manage to obtain the user's credentials. By requiring users to provide a second form of authentication, such as a one-time code generated by an authenticator app or sent via SMS, 2FA mitigates the risk of unauthorized access. This extra layer of security significantly enhances the overall security posture of an account, reducing the likelihood of successful account breaches.

## Attacking Two-Factor Authentication (2FA)

One of the most common 2FA implementations relies on the user's password and a time-based one-time password (TOTP) provided to the user's smartphone by an authenticator app or via SMS. These TOTPs typically consist only of digits, making them potentially guessable if the length is insufficient and the web application does not implement measures against successive submission of incorrect TOTPs. For our lab, we will assume that we obtained valid credentials in a prior phishing attack: `admin:admin`. However, the web application is secured with 2FA, as we can see after logging in with the obtained credentials:

![](Pasted%20image%2020250314105044.png)

The message in the web application shows that the TOTP is a 4-digit code. Since there are only `10,000` possible variations, we can easily try all possible codes. To achieve this, let us first take a look at the corresponding request to prepare our parameters for `ffuf`:

![](Pasted%20image%2020250314105051.png)

As we can see, the TOTP is passed in the `otp` POST parameter. Furthermore, we need to specify our session token in the `PHPSESSID` cookie to associate the TOTP with our authenticated session. Just like in the previous section, we can generate a wordlist containing all 4-digit numbers from `0000` to `9999` like so:

```shell
gitblanc@htb[/htb]$ seq -w 0 9999 > tokens.txt
```

Afterward, we can use the following command to brute-force the correct TOTP by filtering out responses containing the `Invalid 2FA Code` error message:

```shell
gitblanc@htb[/htb]$ ffuf -w ./tokens.txt -u http://bf_2fa.htb/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93" -d "otp=FUZZ" -fr "Invalid 2FA Code"

<SNIP>
[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 648ms]
    * FUZZ: 6513
[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 635ms]
    * FUZZ: 6514

<SNIP>
[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1ms]
    * FUZZ: 9999
```

As we can see, we get many hits. That is because our session successfully passed the 2FA check after we had supplied the correct TOTP. Since `6513` was the first hit, we can assume this was the correct TOTP. Afterward, our session is marked as fully authenticated, so all requests using our session cookie are redirected to `/admin.php`. To access the protected page, we can simply access the endpoint `/admin.php` in the web browser and see that we successfully passed 2FA.

>[!Example]
>The Academy's exercise for this section

With `admin:admin` we get the following 2FA page:

![](Pasted%20image%2020250314105550.png)

As it says it's a four digit code, we can brute force it by generating a wordlist and then trying it with **ffuf**:

```shell
seq -w 0 9999 > tokens.txt

ffuf -w ./tokens.txt -u http://94.237.55.96:51308/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=au8nm6kethu78o6kqkge9ti5g3" -d "otp=FUZZ" -fr "Invalid 2FA Code"

[redacted]
0028
```

![](Pasted%20image%2020250314105846.png)

# Weak Brute-Force Protection

After understanding different brute-force attacks on authentication mechanisms, this section will discuss security mechanisms that thwart brute-forcing and how to potentially bypass them. Among the common types of brute-force protection mechanisms are rate limits and CAPTCHAs.

## Rate Limits

Rate limiting is a crucial technique employed in software development and network management to control the rate of incoming requests to a system or API. Its primary purpose is to prevent servers from being overwhelmed by too many requests at once, prevent system downtime, and prevent brute-force attacks. By limiting the number of requests allowed within a specified time frame, rate limiting helps maintain stability and ensures fair usage of resources for all users. It safeguards against abuse, such as denial-of-service (DoS) attacks or excessive usage by individual clients, by enforcing a maximum threshold on the frequency of requests.

When an attacker conducts a brute-force attack and hits the rate limit, the attack will be thwarted. A rate limit typically increments the response time iteratively until a brute-force attack becomes infeasible or blocks the attacker from accessing the service for a certain amount of time.

A rate limit should only be enforced on an attacker, not regular users, to prevent DoS scenarios. Many rate limit implementation rely on the IP address to identify the attacker. However, in a real-world scenario, obtaining the attacker's IP address might not always be as simple as it seems. For instance, if there are middleboxes such as reverse proxies, load balancers, or web caches, a request's source IP address will belong to the middlebox, not the attacker. Thus, some rate limits rely on HTTP headers such as `X-Forwarded-For` to obtain the actual source IP address.

However, this causes an issue as an attacker can set arbitrary HTTP headers in request, bypassing the rate limit entirely. This enables an attacker to conduct a brute-force attack by randomizing the `X-Forwarded-For` header in each HTTP request to avoid the rate limit. Vulnerabilities like this occur frequently in the real world, for instance, as reported in [CVE-2020-35590](https://nvd.nist.gov/vuln/detail/CVE-2020-35590).

## CAPTCHAs

A `Completely Automated Public Turing test to tell Computers and Humans Apart (CAPTCHA)` is a security measure to prevent bots from submitting requests. By forcing humans to make requests instead of bots or scripts, brute-force attacks become a manual task, making them infeasible in most cases. CAPTCHAs typically present challenges that are easy for humans to solve but difficult for bots, such as identifying distorted text, selecting particular objects from images, or solving simple puzzles. By requiring users to complete these challenges before accessing certain features or submitting forms, CAPTCHAs help prevent automated scripts from performing actions that could be harmful, such as spamming forums, creating fake accounts, or launching brute-force attacks on login pages. While CAPTCHAs serve an essential purpose in deterring automated abuse, they can also present usability challenges for some users, particularly those with visual impairments or specific cognitive disabilities.

From a security perspective, it is essential not to reveal a CAPTCHA's solution in the response, as we can see in the following flawed CAPTCHA implementation:

![](Pasted%20image%2020250314110242.png)

Additionally, tools and browser extensions to solve CAPTCHAs automatically are rising. Many open-source CAPTCHA solvers can be found. In particular, the rise of AI-driven tools provides CAPTCHA-solving capabilities by utilizing powerful image recognition or voice recognition machine learning models.





