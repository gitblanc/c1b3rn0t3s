---
title: JWT tokens 🐧
---

# The JWT format

A JSON Web Token consists of a header, payload, and signature in base64url encoding, separated by dots, as follows:

```
HEADER.PAYLOAD.SIGNATURE
```

Let’s take apart the following real token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJuYW1lIjoiSm9obiBEb2UiLCJ1c2VyX25hbWUiOiJqb2huLmRvZSIsImlzX2FkbWluIjpmYWxzZX0.
fSppjHFaqlNcpK1Q8VudRD84YIuhqFfA67XkLam0_aY
```

The header contains metadata about the token, such as the algorithm used for the signature and the type of the token (which is simply JWT). For this example, the header before encoding is:

```
{
  "alg": "HS256",
  "typ": "JWT"
}
```

The payload contains information (claims) about the entity (user) that is going to be verified by the application. Our sample token includes the following claims:

```
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}
```

Finally, to generate the signature, we have to apply base64url encoding to the header, dot, and payload, and then sign the whole thing using a secret (for symmetric encryption) or a private key (for asymmetric encryption), depending on the algorithm specified in the header. We’ve put `HS256` in the header, which is a symmetric algorithm, so the encoding and signing operation would be:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

This gives us the following signature, which is then appended (after a dot) to the base64url-encoded header and payload:

```
fSppjHFaqlNcpK1Q8VudRD84YIuhqFfA67XkLam0_aY
```

## Common JWT vulnerabilities

JSON Web Tokens were designed to be flexible and future-proof, leaving a lot of room for adaptation to a variety of use cases and requirements – but also a lot of room for mistakes in implementation and use. Here are some typical vulnerabilities that can be introduced when working with JWTs.

### Failing to verify the signature

Many JWT libraries provide one method to decode the token and another to verify it:

- `decode()`: Only decodes the token from base64url encoding without verifying the signature.
- `verify()`: Decodes the token and verifies the signature.

Sometimes developers might mix up these methods. In that case, the signature is never verified and the application will accept any token (in a valid format). Developers might also disable signature verification for testing and then forget to re-enable it. Such mistakes could lead to arbitrary account access or privilege escalation.

For example, let’s say we have the following valid token that is never actually verified:

```
{
  "alg": "HS256",
  "typ": "JWT"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}
```

An attacker could send the following token with an arbitrary signature to obtain escalated privileges:

```
{
  "alg": "HS256",
  "typ": "JWT"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": true
}
```

### Allowing the `None` algorithm

The JWT standard accepts many different types of algorithms to generate a signature:

- RSA
- HMAC
- Elliptic Curve
- None

The `None` algorithm specifies that the token is not signed. If this algorithm is permitted, we can bypass signature checking by changing an existing algorithm to `None` and stripping the signature. Let’s start with our expected token:

```
{
  "alg": "HS256",
  "typ": "JWT"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}.SIGNATURE
```

Encoded and signed, the token will look like this (signature in bold):

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJuYW1lIjoiSm9obiBEb2UiLCJ1c2VyX25hbWUiOiJqb2huLmRvZSIsImlzX2FkbWluIjpmYWxzZX0.
fSppjHFaqlNcpK1Q8VudRD84YIuhqFfA67XkLam0_aY
```

If `None` is permitted as the algorithm value, an attacker can simply use it to replace the valid algorithm and then get rid of the signature:

```
{
  "alg": "None",
  "typ": "JWT"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": true
}.
```

Though now unsigned, the modified token will be accepted by the application:

```
eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.
eyJuYW1lIjoiSm9obiBEb2UiLCJ1c2VyX25hbWUiOiJqb2huLmRvZSIsImlzX2FkbWluIjp0cnVlfQ.
```

That is why it is important to not accept tokens with `None`, `none`, `NONE`, `nOnE`, or any other case variations in the `alg` header.

### Algorithm confusion

JWT accepts both symmetric and asymmetric encryption algorithms. Depending on the encryption type, you need to use either a shared secret or a public-private key pair:

|                      |                      |                        |
| -------------------- | -------------------- | ---------------------- |
| **Algorithm**        | **Key used to sign** | **Key used to verify** |
| **Asymmetric (RSA)** | Private key          | Public key             |
| **Symmetric (HMAC)** | Shared secret        | Shared secret          |

When an application uses asymmetric encryption, it can openly publish its public key and keep the private key secret. This allows the application to sign tokens using its private key and anyone can verify this token using its public key. The algorithm confusion vulnerability arises when an application does not check whether the algorithm of the received token matches the expected algorithm.

In many JWT libraries, the method to verify the signature is:

- `verify(token, secret)` – if the token is signed with HMAC
- `verify(token, publicKey)` – if the token is signed with RSA or similar

Unfortunately, in some libraries, this method by itself does not check whether the received token is signed using the application’s expected algorithm. That’s why in the case of HMAC this method will treat the second argument as a shared secret and in the case of RSA as a public key.

If the public key is accessible within the application, an attacker can forge malicious tokens by:

1. Changing the algorithm of the token to HMAC
2. Tampering with the payload to get the desired outcome
3. Signing the malicious token with the public key found in the application
4. Sending the JWT back to the application

The application expects RSA encryption, so when an attacker supplies HMAC instead, the `verify()` method will treat the public key as an HMAC shared secret and use symmetric rather than asymmetric encryption. This means that the token will be signed using the application’s non-secret public key and then verified using the same public key.

To avoid this vulnerability, applications must check if the algorithm of the received token is the expected one before they pass the token to the `verify()` method.

### Using trivial secrets

With symmetric encryption, a cryptographic signature is only as strong as the secret used. If an application uses a weak secret, the attacker can simply brute-force it by trying different secret values until the original signature matches the forged one. Having discovered the secret, the attacker can use it to generate valid signatures for malicious tokens. To avoid this vulnerability, strong secrets must always be used with symmetric encryption.

## Attacks against JSON Web Tokens

### `kid` parameter injections

The JWT header can contain the Key Id parameter `kid`. It is often used to retrieve the key from a database or filesystem. The application verifies the signature using the key obtained through the `kid` parameter. If the parameter is injectable, it can open the way to signature bypass or even attacks such as [RCE](https://www.invicti.com/learn/remote-code-execution-rce/), [SQLi](https://www.invicti.com/learn/sql-injection-sqli/), and [LFI](https://www.invicti.com/learn/local-file-inclusion-lfi/).

To see this in action, let’s start with the following valid token:

```
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}
```

If the `kid` parameter is vulnerable to command injection, the following modification might lead to remote code execution:

```
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1|/usr/bin/uname"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}
```

### `kid` parameter injection + directory traversal = signature bypass

If an application uses the `kid` parameter to retrieve the key from the filesystem, it might be vulnerable to [directory traversal](https://www.invicti.com/learn/directory-traversal-path-traversal/). Then an attacker can force the application to use a file whose value the attacker can predict as a key for verification. This can be done using any static file within the application. Knowing the key file value, the attacker can craft a malicious token and sign it using the known key.

Continuing with the previous JWT example, an attacker might try to insert `/dev/null` as the key source to force the application to use an empty key:

```
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": true
}
```

If directory traversal to `/dev/null` succeeds, the attacker will be able to sign a malicious token using an empty string. The same technique can be used with known static files, for example CSS files.

### `kid` parameter injection + SQL injection = signature bypass

If an application uses the `kid` parameter to retrieve the key from a database, it might be vulnerable to [SQL injection](https://www.invicti.com/learn/sql-injection-sqli/). If successful, an attacker can control the value returned to the `kid` parameter from an SQL query and use it to sign a malicious token.

Again using the same example token, let’s say the application uses the following vulnerable SQL query to get its JWT key via the `kid` parameter:

```
SELECT key FROM keys WHERE key='key1'
```

An attacker can then inject a `UNION SELECT` statement into the `kid` parameter to control the key value:

```
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "xxxx' UNION SELECT 'aaa"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": true
}
```

If SQL injection succeeds, the application will use the following query to retrieve the signature key:

```
SELECT key FROM keys WHERE key='xxxx' UNION SELECT 'aaa'
```

This query returns `aaa` into the `kid` parameter, allowing the attacker to sign a malicious token simply with `aaa`.

To avoid these and other injection attacks, applications should always sanitize the value of the `kid` parameter before using it.

### Attacks using the `jku` header

In the JWT header, developers can also use the `jku` parameter to specify the [JSON Web Key Set URL](https://tools.ietf.org/html/rfc7515#section-4.1.2). This parameter indicates where the application can find the [JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517) used to verify the signature – basically the public key in JSON format.

To illustrate, let’s take the following JWT that uses the `jku` parameter to specify the public key:

```
{
  "alg": "RS256",
  "typ": "JWT",
  "jku":"https://example.com/key.json"
}.
{
  "name": "John Doe",
  "user_name": "john.doe",
  "is_admin": false
}
```

The specified `key.json` file might look something like:

```
{
  "kty": "RSA",
  "n": "-4KIwb83vQMH0YrzE44HppWvyNYmyuznuZPKWFt3e0xmdi-WcgiQZ1TC...RMxYC9lr4ZDp-M0",
  "e": "AQAB"
}
```

The application verifies the signature using the JSON Web Key retrieved based on the `jku` header value:

![JSON Web Token verification using a legitimate JKU](https://cdn.invicti.com/statics/img/blogposts/JWT-Attacks_Scenario1.png)

Now for the attack. An attacker can change the `jku` parameter value to point to their own JWK instead of the valid one. If accepted, this allows the attacker to sign malicious tokens using their own private key. After the malicious token is sent, the application will fetch the attacker’s JWK and use it to verify the signature:

![JSON Web Token verification using a malicious JKU](https://cdn.invicti.com/statics/img/blogposts/JWT-Attacks_Scenario2.png)

To prevent such attacks, applications typically use URL filtering. Unfortunately, there are ways for attackers to bypass such filtering, including:

- Using `https://trusted` (for example `https://trusted@attacker.com/key.json`), if the application checks for URLs starting with `trusted`
- Using URL fragments with the `#` character
- Using the DNS naming hierarchy
- Chaining with an [open redirect](https://www.invicti.com/learn/open-redirect-open-redirection/)
- Chaining with a header Injection
- Chaining with SSRF

For this reason, it is very important for the application to whitelist permitted hosts and have correct URL filtering in place. Beyond that, the application must not have other vulnerabilities that an attacker might chain to bypass URL filtering.

# Encoder and decoder

- Encoder and decoder:
  - https://jwt.io/
  - https://token.dev/
