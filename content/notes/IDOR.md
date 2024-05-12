---
title: IDOR ㊗️
---
- Credits to [vickieli](https://vickieli.medium.com/intro-to-idor-9048453a3e5d), [vickieli](https://vickieli.medium.com/how-to-find-more-idors-ae2db67c9489)

## What is IDOR?

IDOR stands for “Insecure Direct Object Reference”. And despite the long and sort of intimidating name, IDOR is actually a very simple vulnerability to understand. Essentially, just remember this: IDOR is missing access control.

Time for an example! Let’s say _socialmedia.com_ is a social media site that allows you to chat with others. And when you signed up, you noticed that your user ID on the website is _1234_. This website has a page that allows you to view all your messages with your friends located at the URL: _https://socialmedia.com/messages_. When you click on the "View Your Messages" button located on the homepage, you get redirected to:

```
https://socialmedia.com/messages?user_id=1234
```

Where you can see all your chat messages with your friends on the website. Now, what if you change the URL in the URL bar to the following?

```
https://socialmedia.com/messages?user_id=1233
```

You notice that you can now see all the private messages between another user (Whose user ID is 1233) and all his friends. Woah. What just happened? At this point, you have found an IDOR vulnerability.

The reason you were able to see the messages of user 1233 is that there is no identity check in place before the server returns private info of users. The server was not verifying that you were, in fact, user 1233 or if you are an imposter. It simply returned the information, as you asked.

IDORs happen when access control is not properly implemented, and when the references to data objects (like a file or a database entry) are predictable. In this case, it was very easy to infer that you can retrieve the messages for user 1232 and user 1231

If the website were to use a unique, unpredictable key for each user, like:

```
https://socialmedia.com/messages?user_key=6MT9EalV9F7r9pns0mK1eDAEW
```

Then, the website would not have been vulnerable. Because there is no way for an attacker to guess the value of _user_key_. But instead, the social media site implemented an insecure, direct, object reference.

## How to find IDORs

The reason why IDORs are so hard to prevent is that automatic vulnerability scanners are pretty bad at finding them. ==So the best way to discover IDORs is through a source code review to see if all direct object references are protected by access control.==

Manual testing is also an effective way of testing for IDOR. When manual testing, you should create two different accounts and see if you can access the account info of the first account using the second account.

When testing, remember that **IDORs can appear in** URL parameters, form field parameters, file paths, headers, and cookies. Capture all the requests going between your web client and the web server. Inspect each of these requests carefully. Go through each request and always test the parameters that contain numbers, usernames or IDs.

## Unsuspected places to look for IDORs

### Don't ignore encoded and hashed IDs

When faced with an encoded ID, it might be possible to decode the encoded ID using common encoding schemes.

And if the application is using a hashed/ randomized ID, see if the ID is predictable. Sometimes applications use algorithms that produce insufficient entropy, and as such, the IDs can actually be predicted after careful analysis. In this case, ==try creating a few accounts to analyze how these IDs are created==. You might be able to find a pattern that will allow you to predict IDs belonging to other users.

Additionally, it might be possible to leak random or hashed IDs via another API endpoint, on other public pages in the application (profile page of other users, etc), or in a URL via referer.

For example, once I found an API endpoint that allows users to retrieve detailed direct messages through a hashed conversation ID. The request kinda looks like this:

```html
GET /api_v1/messages?conversation_id=SOME_RANDOM_ID
```

This seems okay at first glance since the _conversation_id_ is a long, random, alphanumeric sequence. But I later found that you can actually find a list of conversations for each user just by using their user ID!

```shell
GET /api_v1/messages?user_id=ANOTHER_USERS_ID
```

This would return a list of _conversation_ids_ belonging to that user. And the _user_id_ is publicly available on each user’s profile page. Therefore, you can read any user’s messages by first obtaining their user_id on their profile page, then retrieving a list of conversation_ids belonging to that user, and finally loading the messages via the API endpoint /api_v1/messages!

### If you can't guess it, try creating it

If the object reference IDs seem unpredictable, see if there is something you can do to manipulate the creation or linking process of these object IDs.

### Offer the application an ID, even if it doesn’t ask for it

If no IDs are used in the application generated request, try adding it to the request. Try appending _id, user_id, message_id_ or other object reference params and see if it makes a difference to the application’s behavior.

For example, if this request displays all your direct messages:

```
GET /api_v1/messages
```

What about this one? Would it display another user’s messages instead?

```
GET /api_v1/messages?user_id=ANOTHER_USERS_ID
```

### HPP (HTTP Parameter Pollution)

HPP vulnerabilities (supplying multiple values for the same parameter) can also lead to IDOR. Applications might not anticipate the user submitting multiple values for the same parameter and by doing so, you might be able to bypass the access control set forth on the endpoint.

Theoretically, it would look like this. If this request fails:

```shell
GET /api_v1/messages?user_id=ANOTHER_USERS_ID
```

Try this:

```
GET /api_v1/messages?user_id=YOUR_USER_ID&user_id=ANOTHER_USERS_ID
```

Or this:

```
GET /api_v1/messages?user_id=ANOTHER_USERS_ID&user_id=YOUR_USER_ID
```

Or provide the parameters as a list:

```
GET /api_v1/messages?user_ids[]=YOUR_USER_ID&user_ids[]=ANOTHER_USERS_ID
```

### Blind IDORs

Sometimes endpoints susceptible to IDOR don’t respond with the leaked information directly. They might lead the application to leak information elsewhere instead: in export files, emails and maybe even text alerts.

### Change the request method

If one request method doesn’t work, there are plenty of others that you can try instead: GET, POST, PUT, DELETE, PATCH…

A common trick that works is substituting POST for PUT or vice versa: the same access controls might not have been implemented!

### Change the requested file type

Sometimes, switching around the file type of the requested file may lead to the server processing authorization differently. For example, try adding `.json` to the end of the request URL and see what happens.

## How to increase the impacts of IDORs

### Critical IDORs first

Always look for IDORs in critical functionalities first. Both write and read based IDORs can be of high impact.

In terms of state-changing (write) IDORs, password reset, password change, account recovery IDORs often have the highest business impact. (Say, as compared to a “change email subscription settings” IDOR.)

As for non-state-changing (read) IDORs, look for functionalities that handle the sensitive information in the application. For example, look for functionalities that handle direct messages, sensitive user information, and private content. Consider which functionalities on the application makes use of this information and look for IDORs accordingly.

### Stored XSS

When you combine write-IDOR with self-XSS, you can often create a stored-XSS targeted towards a specific user.

When would this be useful? Let’s say you find an IDOR that allows attackers to change the content of another user’s internet shopping list. This IDOR in itself would not be too high impact, and would likely just cause a bit of annoyance if exploited in the wild. But if you can chain this IDOR with a self-XSS on the same input field, you can essentially use this IDOR to deliver the XSS exploit code to the victim user’s browser. This way, you can create targeted stored-XSS that requires no user interaction!
