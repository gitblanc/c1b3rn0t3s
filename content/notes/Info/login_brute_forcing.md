---
title: Login Brute Forcing 🦏
tags:
  - Theory
  - CBBH
---
> *This content was extracted from [HTB Academy](https://academy.hackthebox.com/module/57/section/506)*

# Introduction

Keys and passwords, the modern equivalent of locks and combinations, secure the digital world. But what if someone tries every possible combination until they find the one that opens the door? That, in essence, is `brute forcing`.

## What is Brute Forcing?

In cybersecurity, brute forcing is a trial-and-error method used to crack passwords, login credentials, or encryption keys. It involves systematically trying every possible combination of characters until the correct one is found. The process can be likened to a thief trying every key on a giant keyring until they find the one that unlocks the treasure chest.

The success of a brute force attack depends on several factors, including:

- The `complexity` of the password or key. Longer passwords with a mix of uppercase and lowercase letters, numbers, and symbols are exponentially more complex to crack.
- The `computational power` available to the attacker. Modern computers and specialized hardware can try billions of combinations per second, significantly reducing the time needed for a successful attack.
- The `security measures` in place. Account lockouts, CAPTCHAs, and other defenses can slow down or even thwart brute-force attempts.

## How Brute Forcing Works

The brute force process can be visualized as follows:

![](Pasted%20image%2020250303193902.png)

1. `Start`: The attacker initiates the brute force process, often with the aid of specialized software.
2. `Generate Possible Combination`: The software generates a potential password or key combination based on predefined parameters, such as character sets and length.
3. `Apply Combination`: The generated combination is attempted against the target system, such as a login form or encrypted file.
4. `Check if Successful`: The system evaluates the attempted combination. If it matches the stored password or key, access is granted. Otherwise, the process continues.
5. `Access Granted`: The attacker gains unauthorized access to the system or data.
6. `End`: The process repeats, generating and testing new combinations until either the correct one is found or the attacker gives up.

## Types of Brute Forcing

Brute forcing is not a monolithic entity but a collection of diverse techniques, each with its strengths, weaknesses, and ideal use cases. Understanding these variations is crucial for both attackers and defenders, as it enables the former to choose the most effective approach and the latter to implement targeted countermeasures. The following table provides a comparative overview of various brute-forcing methods:

|Method|Description|Example|Best Used When...|
|---|---|---|---|
|`Simple Brute Force`|Systematically tries all possible combinations of characters within a defined character set and length range.|Trying all combinations of lowercase letters from 'a' to 'z' for passwords of length 4 to 6.|No prior information about the password is available, and computational resources are abundant.|
|`Dictionary Attack`|Uses a pre-compiled list of common words, phrases, and passwords.|Trying passwords from a list like 'rockyou.txt' against a login form.|The target will likely use a weak or easily guessable password based on common patterns.|
|`Hybrid Attack`|Combines elements of simple brute force and dictionary attacks, often appending or prepending characters to dictionary words.|Adding numbers or special characters to the end of words from a dictionary list.|The target might use a slightly modified version of a common password.|
|`Credential Stuffing`|Leverages leaked credentials from one service to attempt access to other services, assuming users reuse passwords.|Using a list of usernames and passwords leaked from a data breach to try logging into various online accounts.|A large set of leaked credentials is available, and the target is suspected of reusing passwords across multiple services.|
|`Password Spraying`|Attempts a small set of commonly used passwords against a large number of usernames.|Trying passwords like 'password123' or 'qwerty' against all usernames in an organization.|Account lockout policies are in place, and the attacker aims to avoid detection by spreading attempts across multiple accounts.|
|`Rainbow Table Attack`|Uses pre-computed tables of password hashes to reverse hashes and recover plaintext passwords quickly.|Pre-computing hashes for all possible passwords of a certain length and character set, then comparing captured hashes against the table to find matches.|A large number of password hashes need to be cracked, and storage space for the rainbow tables is available.|
|`Reverse Brute Force`|Targets a single password against multiple usernames, often used in conjunction with credential stuffing attacks.|Using a leaked password from one service to try logging into multiple accounts with different usernames.|A strong suspicion exists that a particular password is being reused across multiple accounts.|
|`Distributed Brute Force`|Distributes the brute forcing workload across multiple computers or devices to accelerate the process.|Using a cluster of computers to perform a brute-force attack significantly increases the number of combinations that can be tried per second.|The target password or key is highly complex, and a single machine lacks the computational power to crack it within a reasonable timeframe.|

## The Role of Brute Forcing in Penetration Testing

Penetration testing, or ethical hacking, is a proactive cybersecurity measure that simulates real-world attacks to identify and address vulnerabilities before malicious actors can exploit them. Brute forcing is a crucial tool in this process, particularly when assessing the resilience of password-based authentication mechanisms.

While penetration tests encompass a range of techniques, brute forcing is often strategically employed when:

- `Other avenues are exhausted`: Initial attempts to gain access, such as exploiting known vulnerabilities or utilizing social engineering tactics, may prove unsuccessful. In such scenarios, brute forcing is a viable alternative to overcome password barriers.
- `Password policies are weak`: If the target system employs lax password policies, it increases the likelihood of users having weak or easily guessable passwords. Brute forcing can effectively expose these vulnerabilities.
- `Specific accounts are targeted`: In some instances, penetration testers may focus on compromising specific user accounts, such as those with elevated privileges. Brute forcing can be tailored to target these accounts directly.

# Password Security Fundamentals

The effectiveness of brute-force attacks hinges on the strength of the passwords it targets. Understanding the fundamentals of password security is crucial for appreciating the importance of robust password practices and the challenges posed by brute-force attacks.

## The Importance of Strong Passwords

Passwords are the first line of defense in protecting sensitive information and systems. A strong password is a formidable barrier, making it significantly harder for attackers to gain unauthorized access through brute forcing or other techniques. The longer and more complex a password is, the more combinations an attacker has to try, exponentially increasing the time and resources required for a successful attack.

## The Anatomy of a Strong Password

The `National Institute of Standards and Technology` (`NIST`) provides guidelines for creating strong passwords. These guidelines emphasize the following characteristics:

- `Length`: The longer the password, the better. Aim for a minimum of 12 characters, but longer is always preferable. The reasoning is simple: each additional character in a password dramatically increases the number of possible combinations. For instance, a 6-character password using only lowercase letters has 26^6 (approximately 300 million) possible combinations. In contrast, an 8-character password has 26^8 (approximately 200 billion) combinations. This exponential increase in possibilities makes longer passwords significantly more resistant to brute-force attacks.
- `Complexity`: Use uppercase and lowercase letters, numbers, and symbols. Avoid quickly guessable patterns or sequences. Including different character types expands the pool of potential characters for each position in the password. For example, a password using only lowercase letters has 26 possibilities per character, while a password using both uppercase and lowercase letters has 52 possibilities per character. This increased complexity makes it much harder for attackers to predict or guess passwords.
- `Uniqueness`: Don't reuse passwords across different accounts. Each account should have its own unique and strong password. If one account is compromised, all other accounts using the same password are also at risk. By using unique passwords for each account, you compartmentalize the potential damage of a breach.
- `Randomness`: Avoid using dictionary words, personal information, or common phrases. The more random the password, the harder it is to crack. Attackers often use wordlists containing common passwords and personal information to speed up their brute-force attempts. Creating a random password minimizes the chances of being included in such wordlists.

## Common Password Weaknesses

Despite the importance of strong passwords, many users still rely on weak and easily guessable passwords. Common weaknesses include:

- `Short Passwords`: Passwords with fewer than eight characters are particularly vulnerable to brute-force attacks, as the number of possible combinations is relatively small.
- `Common Words and Phrases`: Using dictionary words, names, or common phrases as passwords makes them susceptible to dictionary attacks, where attackers try a pre-defined list of common passwords.
- `Personal Information`: Incorporating personal information like birthdates, pet names, or addresses into passwords makes them easier to guess, especially if this information is publicly available on social media or other online platforms.
- `Reusing Passwords`: Using the same password across multiple accounts is risky. If one account is compromised, all other accounts using the same password are also at risk.
- `Predictable Patterns`: Using patterns like "qwerty" or "123456" or simple substitutions like "p@ssw0rd" makes passwords easy to guess, as these patterns are well-known to attackers.

## Password Policies

Organizations often implement password policies to enforce the use of strong passwords. These policies typically include requirements for:

- `Minimum Length`: The minimum number of characters a password must have.
- `Complexity`: The types of characters that must be included in a password (e.g., uppercase, lowercase, numbers, symbols).
- `Password Expiration`: The frequency with which passwords must be changed.
- `Password History`: The number of previous passwords that cannot be reused.

While password policies can help improve password security, they can also lead to user frustration and the adoption of poor password practices, such as writing passwords down or using slight variations of the same password. When designing password policies, it's important to balance security and usability.

## The Perils of Default Credentials

One critical aspect of password security often overlooked is the danger posed by `default passwords`. These pre-set passwords come with various devices, software, or online services. They are often simple and easily guessable, making them a prime target for attackers.

Default passwords significantly increase the success rate of brute-force attacks. Attackers can leverage lists of common default passwords, dramatically reducing the search space and accelerating the cracking process. In some cases, attackers may not even need to perform a brute-force attack; they can try a few common default passwords and gain access with minimal effort.

The prevalence of default passwords makes them a low-hanging fruit for attackers. They provide an easy entry point into systems and networks, potentially leading to data breaches, unauthorized access, and other malicious activities.

|Device/Manufacturer|Default Username|Default Password|Device Type|
|---|---|---|---|
|Linksys Router|admin|admin|Wireless Router|
|D-Link Router|admin|admin|Wireless Router|
|Netgear Router|admin|password|Wireless Router|
|TP-Link Router|admin|admin|Wireless Router|
|Cisco Router|cisco|cisco|Network Router|
|Asus Router|admin|admin|Wireless Router|
|Belkin Router|admin|password|Wireless Router|
|Zyxel Router|admin|1234|Wireless Router|
|Samsung SmartCam|admin|4321|IP Camera|
|Hikvision DVR|admin|12345|Digital Video Recorder (DVR)|
|Axis IP Camera|root|pass|IP Camera|
|Ubiquiti UniFi AP|ubnt|ubnt|Wireless Access Point|
|Canon Printer|admin|admin|Network Printer|
|Honeywell Thermostat|admin|1234|Smart Thermostat|
|Panasonic DVR|admin|12345|Digital Video Recorder (DVR)|

These are just a few examples of well-known default passwords. Attackers often compile extensive lists of such passwords and use them in automated attacks.

Alongside default passwords, default usernames are another major security concern. Manufacturers often ship devices with pre-set usernames, such as `admin`, `root`, or `user`. You might have noticed in the table above how many use common usernames. These usernames are widely known and often published in documentation or readily available online. SecLists maintains a list of common usernames at [top-usernames-shortlist.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt)

Default usernames are a significant vulnerability because they give attackers a predictable starting point. In many brute-force attacks, knowing the username is half the battle. With the username already established, the attacker only needs to crack the password, and if the device still uses a default password, the attack can be completed with minimal effort.

Even when default passwords are changed, retaining the default username still leaves systems vulnerable to attacks. It drastically narrows the attack surface, as the hacker can skip the process of guessing usernames and focus solely on the password.

### Brute-forcing and Password Security

In a brute-force scenario, the strength of the target passwords becomes the attacker's primary obstacle. A weak password is akin to a flimsy lock on a door – easily picked open with minimal effort. Conversely, a strong password acts as a fortified vault, demanding significantly more time and resources to breach.

For a pentester, this translates to a deeper understanding of the target's security posture:

- `Evaluating System Vulnerability:` Password policies, or their absence, and the likelihood of users employing weak passwords directly inform the potential success of a brute-force attack.
- `Strategic Tool Selection:` The complexity of the passwords dictates the tools and methodologies a pentester will deploy. A simple dictionary attack might suffice for weak passwords, while a more sophisticated, hybrid approach may be required to crack stronger ones.
- `Resource Allocation:` The estimated time and computational power needed for a brute-force attack is intrinsically linked to the complexity of the passwords. This knowledge is essential for effective planning and resource management.
- `Exploiting Weak Points:` Default passwords are often a system's Achilles' heel. A pentester's ability to identify and leverage these easily guessable credentials can provide a swift entry point into the target network.

In essence, a deep understanding of password security is a roadmap for a pentester navigating the complexities of a brute-force attack. It unveils potential weak points, informs strategic choices, and predicts the effort required for a successful breach. This knowledge, however, is a double-edged sword. It also underscores the critical importance of robust password practices for any organization seeking to defend against such attacks, highlighting each user's pivotal role in safeguarding sensitive information.

# Brute Force Attacks

To truly grasp the challenge of brute forcing, it's essential to understand the underlying mathematics. The following formula determines the total number of possible combinations for a password:

```mathml
Possible Combinations = Character Set Size^Password Length
```

For example, a 6-character password using only lowercase letters (character set size of 26) has 26^6 (approximately 300 million) possible combinations. In contrast, an 8-character password with the same character set has 26^8 (approximately 200 billion) combinations. Adding uppercase letters, numbers, and symbols to the character set further expands the search space exponentially.

This exponential growth in the number of combinations highlights the importance of password length and complexity. Even a small increase in length or the inclusion of additional character types can dramatically increase the time and resources required for a successful brute-force attack.

Let's consider a few scenarios to illustrate the impact of password length and character set on the search space:

| |Password Length|Character Set|Possible Combinations|
|---|---|---|---|
|`Short and Simple`|6|Lowercase letters (a-z)|26^6 = 308,915,776|
|`Longer but Still Simple`|8|Lowercase letters (a-z)|26^8 = 208,827,064,576|
|`Adding Complexity`|8|Lowercase and uppercase letters (a-z, A-Z)|52^8 = 53,459,728,531,456|
|`Maximum Complexity`|12|Lowercase and uppercase letters, numbers, and symbols|94^12 = 475,920,493,781,698,549,504|

As you can see, even a slight increase in password length or the inclusion of additional character types dramatically expands the search space. This significantly increases the number of possible combinations that an attacker must try, making brute-forcing increasingly challenging and time-consuming. However, the time it takes to crack a password isn't just dependent on the size of the search space—it also hinges on the attacker's available computational power.

The more powerful the attacker's hardware (e.g., the number of GPUs, CPUs, or cloud-based computing resources they can utilize), the more password guesses they can make per second. While a complex password can take years to brute-force with a single machine, a sophisticated attacker using a distributed network of high-performance computing resources could reduce that time drastically.

![](Pasted%20image%2020250303195015.png)

The above chart illustrates an exponential relationship between password complexity and cracking time. As the password length increases and the character set expands, the total number of possible combinations grows exponentially. This significantly increases the time required to crack the password, even with powerful computing resources.

Comparing the basic computer and the supercomputer:

- Basic Computer (1 million passwords/second): Adequate for cracking simple passwords quickly but becomes impractically slow for complex passwords. For instance, cracking an 8-character password using letters and digits would take approximately 6.92 years.
- Supercomputer (1 trillion passwords/second): Drastically reduces cracking times for simpler passwords. However, even with this immense power, cracking highly complex passwords can take an impractical amount of time. For example, a 12-character password with all ASCII characters would still take about 15000 years to crack.

## Cracking the PIN

The instance application generates a random 4-digit PIN and exposes an endpoint (`/pin`) that accepts a PIN as a query parameter. If the provided PIN matches the generated one, the application responds with a success message and a flag. Otherwise, it returns an error message.

We will use this simple demonstration Python script to brute-force the `/pin` endpoint on the API. Copy and paste this Python script below as `pin-solver.py` onto your machine. You only need to modify the IP and port variables to match your target system information.

```python
import requests

ip = "94.237.54.190"  # Change this to your instance IP address
port = 48781       # Change this to your instance port number

# Try every possible 4-digit PIN (from 0000 to 9999)
for pin in range(10000):
    formatted_pin = f"{pin:04d}"  # Convert the number to a 4-digit string (e.g., 7 becomes "0007")
    print(f"Attempted PIN: {formatted_pin}")

    # Send the request to the server
    response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")

    # Check if the server responds with success and the flag is found
    if response.ok and 'flag' in response.json():  # .ok means status code is 200 (success)
        print(f"Correct PIN found: {formatted_pin}")
        print(f"Flag: {response.json()['flag']}")
        break
```

The Python script systematically iterates all possible 4-digit PINs (0000 to 9999) and sends GET requests to the Flask endpoint with each PIN. It checks the response status code and content to identify the correct PIN and capture the associated flag.

```shell
gitblanc@htb[/htb]$ python pin-solver.py

...
Attempted PIN: 4039
Attempted PIN: 4040
Attempted PIN: 4041
Attempted PIN: 4042
Attempted PIN: 4043
Attempted PIN: 4044
Attempted PIN: 4045
Attempted PIN: 4046
Attempted PIN: 4047
Attempted PIN: 4048
Attempted PIN: 4049
Attempted PIN: 4050
Attempted PIN: 4051
Attempted PIN: 4052
Correct PIN found: 4053
Flag: HTB{...}
```

The script's output will show the progression of the brute-force attack, displaying each attempted PIN and its corresponding result. The final output will reveal the correct PIN and the captured flag, demonstrating the successful completion of the brute-force attack.

# Dictionary Attacks

While comprehensive, the brute-force approach can be time-consuming and resource-intensive, especially when dealing with complex passwords. That's where dictionary attacks come in.

## The Power of Words

The effectiveness of a dictionary attack lies in its ability to exploit the human tendency to prioritize memorable passwords over secure ones. Despite repeated warnings, many individuals continue to opt for passwords based on readily available information such as dictionary words, common phrases, names, or easily guessable patterns. This predictability makes them vulnerable to dictionary attacks, where attackers systematically test a pre-defined list of potential passwords against the target system.

The success of a dictionary attack hinges on the quality and specificity of the wordlist used. A well-crafted wordlist tailored to the target audience or system can significantly increase the probability of a successful breach. For instance, if the target is a system frequented by gamers, a wordlist enriched with gaming-related terminology and jargon would prove more effective than a generic dictionary. The more closely the wordlist reflects the likely password choices of the target, the higher the chances of a successful attack.

At its core, the concept of a dictionary attack is rooted in understanding human psychology and common password practices. By leveraging this insight, attackers can efficiently crack passwords that might otherwise necessitate an impractically lengthy brute-force attack. In this context, the power of words resides in their ability to exploit human predictability and compromise otherwise robust security measures.

## Brute Force vs. Dictionary Attack

The fundamental distinction between a brute-force and a dictionary attack lies in their methodology for generating potential password candidates:

- `Brute Force`: A pure brute-force attack systematically tests _every possible combination_ of characters within a predetermined set and length. While this approach guarantees eventual success given enough time, it can be extremely time-consuming, particularly against longer or complex passwords.
- `Dictionary Attack`: In stark contrast, a dictionary attack employs a pre-compiled list of words and phrases, dramatically reducing the search space. This targeted methodology results in a far more efficient and rapid attack, especially when the target password is suspected to be a common word or phrase.

|Feature|Dictionary Attack|Brute Force Attack|Explanation|
|---|---|---|---|
|`Efficiency`|Considerably faster and more resource-efficient.|Can be extremely time-consuming and resource-intensive.|Dictionary attacks leverage a pre-defined list, significantly narrowing the search space compared to brute-force.|
|`Targeting`|Highly adaptable and can be tailored to specific targets or systems.|No inherent targeting capability.|Wordlists can incorporate information relevant to the target (e.g., company name, employee names), increasing the success rate.|
|`Effectiveness`|Exceptionally effective against weak or commonly used passwords.|Effective against all passwords given sufficient time and resources.|If the target password is within the dictionary, it will be swiftly discovered. Brute force, while universally applicable, can be impractical for complex passwords due to the sheer volume of combinations.|
|`Limitations`|Ineffective against complex, randomly generated passwords.|Often impractical for lengthy or highly complex passwords.|A truly random password is unlikely to appear in any dictionary, rendering this attack futile. The astronomical number of possible combinations for lengthy passwords can make brute-force attacks infeasible.|

Consider a hypothetical scenario where an attacker targets a company's employee login portal. The attacker might construct a specialized wordlist that incorporates the following:

- Commonly used, weak passwords (e.g., "password123," "qwerty")
- The company name and variations thereof
- Names of employees or departments
- Industry-specific jargon

By deploying this targeted wordlist in a dictionary attack, the attacker significantly elevates their likelihood of successfully cracking employee passwords compared to a purely random brute-force endeavor.

## Building and Utilizing Wordlists

Wordlists can be obtained from various sources, including:

- `Publicly Available Lists`: The internet hosts a plethora of freely accessible wordlists, encompassing collections of commonly used passwords, leaked credentials from data breaches, and other potentially valuable data. Repositories like [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) offer various wordlists catering to various attack scenarios.
- `Custom-Built Lists`: Penetration testers can craft their wordlists by leveraging information gleaned during the reconnaissance phase. This might include details about the target's interests, hobbies, personal information, or any other data for password creation.
- `Specialized Lists`: Wordlists can be further refined to target specific industries, applications, or even individual companies. These specialized lists increase the likelihood of success by focusing on passwords that are more likely to be used within a particular context.
- `Pre-existing Lists`: Certain tools and frameworks come pre-packaged with commonly used wordlists. For instance, penetration testing distributions like ParrotSec often include wordlists like `rockyou.txt`, a massive collection of leaked passwords, readily available for use.

Here is a table of some of the more useful wordlists for login brute-forcing:

|Wordlist|Description|Typical Use|Source|
|---|---|---|---|
|`rockyou.txt`|A popular password wordlist containing millions of passwords leaked from the RockYou breach.|Commonly used for password brute force attacks.|[RockYou breach dataset](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)|
|`top-usernames-shortlist.txt`|A concise list of the most common usernames.|Suitable for quick brute force username attempts.|[SecLists](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt)|
|`xato-net-10-million-usernames.txt`|A more extensive list of 10 million usernames.|Used for thorough username brute forcing.|[SecLists](https://github.com/danielmiessler/SecLists/blob/master/Usernames/xato-net-10-million-usernames.txt)|
|`2023-200_most_used_passwords.txt`|A list of the 200 most commonly used passwords as of 2023.|Effective for targeting commonly reused passwords.|[SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt)|
|`Default-Credentials/default-passwords.txt`|A list of default usernames and passwords commonly used in routers, software, and other devices.|Ideal for trying default credentials.|[SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.txt)|

## Throwing a dictionary at the problem

The instance application creates a route (`/dictionary`) that handles POST requests. It expects a `password` parameter in the request's form data. Upon receiving a request, it compares the submitted password against the expected value. If there's a match, it responds with a JSON object containing a success message and the flag. Otherwise, it returns an error message with a 401 status code (Unauthorized).

Copy and paste this Python script below as `dictionary-solver.py` onto your machine. You only need to modify the IP and port variables to match your target system information.

```python
import requests

ip = "94.237.54.190"  # Change this to your instance IP address
port = 32926       # Change this to your instance port number

# Download a list of common passwords from the web and split it into lines
passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/500-worst-passwords.txt").text.splitlines()

# Try each password from the list
for password in passwords:
    print(f"Attempted password: {password}")

    # Send a POST request to the server with the password
    response = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})

    # Check if the server responds with success and contains the 'flag'
    if response.ok and 'flag' in response.json():
        print(f"Correct password found: {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```

The Python script orchestrates the dictionary attack. It performs the following steps:

1. `Downloads the Wordlist`: First, the script fetches a wordlist of 500 commonly used (and therefore weak) passwords from SecLists using the `requests` library.
2. `Iterates and Submits Passwords`: It then iterates through each password in the downloaded wordlist. For each password, it sends a POST request to the Flask application's `/dictionary` endpoint, including the password in the request's form data.
3. `Analyzes Responses`: The script checks the response status code after each request. If it's 200 (OK), it examines the response content further. If the response contains the "flag" key, it signifies a successful login. The script then prints the discovered password and the captured flag.
4. `Continues or Terminates`: If the response doesn't indicate success, the script proceeds to the next password in the wordlist. This process continues until the correct password is found or the entire wordlist is exhausted.

```shell
gitblanc@htb[/htb]$ python3 dictionary-solver.py

...
Attempted password: turtle
Attempted password: tiffany
Attempted password: golf
Attempted password: bear
Attempted password: tiger
Correct password found: ...
Flag: HTB{...}
```

# Hybrid Attacks

Many organizations implement policies requiring users to change their passwords periodically to enhance security. However, these policies can inadvertently breed predictable password patterns if users are not adequately educated on proper password hygiene.

![](Pasted%20image%2020250303201042.png)

Unfortunately, a widespread and insecure practice among users is making minor modifications to their passwords when forced to change them. This often manifests as appending a number or a special character to the end of the current password. For instance, a user might have an initial password like "Summer2023" and then, when prompted to update it, change it to "Summer2023!" or "Summer2024."

This predictable behavior creates a loophole that hybrid attacks can exploit ruthlessly. Attackers capitalize on this human tendency by employing sophisticated techniques that combine the strengths of dictionary and brute-force attacks, drastically increasing the likelihood of successful password breaches.

### Hybrid Attacks in Action

Let's illustrate this with a practical example. Consider an attacker targeting an organization known to enforce regular password changes.

![](Pasted%20image%2020250303201057.png)

The attacker begins by launching a dictionary attack, using a wordlist curated with common passwords, industry-specific terms, and potentially personal information related to the organization or its employees. This phase attempts to quickly identify any low-hanging fruit - accounts protected by weak or easily guessable passwords.

However, if the dictionary attack proves unsuccessful, the hybrid attack seamlessly transitions into a brute-force mode. Instead of randomly generating password combinations, it strategically modifies the words from the original wordlist, appending numbers, special characters, or even incrementing years, as in our "Summer2023" example.

This targeted brute-force approach drastically reduces the search space compared to a traditional brute-force attack while covering many potential password variations that users might employ to comply with the password change policy.

### The Power of Hybrid Attacks

The effectiveness of hybrid attacks lies in their adaptability and efficiency. They leverage the strengths of both dictionary and brute-force techniques, maximizing the chances of cracking passwords, especially in scenarios where users fall into predictable patterns.

It's important to note that hybrid attacks are not limited to the password change scenario described above. They can be tailored to exploit any observed or suspected password patterns within a target organization. Let's consider a scenario where you have access to a common passwords wordlist, and you're targeting an organization with the following password policy:

- Minimum length: 8 characters
- Must include:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number

To extract only the passwords that adhere to this policy, we can leverage the powerful command-line tools available on most Linux/Unix-based systems by default, specifically `grep` paired with regex. We are going to use the [darkweb2017-top10000.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/darkweb2017-top10000.txt) password list for this. First, download the wordlist

```shell-session
gitblanc@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/darkweb2017-top10000.txt
```

Next, we need to start matching that wordlist to the password policy.

```shell-session
gitblanc@htb[/htb]$ grep -E '^.{8,}$' darkweb2017-top10000.txt > darkweb2017-minlength.txt
```

This initial `grep` command targets the core policy requirement of a minimum password length of 8 characters. The regular expression `^.{8,}$` acts as a filter, ensuring that only passwords containing at least 8 characters are passed through and saved in a temporary file named `darkweb2017-minlength.txt`.

```shell-session
gitblanc@htb[/htb]$ grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt
```

Building upon the previous filter, this `grep` command enforces the policy's demand for at least one uppercase letter. The regular expression `[A-Z]` ensures that any password lacking an uppercase letter is discarded, further refining the list saved in `darkweb2017-uppercase.txt`.

```shell-session
gitblanc@htb[/htb]$ grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt
```

Maintaining the filtering chain, this `grep` command ensures compliance with the policy's requirement for at least one lowercase letter. The regular expression `[a-z]` serves as the filter, keeping only passwords that include at least one lowercase letter and storing them in `darkweb2017-lowercase.txt`.

```shell-session
gitblanc@htb[/htb]$ grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt
```

This last `grep` command tackles the policy's numerical requirement. The regular expression `[0-9]` acts as a filter, ensuring that passwords containing at least one numerical digit are preserved in `darkweb2017-number.txt`.

```shell-session
gitblanc@htb[/htb]$ wc -l darkweb2017-number.txt

89 darkweb2017-number.txt
```

As demonstrated by the output above, meticulously filtering the extensive 10,000-password list against the password policy has dramatically narrowed down our potential passwords to 89. This drastic reduction in the search space represents a significant boost in efficiency for any subsequent password cracking attempts. A smaller, targeted list translates to a faster and more focused attack, optimizing the use of computational resources and increasing the likelihood of a successful breach.

## Credential Stuffing: Leveraging Stolen Data for Unauthorized Access

![](Pasted%20image%2020250303201138.png)

Credential stuffing attacks exploit the unfortunate reality that many users reuse passwords across multiple online accounts. This pervasive practice, often driven by the desire for convenience and the challenge of managing numerous unique credentials, creates a fertile ground for attackers to exploit.

It's a multi-stage process that begins with attackers acquiring lists of compromised usernames and passwords. These lists can stem from large-scale data breaches or be compiled through phishing scams and malware. Notably, publicly available wordlists like `rockyou` or those found in `seclists` can also serve as a starting point, offering attackers a trove of commonly used passwords.

Once armed with these credentials, attackers identify potential targets - online services likely used by the individuals whose information they possess. Social media, email providers, online banking, and e-commerce sites are prime targets due to the sensitive data they often hold.

The attack then shifts into an automated phase. Attackers use tools or scripts to systematically test the stolen credentials against the chosen targets, often mimicking normal user behavior to avoid detection. This allows them to rapidly test vast numbers of credentials, increasing their chances of finding a match.

A successful match grants unauthorized access, opening the door to various malicious activities, from data theft and identity fraud to financial crimes. The compromised account may be a launchpad for further attacks, spreading malware, or infiltrating connected systems.

### The Password Reuse Problem

The core issue fueling credential stuffing's success is the pervasive practice of password reuse. When users rely on the same or similar passwords for multiple accounts, a breach on one platform can have a domino effect, compromising numerous other accounts. This highlights the urgent need for strong, unique passwords for every online service, coupled with proactive security measures like multi-factor authentication.

