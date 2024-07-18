---
title: Exiftool 🐧
tags:
  - Tool
---
- *Credits to [exiftool-cheat-sheet](https://www.henryleach.com/2021/06/exiftool-cheat-sheet/)*

## Read Existing Tags

The bare command just lists all the existing tags found in an image file:

```shell
exiftool PICTURE.png
```

Use the `-a` option to see all the entries:

```shell
exiftool -a PICTURE.png
```

If you want to see a specific tag add it to the command like:

```shell
exiftool -gpsdatetime PICTURE.png
```

If you need a custom output format, you can use the `-p` for Print Format and use tag names as a variable within a string, e.g.

```shell
exiftool -p 'This image was taken at $gpsdatetime' PICTURE.jpg
```

## Multiple pictures

To deal with multiple pictures you can either point ExifTool at a directory instead of a single file. The `-r` will run the command recursively, and process any images it finds in sub-directories. e.g. the following will work on all pictures in the Pictures directory, and below.

```shell
exiftool -r -gpsdatetime ~/Pictures
```

If you want to filter files based on their type/extension then use the `-ext` flag and choose your extension. This is _not_ case sensitive, but it will differentiate between “.jpg” and “.jpeg” should you have both in your collection.

```shell
exiftool -gpsdatetime -ext jpg ~/Pictures
```

## Editing tags

Generally editing tags is in the format `-tagname='new tag value'`, the single quotes are only needed if your new value has spaces in it.

To delete a tag, and its value, just leave a blank after the equals sign, e.g. `-tagname=`.

There is also a special “all” tag, which is most useful if you want to remove any metadata from an image, e.g. the following would remove all metadata from all jpg files in the directory “Pictures”.

```bash
exiftool -all= -ext jpg ~/Pictures
```

## List tags

Some tags, like “Keywords” are a list. These behave [slightly differently](https://www.exiftool.org/faq.html#Q17) to other tags. Here you have to either list the entries separately, as follows:

```shell
exiftool -keywords=banana -keywords=fruit myimage.jpg
```

or use the `-sep` flag to do it in one entry.

```shell
exiftool -sep ", " -keywords="banana, fruit" myimage.jpg
```

If all you want to do is add or remove specific items you can use the `+=`and `-=` operators.