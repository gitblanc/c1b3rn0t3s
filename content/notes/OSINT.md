---
title: OSINT 👻
---
## Locate a city

- If you found some coordinates, you can find out the location in [gps-coordinates.org/](https://gps-coordinates.org/)

![](Pasted%20image%2020240425155902.png)

## Locate BSSID

- If you found a bssid like `B4:5D:50:AA:86:41`, you can find out its ocation on [wiggle.net](https://www.wigle.net/)
	- You will need to register
	- Go to the tab `Search >> Advanced Search` and place the bssid
	- You will get a record at the bottom

![](Pasted%20image%2020240425161529.png)

## Find the name of someone

- If you found a nickname you can search for the social medias of the person in [whatsmyname.app](https://whatsmyname.app/)

![](Pasted%20image%2020240426001520.png)

## Find social media of a nickname

- Use the cli app [Sherlock](https://github.com/sherlock-project/sherlock)

## Finding a pgp key

- If you find something like:

```shell
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
23pRnPKc+41cwL3oq8yb/Fhj+biohgIp
=grbk
-----END PGP PUBLIC KEY BLOCK-----
```

- Import the key by doing: `gpg --import NAMETOOLONG.asc`, 'cause you can find the email of somebody:

![](Pasted%20image%2020240426001953.png)

## Search crypto wallet movements

- Go to [blockchain explorer](https://www.blockchain.com/explorer/search?search=bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa) and check the wallet you found

## IMINT/GEOINT

The title is short for Image intelligence and geospatial intelligence

- First of all, before using any tool we've got to evaluate by using our eyes to perform further actions. You must check:
	- Context
	- Foreground
	- Background
	- Map markings
	- Trial and error

### Questions to ask yourself while looking at challenges

1. **The questions**
	- Are there any obvious data in the image that reveals the location, like a street name or storefront signs?
	- Can you determine the country or region of the image by, for instance, which side of the road they drive on, language or architectural characteristics that may reveal a country or continent/region?
	- Do you recognize road sign styles, nature and environmental characteristics, or popular motor vehicle brands or vehicle types?
	- What is the quality of any visible infrastructure like? Is the road paved or do you see gravel roads?
	- Do you see any unique landmarks, buildings, bridges, statues or mountains that can help you geolocate the image?

	![](Pasted%20image%2020240426205652.png)

> In the pic above the clue is `Carnaby Street`

2. **Google what you found!**
	- Some useful  [Google Dorking 👓](google_dorking.md)
	- You've also got the [THM Room](https://tryhackme.com/r/room/googledorking)
	- You've also got [Google Lens](https://www.google.com/?authuser=0)

3. **Reverse your thinking**
One of the methods for geolocating an image is to do an image reverse search. This means that we are searching for the image itself online, and if the image has been indexed by search engines we may find the exact image or we can do a visual search or crop search to help us find similar images. 

 [Aric Toler](https://twitter.com/AricToler) from [Bellingcat](https://www.bellingcat.com/) has written a fantastic guide on reversing images, please read it [here](https://www.bellingcat.com/resources/how-tos/2019/12/26/guide-to-using-reverse-image-search-for-investigations/). [OSINT Curious](https://osintcurio.us/) also has a [write-up](https://osintcurio.us/2020/04/12/tips-and-tricks-on-reverse-image-searches/) on the topic that you should look through before attempting this challenge. 

I recommend adding this extension to ease the workflow for when you find images online that you want to do an image reverse on:

**Addon description:** "Perform a search by image. Choose between the image search engines Google, Bing, Yandex, TinEye and Baidu."

**Chrome:** [RevEye Reverse Image Search](https://chrome.google.com/webstore/search/RevEye%20Reverse%20Image%20Search?hl=no) - 

**Firefox:** [RevEye Reverse Image Search](https://addons.mozilla.org/nb-NO/firefox/addon/reveye-ris/)
## Geolocating videos

Geolocating videos aren't much different from geolocating images. A video is just a string of images, usually played at 24 frames(or images) per second. In other words, a video will hold a whole lot more images that can be analyzed, reversed and scrutinized by you.   

Here's a good [writeup](https://nixintel.info/osint-tools/using-ffmpeg-to-grab-stills-and-audio-for-osint/) by [Nixintel](https://twitter.com/nixintel) on a tool called [FFmpeg](https://ffmpeg.org/), which will help you extract the key images from the video that you may need to solve this challenge. Download the attached video and follow Nixintel's guide!

- I took a note in [FFmpeg 🚍](FFmpeg.md)

