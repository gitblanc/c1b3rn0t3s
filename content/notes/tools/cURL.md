---
title: cURL ⚙️
tags:
  - Tool
---
- Download a file from the Internet:

```shell
curl -O https://website.com
```

- Download a file silent (wihout info) from the Internet:

```shell
curl -s -O https://website.com
```

- Skip the certificate:

```shell
curl -k https://website.com
```

- Preview the full http request:

```shell
curl https://website.com -v
curl https://website.com -vvv
```

- Just see the response headers:

```shell
curl -I https://website.com
```

- Set your own user agent:

```shell
curl https://website.com -A 'Mozilla/5.0'
```

- Access with username and password:

```shell
curl -u admin:admin http://<SERVER_IP>:<PORT>/
# or
curl http://admin:admin@<SERVER_IP>:<PORT>/
```

- Access setting manually authorization header:

```shell
curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/
```

- Send a GET Request with cURL:
	- Open the browser devtools
	- Right click on the request and select `Copy>Copy as cURL`
	- Then:

```shell
curl 'http://<SERVER_IP>:<PORT>/search.php?search=le' -H 'Authorization: Basic YWRtaW46YWRtaW4='
```

- Send a POST request with data:

```shell
curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/
```

- Authenticate with a cookie:

```shell
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
# or
curl -H 'Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```
- A full POST example (with cookie and JSON data):

```shell
curl -X POST -d '{"search":"flag"}' -H 'Content-Type: application/json' -b 'PHPSESSID=149437hctb1edgbb6gs807fmv2' http://83.136.252.57:48546/search.php -i
```

- Send a PUT request:

```shell
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london
```

- **Read** data of an API:

```shell
curl http://<SERVER_IP>:<PORT>/api.php/city/london

# read it as json string
curl http://<SERVER_IP>:<PORT>/api.php/city/london | jq

# provide a search term
curl -s http://<SERVER_IP>:<PORT>/api.php/city/le | jq

# pass an empty string to retrieve all entries in the table
curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq
```

- **Create** data on an API:

```shell
curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```

- **Update** data on an API:

```shell
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```

- **Delete** data on an API:

```shell
curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City
```

