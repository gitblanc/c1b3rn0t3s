---
title: TimeKORP
tags:
  - CTF
  - Web
---
![](Pasted%20image%2020241013105435.png)

If we click on what's the date/time we get it, so it's time to analyze the source code:

![](Pasted%20image%2020241013105539.png)

If we analyze the Dockerfile, it seems that the flag is being copied in `/flag`:

![](Pasted%20image%2020241013105706.png)

If we inspect the `controllers` folder, we find `TimeController.php`:

```php
<?php
class TimeController
{
    public function index($router)
    {
        $format = isset($_GET['format']) ? $_GET['format'] : '%H:%M:%S';
        $time = new TimeModel($format);
        return $router->view('index', ['time' => $time->getTime()]);
    }
} 
```

This controller calls a model inside `models` subfolder, so let's inspect `TimeModel.php`:

```php
<?php
class TimeModel
{
    public function __construct($format)
    {
        $this->command = "date '+" . $format . "' 2>&1";
    }

    public function getTime()
    {
        $time = exec($this->command);
        $res  = isset($time) ? $time : '?';
        return $res;
    }
}
```

We can espace the command of the construct function by appending a `' #`, so we can read the content of `/flag` by altering the petition with burp using the payload (url encoded): `' && cat /flag #`

![](Pasted%20image%2020241013110312.png)

