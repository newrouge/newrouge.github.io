---
layout: post
tags: web
title: Aliexpress Captcha Reuse
---

Captcha reuse in Aliexpress login form

<div style="text-align: center;">
 <a href="/tags#system"><img src="{{ site.baseurl }}/icons/web.png" width="200" title="web" ></a>
</div>




{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/aliexpress/captcha_reuse.png)
{: refdef}

request:
```
GET /captcha/image/get.jsonp?sessionid=random&identity=data&style=default&callback=callback HTTP/1.1
Host: usdiablo.alibaba.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: */*
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Referer: https://www.aliexpress.com/
```
