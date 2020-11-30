---
layout: post
tags: web
title: Aliexpress Captcha Reuse
---

Captcha reuse in Aliexpress login form

<div style="text-align: center;">
 <a href="/tags#system"><img src="{{ site.baseurl }}/icons/web.png" width="200" title="web" ></a>
</div>

I recently noticed (thanks to Chrome's form cache) that Aliexpress login captcha's were not random. Instead, it seems they are using a set of pre-generated images and sending user a random one from this set. This is, of course, not the right way to use captchas, especially if we add the fact that those are text captchas with very few transformations, making them easy to solve by an OCR.  
My goal here is not to demonstrate a successful attack against Aliexpress's login form, but instead just a simple PoC to show these captcha's weaknesses.


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/aliexpress/captcha_reuse.png)
{: refdef}


# Part 1: Building a hashtable of known captchas
The first step was knowing if the captcha request required authentication. This is the original request proxied:
{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/aliexpress/captcha_request.png)
{: refdef}

One of the first things I do when examining a request is stripping manually each get or post parameter, and HTTP headers, in order to discriminate the one needed by the application from the others. In this case, some parameters are needed, but they don't need to have a valid value. We use the following request to get captchas:

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

# Part 3: Protections

There seems to be extra protections against this form, which I did not explore. In fact, when sending the captcha's response, it is also expected to send a parameter named "captchaToken"
```
{"answer":"DBPR","captchaToken":"S10bb4dcdf0b3252825a76f4f803310a277f618d6bbe2893267eb379ee61c82a2a842f3b8ee064997f600430705cd5246e64ec5e81d671284efe9547475a00b9a003db505623d8e41ba2dc70f8dccf6977e66a1eb08a67dd3e379c13938e896784f3bd47f69ce1edc979a938dc61a0f7aae0db6beb8f6bc3b6178ecc3fa3e2a1dcdc51f0e3b866d56da16de672d83f0b9e9700dc1848ee697daf304c2d2722b1d253f99065a787a5ca2b3dc33311dabbf16342ff20b77b6355188f14f7a7425826ada937221d0d18bded87dc63bbc52fffbc81e251f52e835152e0d275324451e3f3bc3eef76ebb840f713e00d44548f09e8750bfde2d5d703c7f0a5444ab60547e99bda820b98bb91d7a590a2f5cb1e9dd846b719fd408223e629a75c92cbf9a1d708a2f4ab8b8f578c5671dfb5dbd17ffefe6128dac6b168b7d6b386cbf4d0cde74e377e443c3ce92c34992a57cac28931e3d2740b199306771187d8bb019f832f7b86699e1ea6b22a3abd1"}&a=CFUS_APP_HAVANALogin&t=CFUS_APP_HAVANALogin:XXXX
```
Supposedly it is randomly generated and uniquely identifies a captcha response submission, but we can already see they are not purely random and contain a sort of structure and headers:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/aliexpress/captcha_token.png)
{: refdef}

This token comes from the getcaptcha reponse so it does not really prevent from automatic form submission.  
There are many other parameters at stake in these requests (like a signature for example) and not knowing their exact roles, I will not mention them here.
