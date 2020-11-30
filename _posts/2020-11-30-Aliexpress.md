---
layout: post
tags: web
title: AliExpress Captcha Reuse
---

Captcha reuse in Aliexpress login form

<div style="text-align: center;">
 <a href="/tags#system"><img src="{{ site.baseurl }}/icons/web.png" width="200" title="web" ></a>
</div>

I recently noticed (thanks to Chrome's form cache) that AliExpress login captcha's were not random. Instead, it seems they are using a set of pre-generated images and sending user a random one from this set. This is, of course, not the right way to use captchas, especially if we add the fact that those are text captchas, quite easy to solve with OCR.  
My goal here is not to demonstrate a successful attack against Aliexpress's login form, but instead just a simple PoC to show these captcha's weaknesses. This has been reported to AliExpress through their bugbounty program.  


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/aliexpress/captcha_reuse.png)
{: refdef}


# Part 1: Building a table of known captchas

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
The captchas received always contain 4 alphanumeric characters, in capital letters:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/aliexpress/captcha.jpg)
{: refdef}

We can solve them using tesseract (https://github.com/tesseract-ocr/tesseract):
```bash
root@kali:~# tesseract --psm 8 captcha.jpg - --dpi 100
— MRRP
```
There are ways to improve tesseract's accuracy by modifying the image. Here are two very basic transformations I use:
```
convert captcha2.jpg  -type grayscale -quality 100 -density 300 grayscale.jpg  
convert captcha2.jpg  -level 50% -quality 100 -density 300 contrast.jpg
```
In this case it did not really help, but it is a good tip to keep in mind when handling captchas. There are plenty of forums and blog posts proposing much more advanced image processing methods for OCR .  


Now, to make this more efficient, we can optimize the captcha's lookup time and save precomputed results. A problem quickly came up in my reasoning: two similar images had **different checksums** (I wanted to use the image's md5 for indexing). I dug a little deeper to understand why these pictures, yet alike pixel per pixel, were different:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/aliexpress/bindiff.png)
{: refdef}

The server generates different images by modifying **the two last bytes of the picture!** The changes are impossible to perceive, there is no impact on the image, but the hashes differ. So I could still index my images using a checksum, but first I had to remove the last two bytes of each file.  
I decided to opt for another, simpler way to index my files: the **number of random bytes is always the same**, and pictures displaying different captchas have different sizes. So I can index my pictures using their bytes count!
```python
capt_hash[1571] = "7FKT"
capt_hash[1749] = "9GNN"
capt_hash[1799] = "DBPR"
capt_hash[1818] = "UH9G"
capt_hash[1841] = "RCVC"
capt_hash[1867] = "MRRP"
capt_hash[1900] = "EFU2"
capt_hash[1927] = "USN8"
capt_hash[1935] = "BWSJ"
capt_hash[1965] = "5UFH"
```

So simply put, no need to solve the captcha anymore, the length of the image received is enough to know what the input should be!

# Part 2: Limitations

The automatic resolution of captchas challenges using tesseract is not very accurate for the moment. Building the dictionary manually is not very hard as the number of captchas is very limited. But to take this further, the OCR method must be improved.

There seems to be extra protections against this form, which I did not explore. In fact, when sending the captcha's response, it is also expected to send a parameter named "captchaToken"
```
{"answer":"DBPR","captchaToken":"S10bb4dcdf0b3252825a76f4f803310a277f618d6bbe2893267eb379ee61c82a2a842f3b8ee064997f600430705cd5246e64ec5e81d671284efe9547475a00b9a003db505623d8e41ba2dc70f8dccf6977e66a1eb08a67dd3e379c13938e896784f3bd47f69ce1edc979a938dc61a0f7aae0db6beb8f6bc3b6178ecc3fa3e2a1dcdc51f0e3b866d56da16de672d83f0b9e9700dc1848ee697daf304c2d2722b1d253f99065a787a5ca2b3dc33311dabbf16342ff20b77b6355188f14f7a7425826ada937221d0d18bded87dc63bbc52fffbc81e251f52e835152e0d275324451e3f3bc3eef76ebb840f713e00d44548f09e8750bfde2d5d703c7f0a5444ab60547e99bda820b98bb91d7a590a2f5cb1e9dd846b719fd408223e629a75c92cbf9a1d708a2f4ab8b8f578c5671dfb5dbd17ffefe6128dac6b168b7d6b386cbf4d0cde74e377e443c3ce92c34992a57cac28931e3d2740b199306771187d8bb019f832f7b86699e1ea6b22a3abd1"}&a=CFUS_APP_HAVANALogin&t=CFUS_APP_HAVANALogin:XXXX
```
Supposedly it is randomly generated and uniquely identifies a captcha response submission, but we can already see they are not purely random and contain a sort of structure and headers:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/aliexpress/captcha_token.png)
{: refdef}

This token comes with the captcha image file, and it does not really prevent from automatic form submission.  
There are many other parameters at stake in these requests (like a signature for example) and not knowing their exact roles, I will not mention them here.

# Part 3: Resources
[Tesseract](https://muthu.co/all-tesseract-ocr-options/)  
[Mathieu Larose's blog/image processing techniques for solving captchas](https://mathieularose.com/decoding-captchas/)  

Stay classy netsecurios!
