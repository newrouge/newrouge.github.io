---
layout: post
tags: redteam
title: Tales of the Crimson Foes
---

The Tales of the Crimson Foes<br>
*A compilation of red team and pentest stories*


{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/crimson.jpg)
{: refdef}

At long last, the untold stories of the realm's secrets wardens. I hereby present to you: The Tales of the Crimson Foes, *a compilation of red team and pentest stories*.

# Prologue

We have been pretty busy lately, mainly with red team engagements. That goes to explain why this blog is growing more and more inactive. On the other hand, we have **plenty** to tell. And so what you will find here is a lot less technical than you might be used to, if you read our posts before. Here lies the main gist, I hope you have a good read:

> &rarr; Beware, reader, as this will **not** be a simple arrogant criticism, but rather a series of comical and relatable situations we found ourselves in, sprinkled with self reflection and introspection: <br>**what could we have done better ?**<br>
> &rarr; As my fellow Crimson Foes are aware, the technical aspect of the task can easily be overshadowed by haughty manners, or erroneous conveyance. Hence, displaying diplomacy and being understanding is a **very** important part of what we do.<br>
> &rarr; As obvious as it can be: no confidential information will be displayed here. As a matter of fact: *all characters and events in this tale --even those based on real people-- are entirely fictional, any resemblance with actual events is also fortuitous.*<br>

# Chapter 1 - The forbidden scroll of truth

It was a chill morning in November, and although I strongly dislike the cold gusts of wind that make the traveller's nose runny, I was excited to visit a new place I had never seen before. This mission was important. As I always do, I made sure I had the right companionship with me. That time, it was a man named M. He was the one who taught me the arts and crafts of Windows and Active Directory, at least most of it. So I knew we were the right force for the matter at hands.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/beach.jpg)
{: refdef}

As we, the Crimson Foes, enter the small village, the mist settles down slowly and the sun starts shining in an eerie way. Faces turn and eyes are curious: we are seemingly out of place.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/village.jpg)
{: refdef}

We are warmly greeted at the entrance of the building. A cheerful lady shows us the premises, and introduces us to the local workers. We even have our own room for ourselves. The day can start. The hack can happen.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/hack.jpg)
{: refdef}

8 A.M: we enter the main network. By lunch time we have the castle's keys. Nothing too surprising so far, they were not expecting *us*. Most things go just as usual.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/coffee.jpg)
{: refdef}

As the operation can be quite costly on the long run, our brains start to run dry. We decide to go for food and refreshments, as the clock strikes 12. The weather has now cleared, as it often does during the day in this region of the country. A local tavern quickly catches our interest, as it serves Turkish specialties us Crimson Foes relish.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/kebab.jpg)
{: refdef}

Even more eyes lay on the Crimson Foes as they replenish themselves with what does not seem to be a local meal, nor is it consumed frequently in these surroundings. Villagers grow wary, and curious. This won't stop us. We are on a mission.

The end of the day arrives mechanically, without thinking about the passage of time. By then, most local workers in the premises we occupy have left home already. It has already been dark for a long time before I realize it. I am pretty sure M. hasn't even noticed yet. He too, is on a mission. 

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/night.jpg)
{: refdef}

I call it a night. We have a few more days, let's not burn everything too quickly, we will likely need more energy in the coming days. Especially with what we were about to discover.
However M. is restless. Like most Crimson Foes, his mind is always on the lookout for details, leftover information, for us to explore and exploit.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/call.jpg)
{: refdef}

As the darkness now fully surrounds the little beach town, the mist has come back. A soft call breaks the silence like a sharpened sword swiftly shreds thin paper sheets.

> "M.: A., come. You should see this."<br>

M. is a very moderate man of a few words. A quiet and sharp man, as we like to call it in our country "une force tranquille". He does not exaggerate. He does not embellish. He uses people's attention very wisely. I knew better than not to take his advise seriously.

> "A.: What is it that delays my ale my dear companion?"<br>
> "M.: They left an artifact."<br>

he said, mincing his words.

> "M.: You will like it."<br>

His grinning smile made me understand only but one thing: Whatever he found will ultimately lead us to **more work**.

> "M.: 'Tis a scroll, a most perilous one."

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/printer.jpg)
{: refdef}

A leftover artifact in a printing machine, common and usually harmless. Except this time. <br>
The printer was located in a public area of the premises, which was commonly visited by villagers and travelers. Needless to say that the risk is only made greater by that single observation. But the content of the file is what made this story the legend we will tell our grandchildren:

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/scroll.jpg)
{: refdef}

It was there, the **forbidden scroll of truth**, the holy grail, containing every local workers personal information and **plaintext currently valid passwords**. We knew exactly how **valid** and **currently used** they were, as we had spent a part of the afternoon breaking them using the dark prowess of the legendary RTX 4090.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/ocean.jpg)
{: refdef}

> "A.: Lord, why choose me?"<br>

I thought, looking at the ocean as if it carried answers.

> "A.: Why can't I be the bearer of good news for once alas?"<br>
> "Lord.exe: The path you chose ultimately bequeathed upon you this very duty, as you shall be the bringer of doom and despair, for a slighty higher salary."<br>

M. looked at me like he felt compassion. He knew I had to find the person responsible, and bring that very issue to them. It might not be pleasant. But it is our mission. From there, the sequence of steps drew itself quite easily and quickly in my mind:

1. root the printer
2. access the printing queue history
3. find the originating IP that printed the unholy document
4. find who was behind this
5. understand what might possibly have brought them down to that path

In this very specific case, direct confrontation is pointless. It might actually even might make things worse. Diplomacy, measure, and understanding have to be used, so that **this** never happens again.
<br><br>

The **hunt** was on, and it was not long before M. and I found the culprit: the lady that greeted us on the very first morning.

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/lens.jpg)
{: refdef}

As I entered her office, the look in her eyes changed. It was not the warming and cheerful lady we had met a few days back. Warmth had been replaced with anxiety.

> "A.: We found a document, on Monday. A document no living soul should own."

She knew, she was not here to fight. She wanted answers to the many questions she had had for all these years, without anybody ever providing anything.

> "Lady: I know I shouldn't have done this, but how else am I supposed to manage accounts?"

This sad truth hurt more than it should, as us Crimson Foes know already. These responsibilities often land on people that did not ask for, nor know how to do it. Now was the time to show that seeking guidance is the correct path, and guidance we provide.

> "A.: My lady, several problems arise from our discoveries. The main one being that **you should not know your workers passwords**"<br>
> "Lady: But my fellow IT provider assured me that setting one time passwords for everybody would take weeks"<br>
> "A.: Liars my lady, I am afraid. 'Tis only but one box to tick."<br>
> "Lady: Can you show me?"<br>

She asked, anguishly. Visibly she was not used to have her questions addressed.

> "A.: In due time, we will, my lady. But first, let me address another aspect of our little issue."<br>
> "Lady: Please, proceed"<br>
> "A.: Now you are aware that this printer is accessible by commoners? Why print there?"<br>
> "Lady: No choice was mine then sir, as the other printers were out of ink."<br>

It is what it is, what is done is done and now we deal with it.

> "A.: What is your most precious resource cannot be thrown to wolves. Shall it never happen again."<br>

The words were sharp, but respectful. Strong enough to teach, soft enough to show understanding. This is the way of the Crimson Foes.

# Resolution

{:refdef: style="text-align: center;"}
![_config.yml]({{ site.baseurl }}/images/crimson/five.jpg)
{: refdef}

Our work was done here. Nobody else needed to know about that. We like the idea that people can make mistakes, without everybody knowing about it and shaming them, even passively. So we show decency. <br>

The mission was over, we left as we arrived, discreetly. The lady thanked us warmly again before we left. Our trouble was long gone. Now she had all the keys.

Thats all folks.

# Epilogue

I initially wanted to write several anecdotes but got carried away with AI images generation and this one took me a **lot** longer than expected. If that type of content pleases you, feel free to let me know, as we Crimson Foes have many other tales to tell.



Stay classy netsecurios!

### Tales of the Crimson Foes
---
11 November 2024 | Happy Remembrance Day to all
---
