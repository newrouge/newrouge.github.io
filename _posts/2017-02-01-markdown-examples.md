---
title:  "Secret - HackTheBox"
layout: post
---

## Info:

This machine had pretty sweet learning curve for new comers, exploiting command injection to get foorhold and core-dump abuse to get root on machine. 

![Secret](https://user-images.githubusercontent.com/79413473/160227585-1c832d19-b152-4d08-835e-da9b8bc33809.png)

## Recon:

Starting with portscan, we get 3 open ports.
```
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    syn-ack Node.js (Express middleware)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
on port 3000 node js application is running and port 80 has docs for same application. And there is source-code avialable for downlaod.

![Screenshot from 2022-03-26 13-27-24](https://user-images.githubusercontent.com/79413473/160230465-f5ffa54b-a01b-489e-b57a-13692e6daeae.png)

Docs shows how using API we can register new user and login it will then give JWT token for that user. there is *theadmin* user which is admin. 
Direcctory fuzzing also reveal already known paths

![Screenshot from 2022-03-26 13-32-59](https://user-images.githubusercontent.com/79413473/160230614-6054b973-85ad-48b8-92e8-775c33310fd1.png)

## Foothold: Command Injection

Reading docs let's register a user by sending post requests to **/api/user/register**.

![Screenshot from 2022-03-26 13-39-00](https://user-images.githubusercontent.com/79413473/160230788-55cde1cf-1e82-4848-aceb-38b3118e0ce8.png)

Login to get **auth-token**

![Screenshot from 2022-03-26 13-39-54](https://user-images.githubusercontent.com/79413473/160230811-91a2fda0-e80d-4c5f-8115-fb6b3357c939.png)

A JWT token is set as our auth-token and using this we can make request to **/api/priv**

![Screenshot from 2022-03-26 13-40-58](https://user-images.githubusercontent.com/79413473/160230842-217f1ac4-ec99-4ac8-b21b-c5d26ef78720.png)

And it tells we are normal user. Let's decode our jwt token at [jwt.io](https://jwt.io/) 

![Screenshot from 2022-03-26 13-41-54](https://user-images.githubusercontent.com/79413473/160230870-a819a7b5-1374-4591-909f-ddf5cc5094eb.png)

### Finding vulnerable route

Looking into source code we downloaded. There is and interesting function in */routes/private.js* file

```

router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
``` 

The endpoint */api/logs*   is vulnerable to command injection as user input *file* is directly passed into exec command. But for that we have to somehow become **theadmin** user. But we don't have any *secret* to forge JWT token. One i tried using was secret=secret as listed in **.env** file but that didn'w work. 

### Finding .git folder
Let's examine downloaded source-code once again. 

![Screenshot from 2022-03-26 14-22-52](https://user-images.githubusercontent.com/79413473/160232205-21499705-8b87-4373-845f-61d3114dd0e6.png)

There is folder **.git** which we didn't notice earlier. Let's change directory and see what it offers.

using **git log** command we can list all the comits that happened.

![Screenshot from 2022-03-26 14-26-18](https://user-images.githubusercontent.com/79413473/160232292-4f0df360-36ce-45c6-bd24-783e7bb13baa.png)

second commit is interesting as it says*removed .env* where our secret is stored let's look into that using **git show <commit_id>**.

![Screenshot from 2022-03-26 14-28-28](https://user-images.githubusercontent.com/79413473/160232371-8c2abeb6-ccbc-4b70-aa6c-06ce8ae2a25b.png)

As it shows, older JWT secret is replaced with *secret*. Let's use this to sign our new auth-token and get admin. 

```
gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
```
As code only checks username from jwt token, we just have to change that to **theadmin** and give it secret obtained.

![2022-03-26_14-34](https://user-images.githubusercontent.com/79413473/160232598-be4213be-0ec1-4f99-8ebe-dd2c7dc1067e.png)

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjNlYzk2NGFiN2I1YzA0NTkxOGJkOTIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJpYXQiOjE2NDgyODE5ODB9.fjQzAdpsLN1B7_0gnLv_hWN_E2LAG7KuIMdJhjkm0vM
```

Let's put this new JWT into request and verify. 

![Screenshot from 2022-03-26 14-35-27](https://user-images.githubusercontent.com/79413473/160232644-29b4440e-218f-4029-9202-f12b16171e64.png)

### Command injection:

![Screenshot from 2022-03-26 14-37-12](https://user-images.githubusercontent.com/79413473/160232709-d6bc7a32-8e4f-4478-b614-2094cb9268c9.png)

As it requires a file name to show git logs. Let's do that

![Screenshot from 2022-03-26 14-38-34](https://user-images.githubusercontent.com/79413473/160232751-44764feb-0ebb-4dcc-acee-fcf1840f04f2.png)

As shown our input *"ip"* is concatenated in command. Let's get code execution with *"ip;id"*

![Screenshot from 2022-03-26 14-39-48](https://user-images.githubusercontent.com/79413473/160232794-3ebc6519-f2e0-4e29-84be-0556c716b6fd.png)

Let's get shell from here

![Screenshot from 2022-03-26 14-43-51](https://user-images.githubusercontent.com/79413473/160232959-078afbe4-47f9-49f7-ae11-70b5baf792cc.png)

![Screenshot from 2022-03-26 14-43-33](https://user-images.githubusercontent.com/79413473/160232963-7db37eb3-2cb4-4bed-b732-15f9b3835151.png)


## Privilege escalation: Abuse Core-Dump to read files

In */opt* there is a suid binary **count** which counts number of lines, characters, words in a file. Being suid binary it can also read privileged files. we just have to find a way to extract what it reads from memory. If you try to run suid binaries with some external tool like gdb, suid privilege will drop.

There is also *code.c** file given for the binary. One important thing i noticed was this

![Screenshot from 2022-03-26 15-48-23](https://user-images.githubusercontent.com/79413473/160235154-8a4fc433-955f-4640-82f4-36019a3bc4d9.png)

**[PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/prctl.2.html)** will decide whether to generate core-dump when crashing. And this crash can also contain sensitive info. Google core dump privilege escaltion gave [this](https://schulz.dk/2021/10/25/using-core-dumps-for-linux-privacy-escalation/) blog.

Which states that which type of process kill signals will generate core_dump.

![Screenshot from 2022-03-26 15-51-05](https://user-images.githubusercontent.com/79413473/160235246-67feccdb-1898-43da-a4e7-567a118d1966.png)

Get another shell in another pane to kill the process after reading the sensitive file.

### Dumpping core:

Run the binary from one pane

![Screenshot from 2022-03-26 15-54-15](https://user-images.githubusercontent.com/79413473/160235320-24b7607a-82fa-42bc-acfa-4de8b7df6a78.png)

Now kill this process from another pane, [this](https://bash.cyberciti.biz/guide/Sending_signal_to_Processes) blog has detailed explaination on how to send kill signals. 

using **SIGBUS** signal we kill the process , `killall -s SIGBUS count`.

![Screenshot from 2022-03-26 15-56-31](https://user-images.githubusercontent.com/79413473/160235415-e091a85c-13af-408d-a101-fedd28f9030c.png)

and it kills the process in another pane & generates the core dump in */var/crash*

![Screenshot from 2022-03-26 15-57-31](https://user-images.githubusercontent.com/79413473/160235438-059f3738-9b8f-46ea-b5cb-9018d5755149.png)

![Screenshot from 2022-03-26 15-58-33](https://user-images.githubusercontent.com/79413473/160235462-90870446-3e2c-4298-ae24-e4a0af1da7ec.png)

Now this **.crash** file has all the information we need but we can't just read it from here, as i tried decoding base64 value in it. it doesn' work.

Little bit of google gave [this](https://askubuntu.com/questions/434431/how-can-i-read-a-crash-file-from-var-crash), using **apport-unpack**, which is luckily installed on system, we can generate useful Human-redable information.

`apport-unpack _opt_count.1000.crash crash` will genrate crash directory with all information.

![Screenshot from 2022-03-26 16-02-10](https://user-images.githubusercontent.com/79413473/160235589-be697c50-2721-43b1-96fd-63b6696bcd8e.png)

and in CoreDump file we can see the contents of file we read. 

![Screenshot from 2022-03-26 16-03-18](https://user-images.githubusercontent.com/79413473/160235620-059ca31b-a91f-4770-9a7e-dfae1f1d6f81.png)

To get shell let's read root's ssh keys. or read crack the password obtained from /etc/shadow or directly read root flag your choice.

Let's again create the core-dump after reading */root/.ssh/id_rsa* & read the CoreDump conntent

![Screenshot from 2022-03-26 16-06-15](https://user-images.githubusercontent.com/79413473/160235714-4a487b5a-2bb6-4a48-989c-f4433c63b6c2.png)

and using this key we can login as root.

```
ssh -i id_rsa root@10.10.11.120
```
![Screenshot from 2022-03-26 16-09-52](https://user-images.githubusercontent.com/79413473/160235819-452d5b47-4c0f-414f-afe0-eeb903d54d0c.png)

That's how we get root on this machine and don't forget to remove your scripts and crash dump from machine before leaving. 

Thank you for reading.

Twitter: [Avinashkroy](https://twitter.com/Avinashkroy)
