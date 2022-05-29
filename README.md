# HACK.INI 10th edition 2022

## author : Aghiles Gharbi

## teamName : AnonyBlasBlas

## junior : 2nd place

## senior : 5th place

## individual : 5th

## team members:

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