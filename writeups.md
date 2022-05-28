# Web

## baby lfi

> Author : Anis Chebah

> link : https://baby-lfi.challs.shellmates.club/

the website has a simple basic lfi (local file inclusion) in the 'language' GET parameter where it just passes the language parameter to include function in php without cheking.

so the solutuin was just giving the file to read in the language parameter.
> exploit : 'https://baby-lfi.challs.shellmates.club/?language=/etc/passwd'

> flag: shellmates{10CA1_F11e_1Nc1US10n_m4y_r3ve4l_in7Er3st1nG_iNf0Rm4t1on}

## lfi

> Author : Anis Chebah

> link : 'https://lfi.challs.shellmates.club'

the website has a simple basic lfi (local file inclusion) in the 'language' GET parameter but in this time they added a filter for (relative paths by removing the '../') where in my case i used the same payload to get the flag because our payload dosn't contain '../'

> exploit : 'https://lfi.challs.shellmates.club/?language=/etc/passwd'

> flag: shellmates{SH0uLD_H4Ve_MadE_th3_checK_recuRS1V3}

## baby lfi 2

> Author : Anis Chebah

> link : 'https://baby-lfi-2.challs.shellmates.club/'

the website has a simple lfi (local file inclusion) in the 'language' GET parameter where it passes the language parameter to include function after checking if it contains "./languages/" (my best guess), but this one it was a bit tricky because i "language=languages/" should work without the './'.

so the solutuin was just giving the file to read in the language parameter.
> exploit : 'https://baby-lfi-2.challs.shellmates.club/?language=./languages/../../../../../../../etc/passwd'

> flag: shellmates{yOU_M4De_yOUr_waY_7hRough_iT}