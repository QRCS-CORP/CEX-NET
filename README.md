#### This library is officially retired!

I haven't updated this in years, and it was only ever supposed to be a prototype, and served its purpose well..
Many of the asymmetric ciphers and signature schemes contained in this library have changed, 
undergoing analysis and improvement during the NIST Post Quantum competition.
These primitives have been installed in the new library CEX++: https://github.com/Steppenwolfe65/CEX, which took up where this one ended, 
and that library contains many other changes and additions, and should now be considered the official version of the CEX library.
Because of these changes, and because a better alternative is available, 
this work should now be considered as only relevant for historical purposes.



### Version 1.5
This is version 1.5; Asymmetric ciphers have been added, along with preliminary work on the DTM-KEX.
Dual License: NTRU and DTM-KEX are GPLv3, everything else is MIT.

Major additions are: Ring-LWE, NTRU, McEliece, GMSS, Rainbow, Volume and Package factories, and the DTM key exchange protocol.

Library has tripled in size from the last release (now 46k+ lines), too much to explain here, I'll update the article when I get a chance..

Update v1.57, all variants of Blake2 added, sequential and parallel; 2B, 2BP, 2S, and 2SP.

CEX++: https://github.com/Steppenwolfe65/CEX

Article: http://www.codeproject.com/Articles/828477/Cipher-EX-V

API Help: http://www.vtdev.com/CEX/Help/index.html

Homepage: http://www.vtdev.com/cexhome.html


This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if these extended symmetric cipher key lengths (512 bit and higher), and algorithms are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.

