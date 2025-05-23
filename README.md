# mbedTLS.ldg

Library using the LDG system and the mbedTLS 3.6.3 library.
Brings SSL/TLS layer (recent TLSv1.2 TLSv1.3) to clients applications using MiNTnet and STinG/STiK TCP layers.

Used by:  
- Troll, usenet and email client.  
- Meg, mailbox checker and spam eraser.  
- Litchi, ftp client.  

Targets: 68000, 68020-060, ColdFire

Other programs can use it, please read the how-to and functions calls in the st-guide documentation.

# installation for makefiles

- pre-requisite: different targets of libmbedtls.a, libmbedcrypto.a, libmbedx509.a, libldg.a in /opt/cross-mint/m68k-atari-mint/lib/

- in an empty folder,  
   ```mkdir ./build/68000```  
   ```mkdir ./build/68020```  
   ```mkdir ./build/ColdFire```  

- get [mbedtls.ldg.r3.zip](https://ptonthat.fr/files/polarssl/sources/mbedtls.ldg.r3.zip) and unpack the contents of /mbedtls.ldg/ to  
   ```./README.md```  
   ```./Makefile```  
   ```./main.c```  
   ```./transport.h```  
   ```./mbedtls.ldg.xcodeproj```  

- mbedtls.ldg.xcodeproj is for Xcode 16.3, you may not need it if you use something else.
