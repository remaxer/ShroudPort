#ShroudPort - Defends your computer from SYN Stealth scanning

### Copyright (C) 2012  REmaxer <remaxer@hotmail.it>

##Prerequisites

* Libpcap

## Build

	$ cd src
	$ gcc -o shroudport shroudport.c -lpcap

## Run

	$ ./shroudport <IP to shroud> [existing ports...] 


