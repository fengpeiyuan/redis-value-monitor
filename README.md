# Redis Value Monitor 

* Frequent bigger redis value will block network IO, how to monitor?
* The redis-cli --bigkeys using strlen, hlen, llen, scard, zcard commands which return length not size.
* The 'debug object' command can show value infomation, but cannot be used in lua script.
* Here we sniffe network card using pcap. 

## Usage

* Use -i(or --interface) option to choose a device to sniffe
  Following commend is sample for this 
	
			redis-value-monitor -i eth0	
* Use -p(or --port) option to set redis port to monitor
  Following commend is sample for this 
	
			redis-value-monitor -p 6379	
* Use -m(or --maxvalue) option to set amount(byte), more then this value will be printed. 

			redis-value-monitor -m 10	
## Output format
	* Print like this.

	10.209.10.63:13348 -> 10.209.10.63:10443        14      MGET BRAND_20001613
	10.209.11.16:36777 -> 10.209.10.63:10443        22      MGET STORE_BRAND_ID_2061660
	10.209.11.16:36777 -> 10.209.10.63:10443        14      MGET BRAND_10462
	10.209.11.34:59986 -> 10.209.10.63:10443        22      MGET STORE_BRAND_ID_2061382
	10.209.10.33:55371 -> 10.209.10.63:10443        14      MGET BRAND_10001284
	10.209.10.64:39708 -> 10.209.10.63:10443        22      MGET STORE_BRAND_ID_2060232
	10.209.11.63:24437 -> 10.209.10.63:10443        22      MGET STORE_BRAND_ID_2059758
	10.209.11.63:24437 -> 10.209.10.63:10443        14      MGET BRAND_10001900
	10.209.10.33:45306 -> 10.209.10.63:10443        14      MGET BRAND_10000807

## Install

* In order to install this project, libpcap(download from http://www.tcpdump.org/) should be installed first. Before install libpcap, m4(like m4-1.4.13), bison(bison-2.4) and flex(flex-2.5.35) should be downloaded and installed. You may find them in http://ftp.gnu.org/gnu/.

## License

Copyright (c) 2014-2015, Peiyuan Feng <fengpeiyuan@gmail.com>.

This module is licensed under the terms of the BSD license.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
