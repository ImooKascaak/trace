# trace - print the route packets trace to network host

Version 1.0.0, June 2020

<pre><code>$ ./trace [OPTIONS] &lt;ip-address&gt; </code></pre>

# Description

Tracking route packets taken from an IP network on their way to a given host. Program works with UDP packets which are sent to the destination address with TTL value. Based on these packets program receive ICMP time exceeded messages. Parsing these messages program determine destination address eventually domain name of gateways all devices step by step until destination is unreachable. Based on ICMP message type and code next step is determined.

### Principle of communication:

<pre>
source                       destination  
  |      UPD packet with TTL      |  
  |------------------------------>|  
  |                               |
  |                               |
  |waits                          |
  |up to                          |
  |2 sec                          |
  |                               |
  |      ICMP TIME_EXCEEDED       |
  |<------------------------------|
  |                               |
</pre>

Program contains DNS extension. Script can be entered with IP address or domain name and for each router, the trace performs a reverse PTR query (attempting to obtain an IP address domain name). After send of UDP packet, program waits on socket up to 2 seconds. If the ICMP TIME_EXCEEDED message is received within 2 seconds then the next information are printed out in format:

``
<ttl-value>   <domain-name> (<ip-address>)    <transit-delay(ms)/anotation>
``

### Anotations:  
**H!**  - host unreachable  
**N!** - network unreachable  
**P!** - protocol unreachable  
**X!** - communication administratively prohibited  

Otherwise sign '**\***' indicates timeout for certain TTL.  

A sample use and output might be successful:  
<pre>
$ ./trace 172.217.23.238  
1	bda-boz.fit.vutbr.cz (147.229.176.1)		0.929 ms  
2	pe-ant.net.vutbr.cz (147.229.254.205)		0.834 ms  
3	rt-ant.net.vutbr.cz (147.229.253.233)		0.125 ms  
4	r98-bm.cesnet.cz (147.229.252.17)		0.63 ms  
5	195.113.235.109 (195.113.235.109)		8.184 ms  
6	r2-r93.cesnet.cz (195.113.157.70)		4.829 ms  
7	108.170.245.49 (108.170.245.49)		4.788 ms  
8	108.170.238.155 (108.170.238.155)		4.897 ms  
9	prg03s06-in-f14.1e100.net (172.217.23.238)		4.76 ms  
</pre>

Or:

<pre>
$ ./trace lol.cz  
1	bda-boz.fit.vutbr.cz (147.229.176.1)		2.572 ms  
2	pe-ant.net.vutbr.cz (147.229.254.205)		0.933 ms  
3	rt-ant.net.vutbr.cz (147.229.253.233)		0.128 ms  
4	r98-bm.cesnet.cz (147.229.252.17)		0.647 ms  
5	195.113.235.99 (195.113.235.99)		5.304 ms  
6	nix-sitel.centronet.cz (91.210.16.7)		4.663 ms  
7	*  
8	217.195.167.222 (217.195.167.222)		4.699 ms  
9	beta.web.pb.cz (109.72.0.11)		X!  
</pre>

Note that the gateway 9 indicates communication administratively prohibited and gateway 7 hops away either don't send ICMP TIME_EXCEEDED message or sent message with a TTL too small to reach us. It indicates timeout what mean that program didn't receive response within 2 seconds. If the program obtains result in some kind of unreachable, trace will give up and exit.

# OPTIONS

**-f**, **first_ttl** Specifies TTL used for the first packet. Implicit value is 1.  

**-m**, **max_ttl** Specifies maximum TTL. Implicit value is 30.  

**\<ip-address\>** IPv4/IPv6 destination address or domain name.  

# FILES

src/trace.cpp  
src/makefile  
README.md  

# AUTHOR

Imrich Kascak
<xkascak1@mendelu.cz>
<ep1602@edu.hmu.gr>

# BUGS

Program ends by printing out error message on standard error output when some error occurs. Detail info about error guarantee function _perror()_.
