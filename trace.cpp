/*
 * Project: trace.cpp
 *
 * Author:  Imrich Kascak
 * Login:   ep1602@edu.hmu.gr
 * Course:  Multimedia Application Development
 *
 * Usage:   ./trace [-f first_ttl] [-m max_ttl] <ip-address>
*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <netdb.h>
#include <linux/errqueue.h>

#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>

using namespace std;

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

// TTL for the first packet, implicit 1
#define FIRST_TTL 1
// max TTL, implicit 30
#define MAX_TTL 30

#define SO_EE_ORIGIN_NONE    0
#define SO_EE_ORIGIN_LOCAL   1
#define SO_EE_ORIGIN_ICMP    2
#define SO_EE_ORIGIN_ICMP6   3

/**
 * Structure keeps values of argument from command line.
 */
struct Params {
	int			first_ttl;
	int			max_ttl;
	string	ip_addr;
	int			is_ip4_addr;
	int			ecode;
};

/**
 * Structures for IPv4 and IPv6.
 */
struct sockaddr_in dst;
struct sockaddr_in6 dst6;

// prototypes of functions
unsigned short checksum(void *b, int len);
int recv_err(int ttl, int socket, struct timeval after_send, int is_ipv4_addr);
int create_socket(int is_ipv4_addr, string ip_addr);
void print_err(int ecode);
Params parse_args(int argc, char* argv[]);
string inverse_dns_lookup(char* ip_addr);




/*----------------------MAIN----------------------*/

int main(int argc, char* argv[]) {
  Params params;
	// Parse args
  params = parse_args(argc, argv);
  if (params.ecode != 0) print_err(params.ecode);
	// Set TTL
	int time_to_live = params.first_ttl;
	// ICMP message
	struct icmphdr icmp_msg;

	struct timeval after_send;
	// Create socket
	int socket = create_socket(params.is_ip4_addr, params.ip_addr);

  do {
		// Send UDP packet
		if (params.is_ip4_addr == 1) {
			// Define socket options for IPv4
			if (setsockopt(socket, IPPROTO_IP, IP_TTL, &time_to_live, sizeof(time_to_live)) < 0) {
				perror("Could not process setsockopt() [IPv4].");
				return EXIT_FAILURE;
			}
			if (sendto(socket, (char*)&icmp_msg, sizeof(icmphdr), 0, (struct sockaddr*)&dst, sizeof(struct sockaddr_in)) < 0) {
		      perror("Could not process sendto() [IPv4].");
		      return EXIT_FAILURE;
		  }
			gettimeofday (&after_send, NULL);
		}
		else {
			// Define socket options for IPv6
			if (setsockopt(socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &time_to_live, sizeof(time_to_live)) < 0) {
				perror("Could not process setsockopt() [IPv6].");
				return EXIT_FAILURE;
			}
			if (sendto(socket, (char*)&icmp_msg, sizeof(icmphdr), 0, (struct sockaddr*)&dst6, sizeof(dst6)) < 0) {
		      perror("Could not process sendto() [IPv6].");
		      return EXIT_FAILURE;
		  }
			gettimeofday (&after_send, NULL);
		}

		// Receive ICMP time exceeded message
		int end = recv_err(time_to_live, socket, after_send, params.is_ip4_addr);
		if (end == 777) break;
		else time_to_live++;
  } while(time_to_live <= params.max_ttl);
	close(socket);
  return 0;
}
/*------------------END-OF-MAIN-------------------*/




/**
 * Receiving ICMP time exceeded messages.
 * @param ttl: time to live
 * @param socket: previously created UDP socket
 */
int recv_err(int ttl, int socket, struct timeval after_send, int is_ipv4_addr)
{
	int response;
	char buffer[512];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr* cmsg;
	struct icmphdr icmph;
	struct sockaddr_storage target;

	// Timeout set for waiting to received message
	fd_set rfds;
	struct timeval timeout;
	int retval;
	// Watch stdin (fd 0) to see when it has input
	FD_ZERO(&rfds);
	FD_SET(socket, &rfds);
	// Wait up to two seconds
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	retval = select(sizeof(rfds), &rfds, NULL, NULL, &timeout);
	// Don't rely on the value of timeout now
	if (retval == -1) {
		perror("select()");
		return EXIT_FAILURE;
	 }
	else if (retval) {}
		//cout << "Data is available now." << endl;
	else {
		cout << ttl << "\t" << "*" << endl;
		return 666;
	}

	for (;;) {
		iov.iov_base = &icmph;
		iov.iov_len = sizeof(icmph);
		msg.msg_name = (void*)&target;
		msg.msg_namelen = sizeof(target);
		msg.msg_iov = &iov; //NULL
		msg.msg_iovlen = 1; //0
		msg.msg_flags = 0;
		msg.msg_control = buffer;
		msg.msg_controllen = sizeof(buffer);

		response = recvmsg(socket, &msg, MSG_ERRQUEUE);
		if (response < 0) continue;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			/* IP level */
			if (cmsg->cmsg_level == SOL_IP || cmsg->cmsg_level == SOL_IPV6) {
				/* We received an error */
				if (cmsg->cmsg_type == IP_RECVERR || cmsg->cmsg_type == IPV6_RECVERR) {
					/* Get data from header */
				 	struct sock_extended_err* sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
					/* Get info about address */
					//struct sockaddr_in* adr;
					//struct sockaddr_in6* adr6;
					//if (is_ipv4_addr == 1) adr = (struct sockaddr_in*)SO_EE_OFFENDER(sock_err);
					//else adr6 = (struct sockaddr_in6*)SO_EE_OFFENDER(sock_err);

					if (sock_err) {
						// get time when message received
						struct timeval after_receive;
						gettimeofday(&after_receive, NULL);
						// count latency
						float latency = (float)(after_receive.tv_usec - after_send.tv_usec) / 1000.0;
						if (latency < 0) latency += 1000;

						char str[1024];
						const char* ip_address;
						string hostname;
						/* We are interested in ICMP errors */
						if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP || sock_err->ee_origin == SO_EE_ORIGIN_ICMP6) {
							if (is_ipv4_addr == 1) { /* IPv4 */
								/* get address - if universal then sockaddr_storage */
								struct sockaddr_in* sin = (struct sockaddr_in*)(sock_err + 1);

								ip_address = inet_ntop(AF_INET, &(sin->sin_addr), str, 1024);
								hostname = inverse_dns_lookup((char*)ip_address);
								if (strcmp(hostname.c_str(), "") == 0) hostname = ip_address;

								/* Handle ICMP errors types */
								if (sock_err->ee_type == ICMP_TIME_EXCEEDED) {
									cout << ttl << "\t" << hostname << " (" << ip_address << ")\t\t" << latency << " ms" << endl;
									return 666;
								}
								else if (sock_err->ee_type == ICMP_DEST_UNREACH) {
									switch (sock_err->ee_code) {
										case ICMP_PORT_UNREACH:
											// port unreachable
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t\t" << latency << " ms" << endl;
											return 777;
										case ICMP_NET_UNREACH:
											// network unreachable
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t\t" << "N!" << endl;
											return 777;
										case ICMP_HOST_UNREACH:
											// host unreachable
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t\t" << "H!" << endl;
											return 777;
										case ICMP_PROT_UNREACH:
											// protocol unreachable
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t\t" << "P!" << endl;
											return 777;
										case ICMP_PKT_FILTERED:
											// communication administratively prohibited
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t\t" << "X!" << endl;
											return 777;
										default:
											break;
									}
								}
							}
							else if (is_ipv4_addr == 0) { /* IPv6 */
								/* Get info about address */
								struct sockaddr_in6* sin = (struct sockaddr_in6*)(sock_err + 1);

								ip_address = inet_ntop(AF_INET6, &(sin->sin6_addr), str, 1024);
								hostname = inverse_dns_lookup((char*)ip_address);
								if (strcmp(hostname.c_str(), "") == 0) hostname = ip_address;

								if (sock_err->ee_type == ICMP6_TIME_EXCEEDED) {
									cout << ttl << "\t" << hostname << " (" << ip_address << ")\t" << latency << " ms" << endl;
									return 666;
								}
								else if (sock_err->ee_type == ICMP6_DST_UNREACH) {
									switch (sock_err->ee_code) {
										case ICMP6_DST_UNREACH_NOPORT:
											// port unreachable
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t" << latency << " ms" << endl;
											return 777;
										case ICMP6_DST_UNREACH_NOROUTE:
											// network unreachable
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t" << "N!" << endl;
											return 777;
										case ICMP6_DST_UNREACH_ADDR:
											// host unreachable
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t" << "H!" << endl;
											return 777;
										case 7:
											// protocol unreachable
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t" << "P!" << endl;
											return 777;
										case ICMP6_DST_UNREACH_ADMIN:
											// communication administratively prohibited
											cout << ttl << "\t" << hostname << " (" << ip_address << ")\t" << "X!" << endl;
											return 777;
										default:
											break;
									}
								}
							}
						}
					}
				}
			}
		}
		return 0;
	}
}

/**
 * Creating specific type of socket.
 * @param is_ipv4_addr: type of socket - IPv4/IPv6
 * @param ip_addr: given IP address
 */
int create_socket(int is_ipv4_addr, string ip_addr) {
	int sock;
	int x = 1;

	if (is_ipv4_addr == 1) { /* IPv4 */
		// Create UDP socket
		if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			perror("Could not process socket() [IPv4].");
			return EXIT_FAILURE;
		}
		memset(&dst, 0, sizeof(struct sockaddr_in));
		dst.sin_family = AF_INET;
		dst.sin_port = htons(33434);
		inet_pton(AF_INET, ip_addr.c_str(), &dst.sin_addr);
		// Destination address
		if (setsockopt(sock, SOL_IP, IP_RECVERR, &x, sizeof(x)) < 0) {
			perror("Could not process setsockopt() [IPv4].");
			return EXIT_FAILURE;
		}
	}
	else { /* IPv6 */
		// Create UDP socket
		if ((sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			perror("Could not process socket() [IPv6].");
			return EXIT_FAILURE;
		}
		memset(&dst6, 0, sizeof(struct sockaddr_in6));
		dst6.sin6_family = AF_INET6;
		dst6.sin6_port = htons(33434);
		inet_pton(AF_INET6, ip_addr.c_str(), &dst6.sin6_addr);
		// Destination address
		if (setsockopt(sock, SOL_IPV6, IPV6_RECVERR, &x, sizeof(x)) < 0) {
			perror("Could not process setsockopt() [IPv6].");
			return EXIT_FAILURE;
		}
	}
	return sock;
}

/**
 * Writing error message a stopping program with error status code.
 * @param ecode: error code
 */
void print_err(int ecode) {
	switch (ecode) {
		case 1:
      fprintf(stderr, "Trace: Unrecognized option. Usage: ./trace [-f first_ttl] [-m max_ttl] <ip-address>\n");
			exit(1);
			break;
    case 2:
      fprintf(stderr, "Trace: Invalid argument(s) value(s).\n");
			exit(2);
			break;
		case 3:
      fprintf(stderr, "Trace: Socket error.\n");
			exit(3);
			break;
		case 4:
      fprintf(stderr, "Trace: Unknown error.\n");
			exit(4);
			break;
	}
}

/**
 * Parsing and validates arguments from command line.
 * Returns structure with params if valid, otherwise set up flag indicates error.
 * @param argc: count of arguments
 * @param argv: values of arguments
 */
Params parse_args(int argc, char* argv[]) {

	Params params;
  params.first_ttl = FIRST_TTL;
  params.max_ttl = MAX_TTL;
  params.ip_addr = "";
  params.ecode = 0;
	char* ptr = nullptr;
  char* ttl_ptr = nullptr;
	int opt;
  bool f = false;
  bool m = false;
	struct addrinfo* result;
	struct addrinfo hints;
	int get_addr_info;
	bool get_out_err = true;

	if (argc > 6) params.ecode = 1;

	// Parsing options using function getopt()
	while ((opt = getopt(argc, argv, "f:m:")) != -1) {
    switch (opt) {
      case 'f':
        f = true;
        ttl_ptr = optarg;
        params.first_ttl = (int)strtoul(ttl_ptr, &ptr, 0);
        if (*ptr != '\0') {
          cerr << "Invalid first_ttl: " << ttl_ptr << endl;
          params.ecode = 1;
        }
        if ((params.first_ttl < 1) || (params.first_ttl > 255)) {
          cerr << "First_ttl out of range: must be in <1,max_ttl>" << endl;
					get_out_err = false;
					params.ecode = 2;
				}
        break;
      case 'm':
        m = true;
        ttl_ptr = optarg;
        params.max_ttl = (int)strtoul(ttl_ptr, &ptr, 0);
        if (*ptr != '\0') {
          cerr << "Invalid max_ttl: " << ttl_ptr << endl;
          params.ecode = 1;
        }
        if ((params.max_ttl < 1) || (params.max_ttl > 255)) {
          cerr << "Max_ttl out of range: must be in <1,255>" << endl;
					params.ecode = 2;
				}
				else if (params.first_ttl > params.max_ttl) {
          if (get_out_err) cerr << "First_ttl out of range: must be in <1,max_ttl>" << endl;
					params.ecode = 2;
				}
        break;
      default:
        params.ecode = 1;
        break;
      }
	}

  // parsing IP address
  if (f || m) {
    if ((f && m) && (argc == 6)) params.ip_addr = argv[5];
    else if (argc == 4) params.ip_addr = argv[3];
    else params.ecode = 1;
  }
  else if (argc == 2) params.ip_addr = argv[1];
  else params.ecode = 1;

	// getaddrinfo()
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = 0;    					/* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */

	get_addr_info = getaddrinfo(params.ip_addr.c_str(), "33434", &hints, &result);
	if (get_addr_info != 0) {
    params.ecode = 2;
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(get_addr_info));
	}
	else {
		char ipbuff[64];
		// create either structure for IPv4 or IPv6 based address family
		if (result->ai_family == AF_INET) {
			struct sockaddr_in* addr;
	    addr = (struct sockaddr_in*)result->ai_addr;
			params.ip_addr = inet_ntop(result->ai_family, &(addr->sin_addr), ipbuff, 64);
		}
		else {
			struct sockaddr_in6* addr;
	    addr = (struct sockaddr_in6*)result->ai_addr;
			params.ip_addr = inet_ntop(result->ai_family, &(addr->sin6_addr), ipbuff, 64);
		}
		// set flag indicates IPv4 address
		params.is_ip4_addr = (result->ai_family == AF_INET ? 1 : 0);
	}
	freeaddrinfo(result);	/* No longer needed */
 	return params;
}

/**
 * Inverse DNS lookup.
 * Returns string with hostname.
 * @param ip_addr: input IPv4/IPv6 address
 */
string inverse_dns_lookup(char* ip_addr) {
	struct addrinfo* result;
	struct addrinfo* res;
	string hostname;
	int error;

	/* resolve the domain name into a list of addresses */
  error = getaddrinfo(ip_addr, NULL, NULL, &result);
  if (error != 0) {
    freeaddrinfo(result);
		hostname = "";
    return hostname;
  }

	/* loop over all returned results and do inverse lookup */
  for (res = result; res != NULL; res = res->ai_next) {
      char founded_hostname[NI_MAXHOST];
      error = getnameinfo(res->ai_addr, res->ai_addrlen, founded_hostname, NI_MAXHOST, NULL, 0, 0);
      if (error != 0) continue;
      if (*founded_hostname != '\0') {
				freeaddrinfo(result);
				hostname = founded_hostname;
				return hostname;
			}
  }

  freeaddrinfo(result);
	hostname = "";
  return hostname;
}
