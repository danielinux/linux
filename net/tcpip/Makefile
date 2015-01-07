#
# Makefile for PicoTCP as Linux TCP/IP replacement.
#
ccflags-y += -I net/tcpip/picotcp/include -I net/tcpip/picotcp/modules -I net/tcpip

obj-y     := af_inet.o \
			netdev.o \
			sock.o \
			ioctl.o \
			proc.o \
			netlink.o \
			core.o

obj-y     += picotcp/stack/pico_device.o \
			picotcp/stack/pico_frame.o \
			picotcp/stack/pico_protocol.o \
			picotcp/stack/pico_socket.o \
			picotcp/stack/pico_socket_multicast.o \
			picotcp/stack/pico_stack.o \
			picotcp/stack/pico_tree.o 

obj-$(CONFIG_PICOTCP_IPV4) 		+= picotcp/modules/pico_ipv4.o picotcp/modules/pico_ipfilter.o
obj-$(CONFIG_PICOTCP_IPV6) 		+= picotcp/modules/pico_ipv6.o picotcp/modules/pico_icmp6.o picotcp/modules/pico_ipv6_nd.o
obj-$(CONFIG_PICOTCP_DEVLOOP) 	+= picotcp/modules/pico_dev_loop.o
obj-$(CONFIG_PICOTCP_ETH) 		+= picotcp/modules/pico_arp.o
obj-$(CONFIG_PICOTCP_TCP) 		+= picotcp/modules/pico_tcp.o picotcp/modules/pico_socket_tcp.o
obj-$(CONFIG_PICOTCP_UDP) 		+= picotcp/modules/pico_udp.o picotcp/modules/pico_igmp.o picotcp/modules/pico_socket_udp.o
obj-$(CONFIG_PICOTCP_NAT) 		+= picotcp/modules/pico_nat.o
obj-$(CONFIG_PICOTCP_ICMP4) 	+= picotcp/modules/pico_icmp4.o
obj-$(CONFIG_PICOTCP_DNS_CLIENT)+= picotcp/modules/pico_dns_client.o picotcp/modules/pico_dns_common.o


