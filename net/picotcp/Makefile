#
# Makefile for PicoTCP as Linux TCP/IP replacement.
#
ccflags-y += -I net/picotcp/include -I net/picotcp/modules

obj-y     := stack/pico_device.o \
			stack/pico_frame.o \
			stack/pico_protocol.o \
			stack/pico_socket.o \
			stack/pico_socket_multicast.o \
			stack/pico_stack.o \
			stack/pico_tree.o \
			modules/pico_linux.o \
			modules/pico_osal_linux.o \
			modules/pico_bsd_sockets.o

obj-$(CONFIG_PICOTCP_IPV4) += modules/pico_ipv4.o modules/pico_ipfilter.o
obj-$(CONFIG_PICOTCP_IPV6) += modules/pico_ipv6.o modules/pico_icmp6.o modules/pico_ipv6_nd.o
obj-$(CONFIG_PICOTCP_DEVLOOP) += modules/pico_dev_loop.o
obj-$(CONFIG_PICOTCP_ETH) += modules/pico_arp.o
obj-$(CONFIG_PICOTCP_TCP) += modules/pico_tcp.o modules/pico_socket_tcp.o
obj-$(CONFIG_PICOTCP_UDP) += modules/pico_udp.o modules/pico_igmp.o modules/pico_socket_udp.o
obj-$(CONFIG_PICOTCP_NAT) += modules/pico_nat.o
obj-$(CONFIG_PICOTCP_ICMP4) += modules/pico_icmp4.o
obj-$(CONFIG_PICOTCP_DNS_CLIENT) += modules/pico_dns_client.o


