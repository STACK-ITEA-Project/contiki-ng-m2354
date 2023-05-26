CONTIKI_PROJECT = dtls-server
all: $(CONTIKI_PROJECT)

CONTIKI=../..

PROJECT_SOURCEFILES += slip-net.c

CFLAGS += -DMBEDTLS_CONFIG_FILE='<mbedtls_config.h>'

MODULES += os/lib/mbedtls

MAKE_NET = MAKE_NET_IPV6
MAKE_MAC = MAKE_MAC_NULLMAC
include $(CONTIKI)/Makefile.include
