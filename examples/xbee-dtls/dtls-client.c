#include "contiki-net.h"
#include "sys/subprocess.h"
#include "NuMicro.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#include <stdlib.h>
#include <string.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"

#include "os/dev/slip.h"
#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define SERVER_NAME "localhost"
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define RX_BUF_SIZE	4096

#define MESSAGE     "Echo this"

static struct udp_socket udp_sock;
static uint8_t *rx_buf = NULL;
static size_t rx_buf_size = RX_BUF_SIZE;
static size_t rx_left = 0;
static int xbee_connected = 0;

typedef struct {
	clock_time_t	start;
	uint32_t	int_ms;
	uint32_t	fin_ms;
} udp_timer_t;

PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);

static void
udp_rx_callback(struct udp_socket *c,
		 void *ptr,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
	size_t new_size;

	if (rx_buf == NULL) {
		LOG_ERR("RX buffer is NULL.\n");
		return;
	}

	if ((rx_left + datalen) > RX_BUF_SIZE) {
		new_size = (rx_left + datalen + RX_BUF_SIZE - 1) & ~(RX_BUF_SIZE - 1);
		rx_buf = realloc(rx_buf, new_size);
		if (rx_buf == NULL) {
			LOG_ERR("realloc error\n");
			return;
		}

		rx_buf_size = new_size;
	}

	memcpy(rx_buf + rx_left, data, datalen);
	rx_left += datalen;

	process_poll(&udp_client_process);
}

static int dtls_client_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct udp_socket *s = ctx;

	return udp_socket_send(s, buf, len);
}

static int dtls_client_recv(void *ctx, unsigned char *buf, size_t len)
{
	if (!rx_left)
		return MBEDTLS_ERR_SSL_WANT_READ;

	if (rx_left > len) {
		rx_left -= len;

		memcpy(buf, rx_buf, len);
		memmove(rx_buf, rx_buf + len, rx_left);
		
		return len;
	}
	else {
		len = rx_left;
		rx_left = 0;
		memcpy(buf, rx_buf, len);
		return len;
	}
}

/*
 * Set delays to watch
 */
static void timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms )
{
	udp_timer_t *ctx = (udp_timer_t *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;
	ctx->start = clock_time();
}

/*
 * Get number of delays expired
 */
static int timing_get_delay( void *data )
{
    udp_timer_t *ctx = (udp_timer_t *) data;
    unsigned long elapsed_ms;

    if( ctx->fin_ms == 0 )
        return( -1 );

    elapsed_ms = (clock_time() - ctx->start + 1) * 1000 / CLOCK_SECOND;

    if( elapsed_ms >= ctx->fin_ms )
        return( 2 );

    if( elapsed_ms >= ctx->int_ms )
        return( 1 );

    return( 0 );
}

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
	((void) ctx);
    ((void) level);

    mbedtls_printf("%s:%04d: %s", file, line, str );
}

int mbedtls_hardware_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen )
{
	static int seeded = 0;
	int i;

	if (!seeded) {
		srand(clock_time());
		seeded = 1;
	}

	for (i = 0; i < len; i++)
		output[i] = rand();

	*olen = len;

	return 0;
}

void GPF_IRQHandler(void)
{
	uint32_t flag;

	flag = PF->INTSRC;
	/* Check if PF9 is asserted */
	if (flag & (1 << 9)) {
		xbee_connected = 1;
		process_poll(&udp_client_process);
	}

	PF->INTSRC = flag;
}

PROCESS_THREAD(udp_client_process, ev, data)
{
    static int ret = 0, len;
    static uint32_t flags;
	static unsigned char buf[1024];
    static const char *pers = "dtls_client";
	static int retry_left = 5;
	static udp_timer_t timer;

    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;
    static mbedtls_ssl_context ssl;
    static mbedtls_ssl_config conf;
    static mbedtls_x509_crt cacert;

    uip_ipaddr_t dest_ipaddr =  {{ 0xFE,0x80,0x00,0x00,0x00, 0x00,0x00,0x00,0x02,0x13,0xA2, 0x00, 0x42, 0x1C, 0x4A, 0xEA}};

    PROCESS_BEGIN();

#if defined(MBEDTLS_DEBUG_C)
	//mbedtls_debug_set_threshold(3);
#endif

	rx_buf = malloc(rx_buf_size);
	if (rx_buf == NULL) {
		LOG_ERR("malloc error\n");
		goto exit;
	}

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 0. Load certificates
     */
    mbedtls_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok (%d skipped)\n", ret );

    /*
     * 1. Start the connection
     */
    mbedtls_printf( "  . Connecting to udp/%s/%d...", SERVER_NAME,
			UDP_SERVER_PORT );
    fflush( stdout );

	udp_socket_register(&udp_sock, NULL, udp_rx_callback);
	udp_socket_connect(&udp_sock, &dest_ipaddr, UDP_SERVER_PORT);
	udp_socket_bind(&udp_sock, UDP_CLIENT_PORT);

#if 0
	printf("PF9_NS = %ld\n", PF9_NS);
#endif
	if (PF9_NS == 0) {
		GPIO_EnableInt(PF, 9, GPIO_INT_RISING);
		NVIC_EnableIRQ(GPF_IRQn);
		NVIC_SetPriority(GPF_IRQn, 0);
		PROCESS_YIELD_UNTIL(xbee_connected);
		NVIC_DisableIRQ(GPF_IRQn);
	}

    mbedtls_printf( " ok\n" );

    /*
     * 2. Setup stuff
     */
    mbedtls_printf( "  . Setting up the DTLS structure..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                   MBEDTLS_SSL_IS_CLIENT,
                   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                   MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &udp_sock,
                         dtls_client_send, dtls_client_recv,
						 NULL );

	memset(&timer, 0, sizeof(timer));

    mbedtls_ssl_set_timer_cb( &ssl, &timer, timing_set_delay,
                                            timing_get_delay );
    mbedtls_printf( " ok\n" );

    /*
     * 4. Handshake
     */
    mbedtls_printf( "  . Performing the DTLS handshake..." );
    fflush( stdout );

    do {
		ret = mbedtls_ssl_handshake( &ssl );
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
			PROCESS_YIELD_UNTIL(rx_left);
	}
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf( "  . Verifying peer X.509 certificate..." );

    /* In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
     * handshake would not succeed if the peer's cert is bad.  Even if we used
     * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        mbedtls_printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        mbedtls_printf( "%s\n", vrfy_buf );
    }
    else
        mbedtls_printf( " ok\n" );

    /*
     * 6. Write the echo request
     */
send_request:
    mbedtls_printf( "  > Write to server:" );
    fflush( stdout );

    len = sizeof( MESSAGE ) - 1;

    do {
		ret = mbedtls_ssl_write( &ssl, (unsigned char *) MESSAGE, len );
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
			PROCESS_YIELD_UNTIL(rx_left);
	}
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
        goto exit;
    }

    len = ret;
    mbedtls_printf( " %d bytes written\n\n%s\n\n", len, MESSAGE );

    /*
     * 7. Read the echo response
     */
    mbedtls_printf( "  < Read from server:" );
    fflush( stdout );

    len = sizeof( buf ) - 1;
    memset( buf, 0, sizeof( buf ) );

    do {
		ret = mbedtls_ssl_read( &ssl, buf, len );
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
			PROCESS_YIELD_UNTIL(rx_left);
	}
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret <= 0 )
    {
        switch( ret )
        {
            case MBEDTLS_ERR_SSL_TIMEOUT:
                mbedtls_printf( " timeout\n\n" );
                if( retry_left-- > 0 )
                    goto send_request;
                goto exit;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                mbedtls_printf( " connection was closed gracefully\n" );
                ret = 0;
                goto close_notify;

            default:
                mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n\n", -ret );
                goto exit;
        }
    }

    len = ret;
    mbedtls_printf( " %d bytes read\n\n%s\n\n", len, buf );

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    mbedtls_printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;

    mbedtls_printf( " done\n" );

    /*
     * 9. Final clean-ups and exit
     */
exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf( "Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_x509_crt_free( &cacert );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    /* Shell can not handle large exit numbers -> 1 for errors */
    if( ret < 0 )
        ret = 1;

    PROCESS_END();
}
