#ifndef COAP_CLIENT_H
#define COAP_CLIENT_H

#include <net/coap.h>
#include <sys/dlist.h>

struct coap_client_request;

typedef void (*coap_reply_handler_t)(struct coap_client_request *req, struct coap_packet *resp);

struct coap_client_request {
    struct coap_packet pkt;
    coap_reply_handler_t reply_handler;
    uint8_t token[COAP_TOKEN_MAX_LEN];
    uint16_t id;
    uint8_t tkl : 4;
    uint8_t confirmable : 1;
    uint8_t confirmed : 1;
    uint8_t observation : 1;
    uint8_t retries : 3;
    int64_t t0;
    uint32_t timeout;
    sys_dnode_t node;
};

struct coap_client_request *coap_client_request_alloc(uint8_t type, uint8_t code);

int coap_client_request_observe(struct coap_client_request *req);

/**
 * Send the coap packet. If you provide a reply handler function,
 * the packet will be tracked, i.e. resent until an ACK is
 * received. If not, the memory is received immediately, and
 * no attempt is made to resend the packet.
*/
int coap_client_send(struct coap_client_request *req, coap_reply_handler_t reply);

/**
 * Helper function to init a packet, append the payload and send it all in one
*/
int coap_client_make_request(const uint8_t** uri, const void *payload, size_t plen, uint8_t type, uint8_t code, coap_reply_handler_t reply);

/**
 * Initialize the CoAP client.
 * The provided callback will be called as soon
 * as the modem is initialized and connected and
 * a socket has been opened.
 * If a tracked request expires finally, the socket
 * will be closed and reopened and this callback
 * will be called again. All reply handlers and tracked
 * packets will be forgotten, so you have to reinstate
 * all observations you had made.
*/
int coap_client_init(void (*cb)(void));

/**
 * Append the uri path to the packet. Last element must be NULL.
 * Usual rules of CoAP option order have to be taken into account.
*/
int coap_packet_append_uri_path(struct coap_packet *pkt, const uint8_t **uri);

/**
 * Append a query string value to the packet. fmt should look like "<var>=%s".
*/
int coap_packet_append_uri_query_s(struct coap_packet *pkt, const char *fmt, const char *s);

/**
 * Append a query int value to the packet. fmt should look like "<var>=%d".
*/
int coap_packet_append_uri_query_d(struct coap_packet *pkt, const char *fmt, int d);



#endif /* COAP_CLIENT_H */
