#ifndef COAP_CLIENT_H
#define COAP_CLIENT_H

#include <net/coap.h>

/**
 * Send the coap packet. If you provide a reply handler function,
 * the packet will be tracked, i.e. resent until an ACK is
 * received. If not, the memory is received immediately, and
 * no attempt is made to resend the packet.
*/
int coap_client_send(struct coap_packet *pkt, coap_reply_t reply);

/**
 * Initialize a packet.
 * Internally, this allocates memory from a slab. The memory is
 * handled by the library and you do not need to free it.
 */
int coap_client_packet_init(struct coap_packet *cpkt, uint8_t type, uint8_t code);

/**
 * Helper function to init a packet, append the payload and send it all in one
*/
int coap_client_make_request(const uint8_t** uri, const void *payload, size_t plen, uint8_t type, uint8_t code, coap_reply_t reply);

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
