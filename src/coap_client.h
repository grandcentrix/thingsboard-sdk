#ifndef COAP_CLIENT_H
#define COAP_CLIENT_H

#include <net/coap.h>

int coap_client_send(struct coap_packet *pkt, coap_reply_t reply);

int coap_client_packet_init(struct coap_packet *cpkt, uint8_t type, uint8_t code);

int coap_client_make_request(const uint8_t** uri, const void *payload, size_t plen, uint8_t type, uint8_t code, coap_reply_t reply);

void *coap_client_buf(size_t *len);

void coap_client_buf_free(void *buf);

int coap_client_init(void (*cb)(void));

int coap_packet_append_uri_path(struct coap_packet *pkt, const uint8_t **uri);

int coap_packet_append_uri_query_s(struct coap_packet *pkt, const char *fmt, const char *s);

int coap_packet_append_uri_query_d(struct coap_packet *pkt, const char *fmt, int d);



#endif /* COAP_CLIENT_H */
