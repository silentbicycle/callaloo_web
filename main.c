/* 
 * Copyright (c) 2014 Scott Vokes <vokes.s@gmail.com>
 *  
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *  
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <err.h>

#include <stdint.h>
#include <stdbool.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "mosquitto.h"
#include "types.h"

static bool init(info_t *info);
static bool init_mqtt(info_t *info);
static bool init_socket(info_t *info);
static void loop(info_t *info);
static bool handle_client(info_t *info, int fd, struct sockaddr *client);
static void choose_http_response(info_t *info, req_info_t *req);
static void send_http_response(int fd, req_info_t *req);
static void on_connect(struct mosquitto *m, void *udata, int res);
static void on_message(struct mosquitto *m, void *udata,
    const struct mosquitto_message *msg);

int main(int argc, char **argv) {
    info_t info;
    memset(&info, 0, sizeof(info));

    /* defaults */
    info.http_port = DEF_HTTP_PORT;
    info.backlog_size = DEF_BACKLOG_SIZE;

    info.broker_hostname = DEF_MQTT_BROKER_HOSTNAME;
    info.broker_port = DEF_MQTT_BROKER_PORT;

    char *var = NULL;
    var = getenv("HTTP_PORT");
    if (var) { info.http_port = atoi(var); }

    var = getenv("MQTT_HOSTNAME");
    if (var) { info.broker_hostname = var; }
    var = getenv("MQTT_PORT");
    if (var) { info.broker_port = atoi(var); }
    
    if (!init(&info)) { exit(1); }

    loop(&info);                /* currently loops forever */

    return 0;
}

static bool init(info_t *info) {
    if (!init_socket(info)) { return false; }
    if (!init_mqtt(info)) { return false; }
    return true;
}
    
static bool init_socket(info_t *info) {
    struct addrinfo hints, *res = NULL;
    int fd = -1;
    int addr_res = 0;
    struct addrinfo *ai = NULL;
#define PORT_STR_BUFSZ 6
    char port_str[PORT_STR_BUFSZ];
    bzero(port_str, PORT_STR_BUFSZ);
    bzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* ipv4 or ipv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (PORT_STR_BUFSZ < snprintf(port_str, PORT_STR_BUFSZ,
            "%u", info->http_port)) {
        printf("snprintf\n");
        return false;
    }
#undef PORT_STR_BUFSZ

    if ((addr_res = getaddrinfo(NULL, port_str, &hints, &res)) != 0) {
        err(1, "getaddrinfo");
        return false;
    }

    /* find & use the first valid addrinfo. */
    for (ai = res; ai; ai=ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) { return false; }

        int res = bind(fd, ai->ai_addr, ai->ai_addrlen);
        if (res < 0) {
            err(1, "bind");
            return false;
        }
        
        /* set non-blocking */
        int flags = fcntl(fd, F_GETFL, 0);
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            err(1, "fcntl");
            return false;
        }

        if (listen(fd, info->backlog_size) < 0) {
            err(1, "listen");
            return false;
        }
        info->fd = fd;
        return true;
    }

    return false;
}

static bool init_mqtt(info_t *info) {
    void *udata = (void *)info;
    size_t buf_sz = 32;
    char buf[buf_sz];
    pid_t pid = getpid();
    if (buf_sz < snprintf(buf, buf_sz, "client_%d", pid)) {
        return false;            /* snprintf buffer failure */
    }

    struct mosquitto *m = mosquitto_new(buf, true, udata);
    if (m == NULL) {
        fprintf(stderr, "mosquitto_new\n");
        return false;
    }

    mosquitto_connect_callback_set(m, on_connect);
    mosquitto_message_callback_set(m, on_message);

    int res = mosquitto_connect(m, info->broker_hostname,
        info->broker_port, KEEPALIVE_SECONDS);

    if (res == MOSQ_ERR_SUCCESS) {
        info->m = m;
        return true;
    } else {
        mosquitto_destroy(m);
        fprintf(stderr, "failed to connect to broker at %s:%d, is it running?\n",
            info->broker_hostname, info->broker_port);
        return false;
    }
}

static void on_connect(struct mosquitto *m, void *udata, int res) {
    if (res == MOSQ_ERR_SUCCESS) {
        /* subscribe to all 'callaloo' topics */
        mosquitto_subscribe(m, NULL, "callaloo/#", 0);
    }
}

static void on_message(struct mosquitto *m, void *udata,
    const struct mosquitto_message *msg) {
    info_t *info = (info_t *)udata;

    if (msg->payloadlen > 1) {
        door_status_t *ds = NULL;
        if (0 == strncmp(msg->topic, "callaloo/upstairs",
                strlen("callaloo/upstairs"))) {
            ds = &info->upstairs;
        } else if (0 == strncmp(msg->topic, "callaloo/downstairs",
                strlen("callaloo/downstairs"))) {
            ds = &info->downstairs;
        }
        if (ds) {
            uint8_t *payload = (uint8_t *)msg->payload;
            /* Just look at the first character */
            switch (payload[0]) {
            case 'o':
                *ds = DOOR_STATUS_OPEN;
                break;
            case 'c':
                *ds = DOOR_STATUS_CLOSED;
                break;
            }
        }
    }
}

static void loop(info_t *info) {
    struct sockaddr client;
    socklen_t address_len = 0;

    for (;;) {
        memset(&client, 0, sizeof(client));
        address_len = sizeof(client);

        int nfd = accept(info->fd, &client, &address_len);
        if (nfd == -1) {
            switch (errno) {
            case EWOULDBLOCK:   /* no new clients */
                break;
            case EINTR:         /* interrupted by signal */
                break;
            default:
                err(1, "accept");
            }
        } else {
            pid_t pid = fork();

            if (pid == -1) {
                err(1, "fork");
            } else if (pid == 0) { /* child */
                (void)close(info->fd);
                (void)handle_client(info, nfd, &client);
                exit(0);
            } else {            /* parent */
                (void)close(nfd);
            }
        }

        /* Check MQTT, delaying there to avoid busywaiting.
         * We could use select() to check for incoming connections
         * and MQTT activity, but this is good enough. */
        int res = mosquitto_loop(info->m, 100, 1);
        if (res != MOSQ_ERR_SUCCESS) {
            printf("mqtt error %d\n", res);
            break;
        }
    }
}

/* Parse a request-line as per RFC 2616, section 5.1. */
static bool parse_request(req_info_t *req_info) {
    const char *req = req_info->req_buf;
    ssize_t req_sz = req_info->req_length;
    size_t offset = 0;

    if (req_sz == -1) { err(1, "recv"); }

    if (req_sz < MAX_METHOD_LENGTH) { return false; }

    /* Only GET and HEAD are implemented. */
    if (req[0] != 'G' && req[0] != 'H') { return false; }

    while (offset < MAX_METHOD_LENGTH) {
        uint8_t c = req[offset];
        if (c == ' ') {         /* End of method */
            memcpy(req_info->method, req, offset);
            offset++;
            req_info->method[offset] = '\0';
            break;
        }
        offset++;
        if (offset >= req_sz) { return false; }
    }

    size_t uri_offset = offset;
    while (offset - uri_offset < MAX_URI_LENGTH) {
        uint8_t c = req[offset];
        if (c == ' ') {
            size_t uri_length = offset - uri_offset;
            memcpy(req_info->uri, &req[uri_offset], uri_length);
            req_info->uri[uri_length] = '\0';
            req_info->uri_length = uri_length;
            offset++;
            break;
        }
        
        offset++;
        if (offset >= req_sz) { return false; }
    }

    static const char http_version_crlf[] = "HTTP/1.1\r\n";
    if (req_sz - offset < strlen(http_version_crlf)) { return false; }
    if (0 == strncmp(http_version_crlf, &req[offset], strlen(http_version_crlf))) {
        /* Got a full request-line; ignore headers. */
        return true;
    } else {
        return false;
    }
}

static bool handle_client(info_t *info, int fd, struct sockaddr *client) {
    #define BUF_SZ 4096
    uint8_t req_buf[BUF_SZ];
    req_info_t req_info;
    memset(&req_info, 0, sizeof(req_info));
    (void)client;

    req_info.req_length = recv(fd, req_info.req_buf, MAX_REQUEST_LENGTH, 0);

    if (req_info.req_length != -1) {
        bool res = parse_request(&req_info);
        
        if (res) {                  /* request-line looks valid */
            choose_http_response(info, &req_info);
            send_http_response(fd, &req_info);
        } else {
            req_info.status = 400;
            req_info.resp_length = snprintf(req_info.resp_buf,
                MAX_RESPONSE_LENGTH, "400 Bad Request\r\n");
            send_http_response(fd, &req_info);
        }
    }

    if (close(fd) == -1) {
        printf("close\n");
        return false;
    }
    return true;
}

static char *status_label(uint16_t status) {
    switch (status) {
    case 200:
        return "OK";
    case 400:
        return "Bad Request";
    case 404:
        return "Not Found";
    case 401:
        return "Not Implemented";
    default:
        return "ERROR";
    } 
}

static const char *door_status_str(door_status_t s) {
    switch (s) {
    case DOOR_STATUS_CLOSED:
        return "closed";
    case DOOR_STATUS_OPEN:
        return "open";
    default:
        return "error";
    }
}

static void choose_http_response(info_t *info, req_info_t *req) {
    req->content_type = "text/plain";

    if ((0 == strncmp(req->method, "GET", 3)) ||
        (0 == strncmp(req->method, "HEAD", 3))) {
        if (0 == strncmp(req->uri, "/", req->uri_length)) {
            req->status = 200;
            req->resp_length = snprintf(req->resp_buf, MAX_RESPONSE_LENGTH,
                "dowstairs %s\r\n"
                "upstairs %s\r\n",
                door_status_str(info->downstairs),
                door_status_str(info->upstairs));
        } else if (0 == strncmp(req->uri, "/json", req->uri_length)) {
            req->status = 200;
            req->content_type = "text/json";
            req->resp_length = snprintf(req->resp_buf, MAX_RESPONSE_LENGTH,
                "{\r\n"
                "    \"dowstairs\": \"%s\",\r\n"
                "    \"upstairs\": \"%s\"\r\n"
                "}\r\n",
                door_status_str(info->downstairs),
                door_status_str(info->upstairs));
        } else if (0 == strncmp(req->uri, "/upstairs", req->uri_length)) {
            req->status = 200;
            req->resp_length = snprintf(req->resp_buf, MAX_RESPONSE_LENGTH,
                "upstairs %s\r\n", door_status_str(info->upstairs));
        } else if (0 == strncmp(req->uri, "/downstairs", req->uri_length)) {
            req->status = 200;
            req->resp_length = snprintf(req->resp_buf, MAX_RESPONSE_LENGTH,
                "downstairs %s\r\n", door_status_str(info->downstairs));
        } else {
            req->status = 404;
            req->resp_length = snprintf(req->resp_buf, MAX_RESPONSE_LENGTH,
                "404 Not Found\r\n");
        }
    } else {
        req->status = 501;
        req->resp_length = snprintf(req->resp_buf, MAX_RESPONSE_LENGTH,
            "501 Not Implemented\r\n");
    }
}

static void send_http_response(int fd, req_info_t *req) {
    char header_buf[MAX_RESPONSE_HEADER_LENGTH];
    int header_length = snprintf(header_buf, MAX_RESPONSE_HEADER_LENGTH,
        "HTTP/1.1 %u %s\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: %s\r\n"
        "\r\n", req->status, status_label(req->status),
        req->resp_length, req->content_type);
    if (MAX_RESPONSE_HEADER_LENGTH < header_length) {
        return;                 /* snprintf overflow */
    }
    ssize_t sz = send(fd, header_buf, header_length, 0);
    if (sz == -1) { return; }

    if (0 == strncmp("GET", req->method, 3)) {
        sz = send(fd, req->resp_buf, req->resp_length, 0);
        if (sz == -1) { return; }
    }
}
