#ifndef TYPES_H
#define TYPES_H

typedef enum {
    DOOR_STATUS_CLOSED,
    DOOR_STATUS_OPEN,
} door_status_t;

typedef struct {
    /* web server */
    int http_port;
    int fd;
    int backlog_size;

    /* mqtt */
    char *broker_hostname;
    int broker_port;
    struct mosquitto *m;

    /* door status */
    door_status_t downstairs;
    door_status_t upstairs;
} info_t;

#define DEF_HTTP_PORT 12345
#define DEF_BACKLOG_SIZE 5

#define MAX_METHOD_LENGTH 8
#define MAX_URI_LENGTH 256
#define MAX_REQUEST_LENGTH 4096
#define MAX_RESPONSE_HEADER_LENGTH 1024
#define MAX_RESPONSE_LENGTH 1024

/* Hostname and port for the MQTT broker. */
#define DEF_MQTT_BROKER_HOSTNAME "localhost"
#define DEF_MQTT_BROKER_PORT 1883
#define KEEPALIVE_SECONDS 60

typedef struct {
    char method[MAX_METHOD_LENGTH];
    char uri[MAX_URI_LENGTH];
    size_t uri_length;
    char req_buf[MAX_REQUEST_LENGTH];
    ssize_t req_length;
    uint16_t status;
    char *content_type;
    char resp_buf[MAX_RESPONSE_LENGTH];
    uint16_t resp_length;
} req_info_t;

#endif
