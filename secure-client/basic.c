/* 
 * Network Client
 * Patrick Withams
 * November 2017
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define BUFFMAX 1024            // maximum length of a received message

/*
 * error handling function
 */
int error_msg(int code)
{
    printf("Error received: exiting\n");
    exit(code);
}

/* 
 * error handling function
 */
int argument_error()
{
    printf("Usage: ./client [target ip] [port]\n");
    exit(EXIT_FAILURE);
}

/*
 * Custom get input function
 * Reads stdin to chosen buffer, and returns
 * the length of any input overflow
 * Note: Always returns string with a new line
 * at the end to be consistent
 * Errors are detected by a greater than zero
 * return value
 */
int get_user_input(char * buffer, int buffer_size)
{
    int overflow_value = 0;
    char current_char = 0;
    int counter = 0;

    // zero buffer
    bzero(buffer, buffer_size);
    
    // read user input into buffer until
    // either buffer limit is reached, or
    // a new line or EOF is submitted
    while(counter < buffer_size)
    {
        current_char = getchar();
        buffer[counter] = current_char;
        if(current_char == '\n' ||
           current_char == EOF)
            break;
        counter++;
    }

    // if input was larger than buffer size
    // dump remaining contents to variable
    // and record verflow length
    if(counter >= buffer_size) {
        // artificially create new line
        // to keep a standard
        buffer[buffer_size-1] = '\n';
        char dump = getchar();
        overflow_value = 1;
        while(dump != '\n' && dump != EOF) {
            dump = getchar();
            overflow_value++;
        }
    }
    // return overflow length
    return overflow_value;
}

/*
 * receives message from connected server until either
 * a new line character is detected or the buffer is full
 */
int receive_message(int clientsocket, char buffer[], int len)
{
    bzero(buffer, len);
    int total = recv(clientsocket, buffer, len, 0);
    while(buffer[total-1] != '\n' && total != -1) {
        if(total >= len) {
            printf("Error: Receive buffer full\n");
            break;
        }
        char *new = buffer + total;
        total += recv(clientsocket, new, (len-sizeof(total)), 0);
    }
    // check for errors
    if(total < 0)
        error_msg(EXIT_FAILURE);

    return 0;
}

/* 
 * sends message to connected server
 */
int send_message(int clientsocket, char message[], int len)
{
    int error = send(clientsocket, message, len, 0);
    // check for errors
    if(error < 0)
        error_msg(EXIT_FAILURE);
    return 0;
}

/* 
 * connects created socket to target server and specified
 * port number
 */
int connect_socket(int clientsocket, char target_ip[], int port)
{
    struct sockaddr_in dest_addr;
    int error;

    // set port and IP
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    // convert string ip to binary
    inet_aton(target_ip, &dest_addr.sin_addr);

    // create socket and connect to server
    clientsocket = socket(AF_INET, SOCK_STREAM, 0);

    // check for errors
    if(clientsocket < 0)
        error_msg(EXIT_FAILURE);

    error = connect(clientsocket, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    // check for errors
    if(error < 0)
        error_msg(EXIT_FAILURE);

    return clientsocket;
}

/* 
 * gets user input and sends messages to server
 * prints any server responses
 */
int communicate(int clientsocket)
{
    char * message = malloc(BUFFMAX);
    char * response = malloc(BUFFMAX);

    // receive server welcome message
    receive_message(clientsocket, response, BUFFMAX);
    printf("%s\n", response);

    char cipher[] = "aes256";
    send_message(clientsocket, cipher, strlen(cipher));

    // receive and print response
    printf("Server response:\n");
    receive_message(clientsocket, response, BUFFMAX);
    printf("%s\n", response);

    // close socket
    close(clientsocket);
    return 0;
}

int main(int argc, char **argv)
{
    int clientsocket;
    char *target_ip;
    char *port;
    int port_no;

    // check if arguments provided
    if( argc != 3)
        argument_error();

    // extract target ip and port no
    // from command line arguments
    target_ip = argv[1];
    port = argv[2];
    port_no = atoi(port);

    // check for valid port number
    if(port_no == 0)
        argument_error();

    // create and connect socket to target
    clientsocket = connect_socket(clientsocket, target_ip, port_no);

    // start communicating with server
    communicate(clientsocket);

    return 0;
}
