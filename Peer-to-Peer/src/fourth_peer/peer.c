#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"
#include "./sha256.h"


// Global variables to be used by both the server and client side of the peer.
// Some of these are not currently used but should be considered STRONG hints
PeerAddress_t *my_address;

pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;
PeerAddress_t** network = NULL;
uint32_t peer_count = 0;

pthread_mutex_t retrieving_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size, 
    int hash_size)
{
  SHA256_CTX shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i=0; i<hash_size; i++)
  {
    hash[i] = shabuffer[i];
  }
}

/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size)
{
    int casc_file_size;

    FILE* fp = fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    casc_file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char buffer[casc_file_size];
    fread(buffer, casc_file_size, 1, fp);
    fclose(fp);

    get_data_sha(buffer, hash, casc_file_size, size);
}

/*
 * A simple min function, which apparently C doesn't have as standard
 */
uint32_t min(int a, int b)
{
    if (a < b) 
    {
        return a;
    }
    return b;
}

/*
 * Select a peer from the network at random, without picking the peer defined
 * in my_address
 */
void get_random_peer(PeerAddress_t* peer_address)
{ 
    PeerAddress_t** potential_peers = malloc(sizeof(PeerAddress_t*));
    uint32_t potential_count = 0; 
    for (uint32_t i=0; i<peer_count; i++)
    {
        if (strcmp(network[i]->ip, my_address->ip) != 0 
                || strcmp(network[i]->port, my_address->port) != 0 )
        {
            potential_peers = realloc(potential_peers, 
                (potential_count+1) * sizeof(PeerAddress_t*));
            potential_peers[potential_count] = network[i];
            potential_count++;
        }
    }

    if (potential_count == 0)
    {
        printf("No peers to connect to. You probably have not implemented "
            "registering with the network yet.\n");
    }

    uint32_t random_peer_index = rand() % potential_count;

    memcpy(peer_address->ip, potential_peers[random_peer_index]->ip, IP_LEN);
    memcpy(peer_address->port, potential_peers[random_peer_index]->port, 
        PORT_LEN);

    free(potential_peers);

    printf("Selected random peer: %s:%s\n", 
        peer_address->ip, peer_address->port);
}

/*
 * Send a request message to another peer on the network. Unless this is 
 * specifically an 'inform' message as described in the assignment handout, a 
 * reply will always be expected.
 */
void send_message(PeerAddress_t peer_address, int command, char* request_body)
{
    fprintf(stdout, "Connecting to server at %s:%s to run command %d (%s)\n", 
        peer_address.ip, peer_address.port, command, request_body);

    compsys_helper_state_t state;
    char msg_buf[MAX_MSG_LEN];
    FILE* fp;

    // Setup the eventual output file path. This is being done early so if 
    // something does go wrong at this stage we can avoid all that pesky 
    // networking
    char output_file_path[strlen(request_body)+1];
    if (command == COMMAND_RETREIVE)
    {     
        strcpy(output_file_path, request_body);

        if (access(output_file_path, F_OK ) != 0 ) 
        {
            fp = fopen(output_file_path, "a");
            fclose(fp);
        }
    }

    // Setup connection
    int peer_socket = compsys_helper_open_clientfd(peer_address.ip, peer_address.port);
    compsys_helper_readinitb(&state, peer_socket);

    // Construct a request message and send it to the peer
    struct RequestHeader request_header;
    strncpy(request_header.ip, my_address->ip, IP_LEN);
    request_header.port = htonl(atoi(my_address->port));
    request_header.command = htonl(command);

    // if command is inform, then the length is 20 as stated by protocol. 16 for ip and 4 for port
    if (command == COMMAND_INFORM)
    {
        request_header.length = htonl(20);
        memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
        memcpy(msg_buf+REQUEST_HEADER_LEN, request_body, 20);
    }
    else
    {
        request_header.length = htonl(strlen(request_body));
        memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
        memcpy(msg_buf+REQUEST_HEADER_LEN, request_body, strlen(request_body));
    }

    compsys_helper_writen(peer_socket, msg_buf, REQUEST_HEADER_LEN+ntohl(request_header.length));

    // We don't expect replies to inform messages so we're done here
    if (command == COMMAND_INFORM)
    {
        return;
    }

    // Read a reply
    compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

    // Extract the reply header 
    char reply_header[REPLY_HEADER_LEN];
    memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

    uint32_t reply_length = ntohl(*(uint32_t*)&reply_header[0]);
    uint32_t reply_status = ntohl(*(uint32_t*)&reply_header[4]);
    uint32_t this_block = ntohl(*(uint32_t*)&reply_header[8]);
    uint32_t block_count = ntohl(*(uint32_t*)&reply_header[12]);
    hashdata_t block_hash;
    memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
    hashdata_t total_hash;
    memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

    // Determine how many blocks we are about to recieve
    hashdata_t ref_hash;
    memcpy(ref_hash, &total_hash, SHA256_HASH_SIZE);
    uint32_t ref_count = block_count;

    // Loop until all blocks have been recieved
    for (uint32_t b=0; b<ref_count; b++)
    {
        // Don't need to re-read the first block
        if (b > 0)
        {
            // Read the response
            compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

            // Read header
            memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

            // Parse the attributes
            reply_length = ntohl(*(uint32_t*)&reply_header[0]);
            reply_status = ntohl(*(uint32_t*)&reply_header[4]);
            this_block = ntohl(*(uint32_t*)&reply_header[8]);
            block_count = ntohl(*(uint32_t*)&reply_header[12]);

            memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
            memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

            // Check we're getting consistent results
            if (ref_count != block_count)
            {
                fprintf(stdout, 
                    "Got inconsistent block counts between blocks\n");
                close(peer_socket);
                return;
            }

            for (int i=0; i<SHA256_HASH_SIZE; i++)
            {
                if (ref_hash[i] != total_hash[i])
                {
                    fprintf(stdout, 
                        "Got inconsistent total hashes between blocks\n");
                    close(peer_socket);
                    return;
                }
            }
        }

        // Check response status
        if (reply_status != STATUS_OK)
        {
            if (command == COMMAND_REGISTER && reply_status == STATUS_PEER_EXISTS)
            {
                printf("Peer already exists\n");
            }
            else
            {
                printf("Got unexpected status %d\n", reply_status);
                close(peer_socket);
                return;
            }
        }

        // Read the payload
        char payload[reply_length+1];
        compsys_helper_readnb(&state, msg_buf, reply_length);
        memcpy(payload, msg_buf, reply_length);
        payload[reply_length] = '\0';
        
        // Check the hash of the data is as expected
        hashdata_t payload_hash;
        get_data_sha(payload, payload_hash, reply_length, SHA256_HASH_SIZE);

        for (int i=0; i<SHA256_HASH_SIZE; i++)
        {
            if (payload_hash[i] != block_hash[i])
            {
                fprintf(stdout, "Payload hash does not match specified\n");
                close(peer_socket);
                return;
            }
        }

        // If we're trying to get a file, actually write that file
        if (command == COMMAND_RETREIVE)
        {
            // Check we can access the output file
            fp = fopen(output_file_path, "r+b");
            if (fp == 0)
            {
                printf("Failed to open destination: %s\n", output_file_path);
                close(peer_socket);
            }

            uint32_t offset = this_block * (MAX_MSG_LEN-REPLY_HEADER_LEN);
            fprintf(stdout, "Block num: %d/%d (offset: %d)\n", this_block+1, 
                block_count, offset);
            fprintf(stdout, "Writing from %d to %d\n", offset, 
                offset+reply_length);

            // Write data to the output file, at the appropriate place
            fseek(fp, offset, SEEK_SET);
            fputs(payload, fp);
            fclose(fp);
        }
    }

    // Confirm that our file is indeed correct
    if (command == COMMAND_RETREIVE)
    {
        fprintf(stdout, "Got data and wrote to %s\n", output_file_path);

        // Finally, check that the hash of all the data is as expected
        hashdata_t file_hash;
        get_file_sha(output_file_path, file_hash, SHA256_HASH_SIZE);

        for (int i=0; i<SHA256_HASH_SIZE; i++)
        {
            if (file_hash[i] != total_hash[i])
            {
                fprintf(stdout, "File hash does not match specified for %s\n", 
                    output_file_path);
                close(peer_socket);
                return;
            }
        }
    }

    // If we are registering with the network we should note the complete 
    // network reply
    char* reply_body = malloc(reply_length + 1);
    memset(reply_body, 0, reply_length + 1);
    memcpy(reply_body, msg_buf, reply_length);

    if (reply_status == STATUS_OK)
    {
        if (command == COMMAND_REGISTER)
        {
            // read the payload

            // payload indeholder liste i form af networkAddress_t
            NetworkAddress_t* received_network_of_peers = (NetworkAddress_t*)reply_body;
            uint32_t received_count = reply_length / sizeof(NetworkAddress_t);

            // locking because are accessing a global variable
            pthread_mutex_lock(&network_mutex);

            network = realloc(network, received_count * sizeof(PeerAddress_t*));

            //add all peers to the network

            for(uint32_t i =0;i < received_count; i++){
                network[i] = malloc(sizeof(PeerAddress_t));
                memcpy(network[i]->ip, received_network_of_peers[i].ip, IP_LEN);
                sprintf(network[i]->port,"%d",ntohl(received_network_of_peers[i].port));
            }
            peer_count = received_count;

            //unlocking
            pthread_mutex_unlock(&network_mutex);
            
        }
    } 
    else
    {
        printf("Got response code: %d, %s\n", reply_status, reply_body);
    }
    pthread_mutex_lock(&network_mutex);
    printf("network:\n");
            for (uint32_t i=0; i<peer_count; i++)
            {
                printf("Peer %d: %s:%s\n", i, network[i]->ip, network[i]->port);
            }
    pthread_mutex_unlock(&network_mutex);
    free(reply_body);
    close(peer_socket);
}

// user interaction function for each client thread
void* client_thread(void* thread_args)
{
    struct PeerAddress *peer_address = thread_args;

    // Register the given user just once
    send_message(*peer_address, COMMAND_REGISTER, "\0");

    //user interface
    while(1){
        get_random_peer(peer_address);
        printf("Type the name of a file to be retrieved, or 'quit' to quit:\n");
        char input[PATH_LEN];
        scanf("%s", input);
        if (strcmp(input, "quit") == 0) {
            break;
        }
        send_message(*peer_address,COMMAND_RETREIVE, input);
    }
    return NULL;
}

/*
 * Handle any 'register' type requests, as defined in the asignment text. This
 * should always generate a response.
 */
void handle_register(int connfd, char* client_ip, int client_port_int)
{
    pthread_mutex_lock(&network_mutex);

    //check if ip and port are valid.
    char* client_port = malloc(PORT_LEN);
    uint32_t informing_client_port = htonl(client_port_int);
    sprintf(client_port,"%d",client_port_int);

    if (is_valid_ip(client_ip) == 0 || is_valid_port(client_port) == 0)
    {
        printf("Invalid IP or port\n");

        // send empty reply with status code 4

        struct ReplyHeader reply_header;
        reply_header.length = htonl(0);
        reply_header.status = htonl(STATUS_OTHER);
        reply_header.this_block = htonl(0);
        reply_header.block_count = htonl(0);
        memset(reply_header.block_hash, 0, SHA256_HASH_SIZE);
        memset(reply_header.total_hash, 0, SHA256_HASH_SIZE);
        char reply_buf[REPLY_HEADER_LEN];
        memcpy(reply_buf, &reply_header, REPLY_HEADER_LEN);
        compsys_helper_writen(connfd, reply_buf, REPLY_HEADER_LEN);
        pthread_mutex_unlock(&network_mutex);
        return;
    }

    // check incase peer already on network list (ligesom i handle inform)
    int exists = 0;
    for (uint32_t  i=0; i<peer_count; i++)
    {
        if (strcmp(network[i]->ip, client_ip) == 0 
                && strcmp(network[i]->port, client_port) == 0 )
        {
            
            exists = 1;
            break;
        }
    }

    // if peer isn't in the network list, then add it to the list. (like in handle inform)
    if(!exists){

        PeerAddress_t* new_peer = malloc(sizeof(PeerAddress_t));
        strncpy(new_peer->ip, client_ip, IP_LEN);
        strncpy(new_peer->port, client_port, PORT_LEN);

        char peer_port[PORT_LEN];
        sprintf(peer_port,"%d",(client_port_int)); 
        strncpy(new_peer->port, peer_port,PORT_LEN);

        network = realloc(network, (peer_count + 1) * sizeof(PeerAddress_t*));
        network[peer_count] = new_peer;
        peer_count++;


        //payload containing network list

        char payload[peer_count * sizeof(NetworkAddress_t)];
        NetworkAddress_t* network_adress = malloc(peer_count*sizeof(NetworkAddress_t));

        // adding the network list to the payload
        for (uint32_t i=0; i<peer_count; i++){
            memcpy(network_adress[i].ip, network[i]->ip, IP_LEN);
            network_adress[i].port = htonl(atoi(network[i]->port));
            memcpy(payload+ i*sizeof(NetworkAddress_t),&network_adress[i],sizeof(NetworkAddress_t));
        }

        printf("new network:\n");
        for (uint32_t i=0; i<peer_count; i++)
        {
            printf("Peer %d: %s:%s\n", i, network[i]->ip, network[i]->port);
        }


        struct ReplyHeader reply_header;
        reply_header.length = htonl(peer_count * sizeof(NetworkAddress_t));
        reply_header.block_count = htonl(1);
        reply_header.status = htonl(STATUS_OK);
        reply_header.this_block = htonl(0);

        //hashing the payload
        hashdata_t payload_hash;
        get_data_sha(payload, payload_hash, peer_count * sizeof(NetworkAddress_t), SHA256_HASH_SIZE);

        memcpy(reply_header.block_hash, payload_hash, SHA256_HASH_SIZE);
        memcpy(reply_header.total_hash, payload_hash, SHA256_HASH_SIZE);

        char reply_buffer[REPLY_HEADER_LEN + peer_count * sizeof(NetworkAddress_t)];
        memcpy(reply_buffer, &reply_header, REPLY_HEADER_LEN);
        memcpy(reply_buffer+REPLY_HEADER_LEN, payload, peer_count * sizeof(NetworkAddress_t));
        compsys_helper_writen(connfd, reply_buffer, sizeof(reply_buffer));


        // inform everynoe else that a new peer joining
        char request[IP_LEN + 4];
        memset(request, '\0', IP_LEN + 4);
        memcpy(request, client_ip,IP_LEN);
        memcpy(request + IP_LEN, &informing_client_port,sizeof(informing_client_port));


        for (uint32_t i=0; i<peer_count; i++)
        {
            if (!(((strcmp(network[i]->ip, client_ip) == 0)
                    && 
                    (strcmp(network[i]->port, client_port) == 0 ))
                    || 
                    ((strcmp(network[i]->ip, my_address->ip) == 0) 
                    && 
                    (strcmp(network[i]->port, my_address->port) == 0 ))))
            {
                send_message(*network[i], COMMAND_INFORM, request);
            }
        }
        pthread_mutex_unlock(&network_mutex);
        return;


    }
    else{
        // reply with status 2 peer already exists 
        struct ReplyHeader reply_header;
        reply_header.length = htonl(0);
        reply_header.status = htonl(STATUS_PEER_EXISTS);
        reply_header.this_block = htonl(0);
        reply_header.block_count = htonl(0);
        memset(reply_header.block_hash, 0, SHA256_HASH_SIZE);
        memset(reply_header.total_hash, 0, SHA256_HASH_SIZE);
        char reply_buf[REPLY_HEADER_LEN];
        memcpy(reply_buf, &reply_header, REPLY_HEADER_LEN);
        compsys_helper_writen(connfd, reply_buf, REPLY_HEADER_LEN);
        pthread_mutex_unlock(&network_mutex);
        return;
    }
    

}

/*
 * Handle 'inform' type message as defined by the assignment text. These will 
 * never generate a response, even in the case of errors.
 */
void handle_inform(PeerAddress_t* peer_address)
{
    int exists = 0;
    //check if the peer already exists
    pthread_mutex_lock(&network_mutex);
    printf("peer ip: %s\n", peer_address->ip);
    printf("peer port: %s\n", peer_address->port);
    for (uint32_t i=0; i<peer_count; i++)
    {
        if ((strcmp(network[i]->ip, peer_address->ip) == 0) 
                && (strcmp(network[i]->port, peer_address->port) == 0) )
        {
            exists = 1;
            break;
        }
    }
    
    //add to network if peer isnt on the list
    if(!exists){

        network = realloc(network, (peer_count + 1) * sizeof(PeerAddress_t*));
        network[peer_count] = peer_address;
        peer_count++;

        
        printf("Peer joining with IP: %s, and PORT: %s\n", peer_address->ip,peer_address->port);
    }
    printf("network:\n");
            for (uint32_t i=0; i<peer_count; i++)
            {
                printf("Peer %d: %s:%s\n", i, network[i]->ip, network[i]->port);
            }
    pthread_mutex_unlock(&network_mutex);
}

/*
 * Handle 'retrieve' type messages as defined by the assignment text. This will
 * always generate a response
 */
void handle_retreive(int connfd, char* request)
{
    char* file_to_get = request;
    pthread_mutex_lock(&retrieving_mutex);

    //open the requested file
    printf("file to get: %s\n", file_to_get);

    FILE* file = fopen(file_to_get, "r");
    if (file == NULL){
        struct ReplyHeader reply_header;
        reply_header.length = htonl(0);
        reply_header.status = htonl(STATUS_BAD_REQUEST);
        reply_header.this_block = htonl(0);
        reply_header.block_count = htonl(0);
        
        get_data_sha("", reply_header.block_hash, 0, SHA256_HASH_SIZE);
        get_data_sha("", reply_header.total_hash, 0, SHA256_HASH_SIZE);
        char reply_buf[REPLY_HEADER_LEN];
        memcpy(reply_buf, &reply_header, REPLY_HEADER_LEN);

        compsys_helper_writen(connfd, reply_buf, REPLY_HEADER_LEN);
        printf("file not found\n");
        pthread_mutex_unlock(&retrieving_mutex);
    }
    else{
        // size of file
        fseek(file,0L,SEEK_END);
        long file_size = ftell(file);
        
        // total number of blocks
        uint32_t total_blocks = ceil((double)file_size / (SENDABLE_LENGTH));

        //total hash of file
        hashdata_t total_hash;
        get_file_sha(file_to_get, total_hash,SHA256_HASH_SIZE);
        fseek(file,0L,SEEK_SET);

        //read the file and send the blocks

        char buffer[SENDABLE_LENGTH];
        uint32_t block_number = 0;
        size_t bytes;
        while((bytes = fread(buffer,1,SENDABLE_LENGTH,file)) > 0 ){
            // create response header
            struct ReplyHeader reply_header;
            reply_header.length = htonl(bytes);
            reply_header.status = htonl(STATUS_OK);
            reply_header.this_block = htonl(block_number);
            reply_header.block_count = htonl(total_blocks);

            //hashing the block
            hashdata_t block_hash;
            get_data_sha(buffer, block_hash, bytes, SHA256_HASH_SIZE);
            memcpy(reply_header.block_hash, block_hash, SHA256_HASH_SIZE);

            //adding the total hash to the header
            memcpy(reply_header.total_hash, total_hash, SHA256_HASH_SIZE);

            char reply_buffer[REPLY_HEADER_LEN + bytes];
            memcpy(reply_buffer, &reply_header, REPLY_HEADER_LEN);
            memcpy(reply_buffer+REPLY_HEADER_LEN,buffer,bytes);
            reply_buffer[REPLY_HEADER_LEN + bytes] = '\0';

            //sending the reply
            printf("sending block %d of %d\n", block_number, total_blocks);
            compsys_helper_writen(connfd, reply_buffer, sizeof(reply_buffer));
            block_number++;
        }
        fclose(file);
    }
    
    pthread_mutex_unlock(&retrieving_mutex);

    // printing the network and locking the mutex as its a global variable
    pthread_mutex_lock(&network_mutex);
    printf("network is:\n");
            for (uint32_t i=0; i<peer_count; i++)
            {
                printf("Peer %d: %s:%s\n", i, network[i]->ip, network[i]->port);
            }
    // unlocking the mutex
    pthread_mutex_unlock(&network_mutex);
}

/*
 * Handler for all server requests. This will call the relevent function based 
 * on the parsed command code
 */
void handle_server_request(int connfd)
{
    char header_buffer[REQUEST_HEADER_LEN];
    struct RequestHeader request_header;

    compsys_helper_state_t state;
    compsys_helper_readinitb(&state, connfd);
    if (compsys_helper_readnb(&state,header_buffer,sizeof(header_buffer)) < 0) {
        printf("error reading header\n");
    }
    
    // extracting the header
    memcpy(&request_header, header_buffer, REQUEST_HEADER_LEN);

    // getting the necessary information needed from the header.
    int command = ntohl(request_header.command);
    int payload_length = ntohl(request_header.length);

    char msg_buf[payload_length];

    //reading payload now
    if(compsys_helper_readnb(&state, msg_buf, payload_length) < 0){
        printf("error reading payload\n");
    }

    char IP[IP_LEN];
    char PORT[PORT_LEN];
    char file_payload[payload_length];
    PeerAddress_t* peer_address = malloc(sizeof(PeerAddress_t));

    switch(command){
        case COMMAND_INFORM:
            memcpy(IP, msg_buf, IP_LEN);
            sprintf(PORT,"%d",ntohl(*(uint32_t*)(msg_buf + IP_LEN)));
            memcpy(peer_address->ip, IP, IP_LEN);
            memcpy(peer_address->port, PORT, PORT_LEN);

            handle_inform(peer_address);
            break;
        case COMMAND_REGISTER:
            handle_register(connfd, request_header.ip, ntohl(request_header.port));
            break;
        case COMMAND_RETREIVE:
            memcpy(file_payload, msg_buf, payload_length);
            file_payload[payload_length] = '\0';
            handle_retreive(connfd, file_payload);
            break;
        default:
            printf("unknown command: %d\n", command);
            break;
    }
}

// each server request is handled by this function
void *server_thread_i(void* thread_args){
    int connfd = *(int *)thread_args;
    free(thread_args);
    handle_server_request(connfd);
    close(connfd);
    return NULL;
}


void* server_thread()
{

    //starting the server

    int listenfd;
    struct sockaddr_in listen_address;
    int lis_addr_len = sizeof(listen_address);
    struct sockaddr_storage clientaddr;

    // Create listening socket
    listenfd = compsys_helper_open_listenfd(my_address->port);
    printf("starting server at: %s:%s\n", my_address->ip, my_address->port);

    while (1) {
        // Accept incoming connections
        int* connfd = malloc(sizeof(int));
        if ((*connfd = accept(listenfd, (struct sockaddr*)&clientaddr, (socklen_t*)&lis_addr_len)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        else{
            //making a new thread for each request
            pthread_t thread_id;
            pthread_create(&thread_id, NULL, server_thread_i, connfd);
        }
    }
    return NULL;
}



int main(int argc, char **argv)
{
    // Initialise with known junk values, so we can test if these were actually
    // present in the config or not
    struct PeerAddress peer_address;
    memset(peer_address.ip, '\0', IP_LEN);
    memset(peer_address.port, '\0', PORT_LEN);
    memcpy(peer_address.ip, "x", 1);
    memcpy(peer_address.port, "x", 1);

    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (PeerAddress_t*)malloc(sizeof(PeerAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memset(my_address->port, '\0', PORT_LEN);

    // Read in configuration options. Should include a client_ip, client_port, 
    // server_ip, and server_port
    char buffer[128];
    fprintf(stderr, "Got config path at: %s\n", argv[1]);
    FILE* fp = fopen(argv[1], "r");
    while (fgets(buffer, 128, fp)) {
        if (starts_with(buffer, MY_IP)) {
            memcpy(&my_address->ip, &buffer[strlen(MY_IP)], 
                strcspn(buffer, "\r\n")-strlen(MY_IP));
            if (!is_valid_ip(my_address->ip)) {
                fprintf(stderr, ">> Invalid client IP: %s\n", my_address->ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, MY_PORT)) {
            memcpy(&my_address->port, &buffer[strlen(MY_PORT)], 
                strcspn(buffer, "\r\n")-strlen(MY_PORT));
            if (!is_valid_port(my_address->port)) {
                fprintf(stderr, ">> Invalid client port: %s\n", 
                    my_address->port);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, PEER_IP)) {
            memcpy(peer_address.ip, &buffer[strlen(PEER_IP)], 
                strcspn(buffer, "\r\n")-strlen(PEER_IP));
            if (!is_valid_ip(peer_address.ip)) {
                fprintf(stderr, ">> Invalid peer IP: %s\n", peer_address.ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, PEER_PORT)) {
            memcpy(peer_address.port, &buffer[strlen(PEER_PORT)], 
                strcspn(buffer, "\r\n")-strlen(PEER_PORT));
            if (!is_valid_port(peer_address.port)) {
                fprintf(stderr, ">> Invalid peer port: %s\n", 
                    peer_address.port);
                exit(EXIT_FAILURE);
            }
        }
    }
    fclose(fp);

    srand(time(0));

    network = malloc(sizeof(PeerAddress_t*));
    network[0] = my_address;
    peer_count = 1;

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x')
    {   
        pthread_create(&client_thread_id, NULL, client_thread, &peer_address);
    } 
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Start the threads. Note that the client is only started if a peer is 
    // provided in the config. If none is we will assume this peer is the first
    // on the network and so cannot act as a client.
    if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x')
    {
        pthread_join(client_thread_id, NULL);
    }
    pthread_join(server_thread_id, NULL);

    // Freeing all malloced memory 
    free(my_address);

    for (uint32_t i=0; i<peer_count; i++)
    {
        free(network[i]);
    }
    free(network);


    exit(EXIT_SUCCESS);
}