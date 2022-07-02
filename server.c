#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>

#define PORT_NUM 4000
#define LISTEN_BACKLOG 100
#define ENCRYPT_FILE "/dev/aes_encrypt"

int hextostring(char *in, int len, char *out);

typedef struct ChatUser
{
    int fd;
    char chat_name[100];
} ChatUser;

typedef struct Account
{
    char username[200];
    uint8_t sha224[57];
} Account;

Account accounts[200];
uint16_t size = 0;

int add_account(Account account)
{
    strcpy(accounts[size].username, account.username);
    strcpy(accounts[size].sha224, account.sha224);
    size++;
    return 0;
}

int remove_account(uint16_t ind)
{
    for (int i = ind; i < size; i++)
    {
        accounts[i] = accounts[i + 1];
    }
    size--;
}

int print_account()
{
    printf("%-5s%-15s%-57s\n", "STT", "username", "sha224");
    for (int i = 0; i < size; i++)
    {
        printf("%-5d%-15s%-57s\n", i + 1, accounts[i].username, accounts[i].sha224);
    }
}

ChatUser register_list[100];
int register_size = 0;

void add_service(int sockfd, char *chat_name)
{
    memset(register_list[register_size].chat_name, 0, sizeof(register_list[register_size].chat_name));
    register_list[register_size].fd = sockfd;
    strcpy(register_list[register_size].chat_name, chat_name);
    register_size++;
}

void remove_service(int sockfd)
{
    for (int i = 0; i < register_size; i++)
    {
        if (register_list[i].fd == sockfd)
        {
            for (int j = i; j < register_size - 1; j++)
            {
                register_list[j] = register_list[j + 1];
            }
            break;
        }
    }
    register_size--;
}


void broadcast(int user_fd, char *message)
{
    char buffer[1000], name[100];
    uint16_t sent_byte;

    for (int i = 0; i < register_size; i++)
    {
        if (register_list[i].fd == user_fd)
        {
            strcpy(name, register_list[i].chat_name);
            break;
        }
    }

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "%s: %s", name, message);
    sent_byte = strlen(buffer);

    for (int i = 0; i < register_size; i++)
    {
        if (register_list[i].fd != user_fd)
        {
            write(register_list[i].fd, &sent_byte, sizeof(sent_byte));
            write(register_list[i].fd, buffer, sent_byte);
        }
    }
}

int login(char *username, char *password)
{
    int encrypt_fd = open(ENCRYPT_FILE, O_RDWR);
    char hash_buffer[500], password_hex[200], password_hash[200];


    hextostring(password, strlen(password), password_hex);
    sprintf(hash_buffer, "hash\n%s", password_hex);
    write(encrypt_fd, hash_buffer, strlen(hash_buffer));
    read(encrypt_fd, password_hash, sizeof(password_hash));

    for (int i = 0; i < size; i++) {
        if (strcmp(username, accounts[i].username) == 0 && strcmp(password_hash, accounts[i].sha224) == 0)
            return 1;
    }

    return 0;
}

int hextostring(char *in, int len, char *out)
{
    int i;

    for (i = 0; i < len; i++)
    {
        sprintf(out, "%s%02hhx", out, in[i]);
    }
    return 0;
}

int stringtohex(char *in, int len, char *out)
{
    int i;
    int converter[105];
    converter['0'] = 0;
    converter['1'] = 1;
    converter['2'] = 2;
    converter['3'] = 3;
    converter['4'] = 4;
    converter['5'] = 5;
    converter['6'] = 6;
    converter['7'] = 7;
    converter['8'] = 8;
    converter['9'] = 9;
    converter['a'] = 10;
    converter['b'] = 11;
    converter['c'] = 12;
    converter['d'] = 13;
    converter['e'] = 14;
    converter['f'] = 15;

    for (i = 0; i < len; i = i + 2)
    {
        char byte = converter[(int)in[i]] << 4 | converter[(int)in[i + 1]];
        out[i / 2] = byte;
    }

    return 0;
}

void *account_manager(void *fun_arg)
{
    int choice = 0, encrypt_fd = -1;

    encrypt_fd = open(ENCRYPT_FILE, O_RDWR);

    while (1)
    {
        system("clear");
        print_account();
        printf("1. create account\n");
        printf("2. remove account\n");
        printf("3. exit\n");
        scanf("%d", &choice);
        getchar();

        switch (choice)
        {
        case 1:
        {
            Account account;
            char hash_buffer[500], password[100], password_hex[200], password_hash[200];

            memset(hash_buffer, 0, sizeof(hash_buffer));
            memset(password, 0, sizeof(password));
            memset(password_hex, 0, sizeof(password_hex));
            memset(password_hash, 0, sizeof(password_hash));

            printf("username: ");
            fgets(account.username, sizeof(account.username), stdin);
            account.username[strlen(account.username) - 1] = 0;

            printf("password: ");
            fgets(password, sizeof(password), stdin);
            password[strlen(password) - 1] = 0;
            hextostring(password, strlen(password), password_hex);
            sprintf(hash_buffer, "hash\n%s", password_hex);
            write(encrypt_fd, hash_buffer, strlen(hash_buffer));
            read(encrypt_fd, password_hash, sizeof(password_hash));

            strcpy(account.sha224, password_hash);

            add_account(account);

            break;
        }

        case 2:
        {
            int index;
            scanf("%d", &index);
            getchar();
            printf("%d\n", index);
            remove_account(index);
            break;
        }

        case 3:
        {
            exit(0);
        }

        default:
            break;
        }
    }
}

void *socket_handler(void *fun_arg)
{
    int *client_fd = (int *)fun_arg, login_result;
    uint16_t sent_byte, receive_byte;
    char message[1000], username[100], password[100], login_buffer[300];

    // printf("accept client: %d\n", *client_fd);

    memset(login_buffer, 0, sizeof(login_buffer));
    read(*client_fd, &receive_byte, sizeof(receive_byte));
    read(*client_fd, login_buffer, receive_byte);

    sscanf(login_buffer, "%[^:]:%s", username, password);

    if (login(username, password) == 0)
        goto out;

    // printf("name: %s\n", username);
    add_service(*client_fd, username);

    while (1)
    {
        int read_status;
        memset(message, 0, sizeof(message));
        if (read(*client_fd, &receive_byte, sizeof(receive_byte)) == 0)
        {
            break;
        }
        if (read(*client_fd, message, receive_byte) == 0)
        {
            break;
        }

        // printf("%s: %s\n", username, message);
        broadcast(*client_fd, message);
    }

out:
    remove_service(*client_fd);
    close(*client_fd);
    free(client_fd);
}

int main()
{
    int server_fd, len, otp;
    struct sockaddr_in server_addr, client_addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        fprintf(stderr, "create socket error\n");
        exit(0);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT_NUM);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    otp = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &otp, sizeof(otp));

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        fprintf(stderr, "binding error\n");
        exit(0);
    }

    if (listen(server_fd, LISTEN_BACKLOG) == -1)
    {
        fprintf(stderr, "listen error\n");
        exit(0);
    }

    printf("listening at port %d\n", PORT_NUM);

    pthread_t account_manager_thread;
    pthread_create(&account_manager_thread, NULL, account_manager, NULL);

    while (1)
    {
        int *pclient_fd = malloc(sizeof(int));
        pthread_t thread;
        *pclient_fd = accept(server_fd, (struct sockaddr *)&client_addr, &len);
        if (*pclient_fd == -1)
        {
            fprintf(stderr, "accept error\n");
            exit(0);
        }
        pthread_create(&thread, NULL, socket_handler, pclient_fd);
    }

    return 0;
}