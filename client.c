#include <fcntl.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define PORT_NUM 4000
#define SERVER_ADDR "127.0.0.1"

int server_fd;
pthread_t receive_thread, sent_thread;

int hextostring(char *in, int len, char *out)
{
    int i;

    memset(out, 0, sizeof(out));
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

    memset(out, 0, sizeof(out));

    for (i = 0; i < len; i = i + 2)
    {
        char byte = converter[in[i]] << 4 | converter[in[i + 1]];
        out[i / 2] = byte;
    }
}

static void *receive_message(void *fun_arg)
{
    int *server_fd = (int *)fun_arg;
    uint16_t receive_byte;
    char buffer[1200], name[100], hex_message[1000], message[1200];
    int des_fd = open("/dev/aes_encrypt", O_RDWR); // mở driver aes_encryt
    while (1)                                      // luồng nhận tin nhắn
    {
        memset(buffer, 0, sizeof(buffer));                              // set giá trị cho vùng nhớ
        if (read(*server_fd, &receive_byte, sizeof(receive_byte)) == 0) // nhận tin nhắn từ server
        {
            printf("disconnect from server\n");
            exit(0);
        }
        if (read(*server_fd, buffer, receive_byte) == 0) // nhận tin nhắn từ server lưu vào buffer
        {
            printf("disconnect from server\n");
            exit(0);
        }
        sscanf(buffer, "%[^:]: %[0-9abcdef]", name, hex_message); // tách tên và tin nhắn từ buffer

        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "decrypt\n%s", hex_message); // gán type cho data
        write(des_fd, buffer, strlen(buffer));       // gửi lệnh giải mã xuống driver

        memset(hex_message, 0, sizeof(hex_message));
        read(des_fd, hex_message, sizeof(hex_message)); // đọc dữ liệu đã được giải mã từ driver

        stringtohex(hex_message, sizeof(hex_message), message); // chuyển đổi hex sang ksi tự
        printf("%s: %s\n", name, message);                      // hiển thị tin nhắn
    }
    close(des_fd);
}

static void *send_message(void *fun_arg)
{
    int *server_fd = (int *)fun_arg;
    uint16_t sent_byte;
    char message[1000], hex_message[1000], encrypt_message[1200];

    int des_fd = open("/dev/aes_encrypt", O_RDWR); // mở driver aes_encryt
    if (des_fd == -1)
    {
        printf("khong mo dc file driver\n");
        exit(0);
    }

    while (1) // luồng gửi tin nhắn
    {
        memset(message, 0, sizeof(message));

        fgets(message, sizeof(message), stdin);
        message[strlen(message) - 1] = 0;

        hextostring(message, strlen(message), hex_message);      // chuyển đổi string to hex
        sprintf(encrypt_message, "encrypt\n%s", hex_message);    // gắn type cho data
        write(des_fd, encrypt_message, strlen(encrypt_message)); // gửi data tới driver để mã hóa

        memset(encrypt_message, 0, sizeof(encrypt_message));
        read(des_fd, encrypt_message, sizeof(encrypt_message)); // nhận dữ liệu mã hóa từ driver

        sent_byte = strlen(encrypt_message);
        write(*server_fd, &sent_byte, sizeof(sent_byte)); // gửi tới server độ dài data
        write(*server_fd, encrypt_message, sent_byte);    // guwit tới server dữ liệu đã được mã hóa
    }
    close(des_fd);
}

int login(int server_fd) // thực hiện đăng nhập
{
    char username[100], password[100], login_buffer[300];
    uint16_t send_byte;

    memset(username, 0, sizeof(username));         // set giá trị cho vùng nhớ
    memset(password, 0, sizeof(password));         // set giá trị cho vùng nhớ
    memset(login_buffer, 0, sizeof(login_buffer)); // set giá trị cho vùng nhớ

    printf("username: ");
    fgets(username, sizeof(username), stdin); // lấy username từ bàn phím
    username[strlen(username) - 1] = 0;

    printf("password: ");
    fgets(password, sizeof(password), stdin); // lấy password từ bàn phím
    password[strlen(password) - 1] = 0;

    sprintf(login_buffer, "%s:%s", username, password);

    send_byte = strlen(login_buffer);
    write(server_fd, &send_byte, sizeof(send_byte));
    write(server_fd, login_buffer, send_byte);
}

int main()
{
    int status, login_status;
    struct sockaddr_in server_addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0); // tạo mô tả về socket
    if (server_fd == -1)
    {
        fprintf(stderr, "create socket error\n");
        exit(0);
    }

    memset(&server_addr, 0, sizeof(server_addr));                     // set giá trị cho vùng nhớ
    server_addr.sin_family = AF_INET;                                 // thiết lập giao thức ipv4
    server_addr.sin_port = htons(PORT_NUM);                           // thiết lập cổng
    if (inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr) == -1) // chuyển đổi địa chỉ ipv4 từ text thành binary
    {
        fprintf(stderr, "server_addr fail\n");
        exit(0);
    }

    status = connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)); // kêt nối tới server
    if (status == -1)
    {
        fprintf(stderr, "connect error\n");
        exit(0);
    }

    printf("connect to server!\n");
    login(server_fd);                                                   // thực hiện đăng nhập
    pthread_create(&receive_thread, NULL, receive_message, &server_fd); // khowit tạo luồng lắng nghe các tin nhắn đến (lắng nghe hàm recevie_message)
    pthread_create(&sent_thread, NULL, send_message, &server_fd);       // khởi tạo luồng lắng nghe các tin nhắn gửi đi(lắng nghe hàm send_message)
    while (1)
        sleep(1);

    return 0;
}