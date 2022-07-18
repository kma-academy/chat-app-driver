#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/ctype.h>

#define MEM_SIZE 1024

struct sdesc
{
    struct shash_desc shash;
    char ctx[];
};

uint8_t *kernel_buffer;
dev_t dev_num;
struct class *device_class;
struct cdev *char_device;
struct crypto_cipher *tfm;
char key[20] = "1234567890abcdef";
char type[100];
char data[MEM_SIZE];
size_t data_len = 0;

static struct sdesc
    *init_sdesc(struct crypto_shash *alg) // hàm khởi tạo vùng nhớ cho việc hash
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(
    struct crypto_shash *alg,
    const unsigned char *data, unsigned int datalen,
    unsigned char *digest) // hàm thực hiện hash
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg); // khởi tạo vùng nhớ cho việc hash
    if (IS_ERR(sdesc))
    {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest); // thực hiện hash dữ liệu
    kfree(sdesc);
    return ret;
}

static int sha224_hash(
    const unsigned char *data,
    unsigned int datalen,
    unsigned char *digest)
{
    struct crypto_shash *alg;       // khai báo thuật toán
    char *hash_alg_name = "sha224"; // thuật toán sử dụng để hash
    int ret;

    alg = crypto_alloc_shash(hash_alg_name, 0, 0); // khởi tạo thuật toán
    if (IS_ERR(alg))
    {
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    ret = calc_hash(alg, data, datalen, digest);
    crypto_free_shash(alg); // giải phóng bộ nhớ
    return ret;
}

int hextostring(char *in, int len, char *out) // chuyển đổi từ string về kí tự hex
{
    int i;

    for (i = 0; i < len; i++)
    {
        sprintf(out, "%s%02hhx", out, in[i]);
    }
    return 0;
}

int stringtohex(char *in, int len, char *out) // chuyển đổi từ hex về string
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

static int open_fun(struct inode *inode, struct file *file)
{
    return 0;
}

static int release_fun(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t read_fun(struct file *file, char *user_buf, size_t len, loff_t *off)
{
    char cipher[1000];
    char hex_cipher[1000];
    int i, j;

    printk("data_len: %ld\n", data_len);

    memset(cipher, 0, sizeof(cipher));         // set giá trị của vùng nhớ
    memset(hex_cipher, 0, sizeof(hex_cipher)); // set giá trị của vùng nhớ

    if (strcmp(type, "hash") == 0) // nếu type là hash thì sẽ thực hiện hash dữ liệu nhận được từ quá trình write
    {
        char sha224[200], sha224_hex[200];
        int len = strlen(data);

        memset(sha224, 0, sizeof(sha224));         // set giá trị của vùng nhớ
        memset(sha224_hex, 0, sizeof(sha224_hex)); // set giá trị của vùng nhớ

        sha224_hash(data, len, sha224);                  // gọi tới hàm sha224_hash để thực hiện hash
        hextostring(sha224, strlen(sha224), sha224_hex); // chuyển đổi hextostring
        printk("hash: %s\n", sha224_hex);
        copy_to_user(user_buf, sha224_hex, strlen(sha224_hex)); // copy dữ liệu vừa hash vào user_buff (kernel space => user space)
    }
    else // nếu ko phải hash thì chỉ còn 2 TH là encrypt hoặc decrypt
    {
        for (i = 0; i < data_len / 16; i++) // khối dữ liệu chia cho 16 và duyệt qua hết các khối
        {
            char one_data[20], one_cipher[20];

            memset(one_data, 0, sizeof(one_data));     // set giá trị của vùng nhớ
            memset(one_cipher, 0, sizeof(one_cipher)); // set giá trị của vùng nhớ

            for (j = 0; j < 16; j++) // lấy 16 byte dữ liệu
                one_data[j] = data[i * 16 + j];

            printk("one data: %s\n", one_data);

            if (strcmp(type, "encrypt") == 0) // nếu type là encrypt thì gọi hàm encrypt
                crypto_cipher_encrypt_one(tfm, one_cipher, one_data);
            if (strcmp(type, "decrypt") == 0) // nếu type là decrypt thì gọi hàm decrypt
                crypto_cipher_decrypt_one(tfm, one_cipher, one_data);
            for (j = 0; j < 16; j++) // nối các khối dữ liệu sau khi đc en/de
                cipher[i * 16 + j] = one_cipher[j];

            // printk("one cipher: %s\n", one_cipher);
        }

        hextostring(cipher, data_len, hex_cipher);
        printk("hex cipher: %s\n", hex_cipher);
        copy_to_user(user_buf, hex_cipher, strlen(hex_cipher)); // copy dữ liệu vừa hash vào user_buff (kernel space => user space)
    }

    return 0;
}

static ssize_t write_fun(struct file *file, const char *user_buff, size_t len, loff_t *off)
{
    char buffer[1000], hex_data[1000];
    int i, j;

    memset(buffer, 0, sizeof(buffer));     // set giá trị của vùng nhớ
    memset(data, 0, sizeof(data));         // set giá trị của vùng nhớ
    memset(type, 0, sizeof(type));         // set giá trị của vùng nhớ
    memset(hex_data, 0, sizeof(hex_data)); // set giá trị của vùng nhớ

    copy_from_user(buffer, user_buff, len); // copy dữ liệu từ kernel space vào  user space

    i = 0;
    j = 0;
    while (buffer[i] != '\n' && j < len) // copy câu lệnh cửa lần write này VD"hash, encrypt,decrypt"

    {
        type[i] = buffer[j];
        i++;
        j++;
    }

    i = 0;
    j++;
    while (j < len) // copy dữ liệu
    {
        hex_data[i] = buffer[j];
        i++;
        j++;
    }

    printk("type: %s\n", type);
    printk("hex_data: %s\n", hex_data);

    memset(buffer, 0, sizeof(buffer));
    stringtohex(hex_data, strlen(hex_data), data); // chuyển đổi string to hex
    printk("data: %s\n", data);

    if (strlen(hex_data) % 32 == 0) // kiểm tra dữ liệu có phải là 1 khối chia hết cho 16 không (16 byte)
        data_len = ((uint16_t)(strlen(hex_data) / 32)) * 16;
    else
        data_len = ((uint16_t)((strlen(hex_data) / 32) + 1)) * 16;
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = read_fun,
    .write = write_fun,
    .open = open_fun,
    .release = release_fun};

static int md_init(void) // định nghĩa hàm nào sẽ được gọi khi module được lắp vào kernel
{
    printk("cai dat module\n");

    tfm = crypto_alloc_cipher("aes", 0, 0); // khởi tạo bộ mã hóa AES
    crypto_cipher_setkey(tfm, key, 16);     // setkey cho AES

    alloc_chrdev_region(&dev_num, 0, 1, "mahoaaesvasha"); // đăng kí số hiệu cho thiết bị truyền kí tự
    // khởi tạo châracter device file
    device_class = class_create(THIS_MODULE, "class");               // tạo một lớp các thiết bị
    device_create(device_class, NULL, dev_num, NULL, "aes_encrypt"); // tạo thiết bị trong lớp đó

    kernel_buffer = kmalloc(MEM_SIZE, GFP_KERNEL); // tạo không gian bộ nhớ trong kernel
    // đăng kí thiết bị
    char_device = cdev_alloc();
    cdev_init(char_device, &fops);
    cdev_add(char_device, dev_num, 1);

    return 0;
}

static void md_exit(void)
{
    crypto_free_cipher(tfm); // giải phóng bộ nhớ
    cdev_del(char_device);   // xóa cdev khởi hệ thống
    kfree(kernel_buffer);
    device_destroy(device_class, dev_num); // xóa thiết bị khởi lớp
    class_destroy(device_class);           // xóa lớp
    unregister_chrdev_region(dev_num, 1);  // hủy số hiệu thiết bị
    printk("thoat module\n");
}

module_init(md_init);
module_exit(md_exit);

MODULE_LICENSE("GPL");