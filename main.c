#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <json-c/json.h>
#include "mongoose.h"

// Static variables
static int s_debug_level = MG_LL_INFO;
static const char *s_root_dir = ".";
static const char *s_listening_address = "http://0.0.0.0:8000";
static const char *s_enable_hexdump = "no";
static const char *s_ssi_pattern = "#.html";
static const char *s_upload_dir = NULL;
static char *login_html;

static int s_signo;

// Signal handler
static void signal_handler(int signo) {
    s_signo = signo;
}

// Function to read login HTML content from file
static void read_login_html(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open login file");
        exit(EXIT_FAILURE);
    }

    // Determine file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // Read content into login_html variable
    login_html = (char *) malloc(file_size + 1);
    fread((void *) login_html, file_size, 1, file);
    login_html[file_size] = '\0';

    fclose(file);
}

// Authentication function
static int authenticate_user(const char *username, const char *password) {
    // Mở tệp JSON để đọc
    FILE *file = fopen("data.json", "r");
    if (file == NULL) {
        perror("Failed to open data.json file");
        return 0; // Trả về lỗi xác thực
    }

    // Tạo một bộ phân tích JSON
    struct json_object *root = json_object_from_file("data.json");
    if (root == NULL) {
        perror("Failed to parse data.json");
        fclose(file);
        return 0; // Trả về lỗi xác thực
    }

    // Tìm đối tượng "account_information"
    struct json_object *account_info;
    if (!json_object_object_get_ex(root, "account_information", &account_info)) {
        perror("Failed to find account_information object");
        fclose(file);
        json_object_put(root);
        return 0; // Trả về lỗi xác thực
    }

    // Tìm kiếm thông tin người dùng trong đối tượng "account_information"
    struct json_object *username_obj, *password_obj;
    json_object_object_get_ex(account_info, "username", &username_obj);
    json_object_object_get_ex(account_info, "password", &password_obj);

    // So sánh tên người dùng và mật khẩu
    int authenticated = (strcmp(json_object_get_string(username_obj), username) == 0) &&
                        (strcmp(json_object_get_string(password_obj), password) == 0);

    // Giải phóng bộ nhớ và đóng tệp
    json_object_put(root);
    fclose(file);

    return authenticated; // Trả về kết quả xác thực
}
void update_json_data(const char *ip_address, const char *logging_level, const char *wireless_mode, const char *wireless_SSID, const char *wireless_Pass_Phrase) {
    FILE *file = fopen("data.json", "r+");
    if (file == NULL) {
        perror("Failed to open data.json file");
        return;
    }

    char temp_file[] = "temp.json";
    FILE *temp = fopen(temp_file, "w");
    if (temp == NULL) {
        fclose(file);
        perror("Failed to create temp file");
        return;
    }

    char line[1024];
    int in_settings = 0;
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "\"settings\": {")) {
            in_settings = 1;
            fputs(line, temp);
            fprintf(temp, "        \"ip-address\": \"%s\",\n", ip_address);
            fprintf(temp, "        \"logging-level\": \"%s\",\n", logging_level);
            fprintf(temp, "        \"wireless-mode\": \"%s\",\n", wireless_mode);
            fprintf(temp, "        \"wireless-SSID\": \"%s\",\n", wireless_SSID);
            fprintf(temp, "        \"wireless-Pass-Phrase\": \"%s\"\n", wireless_Pass_Phrase);
        } else if (in_settings && strstr(line, "}")) {
            in_settings = 0;
            fputs(line, temp);
        } else if (!in_settings) {
            fputs(line, temp);
        }
    }

    fclose(file);
    fclose(temp);

    if (remove("data.json") != 0) {
        perror("Error deleting original file");
        return;
    }

    if (rename(temp_file, "data.json") != 0) {
        perror("Error renaming temp file");
    }
}
void update_password_in_json(const char *new_password) {
    FILE *file = fopen("data.json", "r+");
    if (file == NULL) {
        perror("Failed to open data.json file");
        return;
    }

    // Xác định kích thước của tệp
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // Đọc nội dung của tệp vào bộ đệm
    char *buffer = (char *)malloc(file_size + 1);
    if (buffer == NULL) {
        fclose(file);
        perror("Memory allocation failed");
        return;
    }
    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';

    // Tìm vị trí của "password" trong tệp JSON
    char *password_start = strstr(buffer, "\"password\": \"");
    if (password_start != NULL) {
        password_start += strlen("\"password\": \"");
        char *password_end = strchr(password_start, '\"');
        if (password_end != NULL) {
            // Sao chép mật khẩu mới vào vị trí cũ của mật khẩu cũ
            strncpy(password_start, new_password, password_end - password_start);
        }
    } else {
        printf("Failed to find password field in JSON\n");
    }

    // Đặt con trỏ tệp ở đầu và ghi lại nội dung đã cập nhật
    rewind(file);
    fwrite(buffer, 1, file_size, file);

    // Giải phóng bộ nhớ và đóng tệp
    free(buffer);
    fclose(file);
}
// Event handler for HTTP connection
static void cb(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) { 
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_http_match_uri(hm, "/")) {
            mg_http_reply(c, 200, "", "<html><head><script>window.location.href = 'login.html';</script></head><body></body></html>");
        }
        else if (mg_http_match_uri(hm, "/login")) {
            if (hm->method.len == 4 && memcmp(hm->method.ptr, "POST", 4) == 0) {
                char username[100], password[100];
                mg_http_get_var(&hm->body, "username", username, sizeof(username));
                mg_http_get_var(&hm->body, "password", password, sizeof(password));
                if (authenticate_user(username, password)) {
                    // char location_header[100];
                    // snprintf(location_header, sizeof(location_header), "Location: /home.html?success=%s", "Đăng nhập thành công!");
                    // mg_http_reply(c, 302, "", location_header);
                    mg_http_reply(c, 200, "", "<html><head><script>window.location.href = 'home.html';</script></head><body></body></html>");
                } else {
                    mg_http_reply(c, 401, "", "Authentication failed\n");
                }

            } else {
                mg_http_reply(c, 200, "", login_html);
            }
        } 
        else if(mg_http_match_uri(hm,"/update")) {
            char ip_address[100], logging_level[100], wireless_mode[100], wireless_SSID[100], wireless_Pass_Phrase[100];
            mg_http_get_var(&hm->body, "ip-address", ip_address, sizeof(ip_address));
            mg_http_get_var(&hm->body, "logging-level", logging_level, sizeof(logging_level));
            mg_http_get_var(&hm->body, "wireless-mode", wireless_mode, sizeof(wireless_mode));
            mg_http_get_var(&hm->body, "wireless-SSID", wireless_SSID, sizeof(wireless_SSID));
            mg_http_get_var(&hm->body, "wireless-Pass-Phrase", wireless_Pass_Phrase, sizeof(wireless_Pass_Phrase));

            update_json_data(ip_address, logging_level, wireless_mode, wireless_SSID, wireless_Pass_Phrase);

            // Redirect to a success page or perform other actions if necessary
            mg_http_reply(c, 200, "", "<html><head><script>window.location.href = 'settings.html';</script></head><body></body></html>");
        }
        else if(mg_http_match_uri(hm,"/change_password")) {
            char password[100];
            // mg_http_get_var(&hm->body, "username", username, sizeof(username));
            mg_http_get_var(&hm->body, "new_password", password, sizeof(password));
            update_password_in_json(password);

            // Redirect to a success page or perform other actions if necessary
            mg_http_reply(c, 200, "", "<html><head><script>window.location.href = 'settings.html';</script></head><body></body></html>");
        }
        
        else if (mg_http_match_uri(hm, "/download")) {
            // Xác định tên tệp cần tải xuống từ yêu cầu HTTP
            char file_name[100]; // Độ dài tên tệp tối đa
            if (mg_http_get_var(&hm->body, "file_name", file_name, sizeof(file_name)) > 0) {
                // Tạo đường dẫn đầy đủ đến tệp cần tải xuống
                char file_path[4096];
                snprintf(file_path, sizeof(file_path), "uploads/%s", file_name);

                // Mở tệp để đọc
                FILE *downloaded_file = fopen(file_path, "rb");
                if (downloaded_file != NULL) {
                    fseek(downloaded_file, 0, SEEK_END);
                    long file_size = ftell(downloaded_file);
                    rewind(downloaded_file);

                    // Gửi HTTP headers
                    mg_http_reply(c, 200, "Content-Disposition: attachment", "");

                    // Gửi nội dung của tệp về máy khách
                    char *file_buffer = (char *)malloc(file_size);
                    if (file_buffer != NULL) {
                        fread(file_buffer, 1, file_size, downloaded_file);
                        mg_send(c, file_buffer, file_size);
                        free(file_buffer);
                    } else {
                        // Xử lý lỗi khi không thể cấp phát bộ nhớ
                        mg_http_reply(c, 500, "", "Internal Server Error: Memory allocation failed\n");
                    }

                    fclose(downloaded_file);
                } else {
                    // Xử lý lỗi khi không thể mở tệp để đọc
                    mg_http_reply(c, 500, "", "Internal Server Error: Failed to open file for reading\n");
                }
            } else {
                // Nếu không có tên tệp trong yêu cầu, trả về lỗi 400 (Bad Request)
                mg_http_reply(c, 400, "", "Bad Request: No file name specified\n");
            }
        }
        else if (mg_http_match_uri(hm, "/upload")) {
            struct mg_http_part part;
            size_t ofs = 0;
            while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) > 0) {
                MG_INFO(("Chunk name: [%.*s] filename: [%.*s] length: %lu bytes",
                        (int) part.name.len, part.name.ptr, (int) part.filename.len,
                        part.filename.ptr, (unsigned long) part.body.len));

                printf("Chunk name: [%.*s] filename: [%.*s] length: %lu bytes\n",
                (int) part.name.len, part.name.ptr, (int) part.filename.len,
                part.filename.ptr, (unsigned long) part.body.len);

                // Thay đổi dữ liệu filename trong tệp data.json
                json_object *root_obj, *firmware_obj, *filename_obj;
                FILE *fp;

                // Mở và đọc tệp data.json
                fp = fopen("data.json", "r");
                char buffer[1024];
                fread(buffer, 1, 1024, fp);
                fclose(fp);

                // Phân tích dữ liệu JSON
                root_obj = json_tokener_parse(buffer);
                json_object_object_get_ex(root_obj, "firmware", &firmware_obj);
                json_object_object_get_ex(firmware_obj, "filename", &filename_obj);

                // Thay đổi dữ liệu filename
                json_object_set_string(filename_obj, part.filename.ptr);

                // Ghi dữ liệu JSON mới vào tệp
                fp = fopen("data.json", "w");
                fputs(json_object_to_json_string(root_obj), fp);
                fclose(fp);

                // Giải phóng bộ nhớ
                json_object_put(root_obj);
            }
            mg_http_reply(c, 200, "", "<html><head><script>window.location.href = 'update_firmware.html';</script></head><body></body></html>");
        }

        else {
            struct mg_http_serve_opts opts = {0};
            opts.root_dir = s_root_dir;
            opts.ssi_pattern = s_ssi_pattern;
            mg_http_serve_dir(c, hm, &opts);
        }

        MG_INFO(("%.*s %.*s %lu -> %.*s %lu", hm->method.len, hm->method.ptr,
             hm->uri.len, hm->uri.ptr, hm->body.len, 3, c->send.buf + 9,
             c->send.len));
    }
}

// Usage function
static void usage(const char *prog) {
    fprintf(stderr,
            "Mongoose v.%s\n"
            "Usage: %s OPTIONS\n"
            "  -H yes|no - enable traffic hexdump, default: '%s'\n"
            "  -S PAT    - SSI filename pattern, default: '%s'\n"
            "  -d DIR    - directory to serve, default: '%s'\n"
            "  -l ADDR   - listening address, default: '%s'\n"
            "  -u DIR    - file upload directory, default: unset\n"
            "  -v LEVEL  - debug level, from 0 to 4, default: %d\n",
            MG_VERSION, prog, s_enable_hexdump, s_ssi_pattern, s_root_dir,
            s_listening_address, s_debug_level);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    char path[MG_PATH_MAX] = ".";
    struct mg_mgr mgr;
    struct mg_connection *c;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            s_root_dir = argv[++i];
        } else if (strcmp(argv[i], "-H") == 0) {
            s_enable_hexdump = argv[++i];
        } else if (strcmp(argv[i], "-S") == 0) {
            s_ssi_pattern = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0) {
            s_listening_address = argv[++i];
        } else if (strcmp(argv[i], "-u") == 0) {
            s_upload_dir = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            s_debug_level = atoi(argv[++i]);
        } else {
            usage(argv[0]);
        }
    }

    if (strchr(s_root_dir, ',') == NULL) {
        realpath(s_root_dir, path);
        s_root_dir = path;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    mg_log_set(s_debug_level);
    mg_mgr_init(&mgr);
    if ((c = mg_http_listen(&mgr, s_listening_address, cb, &mgr)) == NULL) {
        MG_ERROR(("Cannot listen on %s. Use http://ADDR:PORT or :PORT", s_listening_address));
        exit(EXIT_FAILURE);
    }
    if (mg_casecmp(s_enable_hexdump, "yes") == 0) c->is_hexdumping = 1;

    MG_INFO(("Mongoose version : v%s", MG_VERSION));
    MG_INFO(("Listening on     : %s", s_listening_address));
    MG_INFO(("Web root         : [%s]", s_root_dir));
    MG_INFO(("Upload dir       : [%s]", s_upload_dir ? s_upload_dir : "unset"));
    read_login_html("login.html");
    while (s_signo == 0) mg_mgr_poll(&mgr, 1000);
    mg_mgr_free(&mgr);
    MG_INFO(("Exiting on signal %d", s_signo));
    return 0;
}
