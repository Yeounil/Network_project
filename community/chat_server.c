// chat_server_2_refactor.c
// 개선: WebSocket 처리 분리 + epoll 기반 + TCP/WebSocket 통합

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <crypt.h>

#include "cJSON.h"

#define MAX_EVENTS   64
#define BUF_SIZE     2048

// 클라이언트 연결 구조체
typedef struct Client {
    int sock;
    bool is_websocket;
    bool handshake_done;
    char buffer[BUF_SIZE];
    char username[64];
    char nickname[64];
    size_t buf_len;
    struct Client *next;
    MYSQL *db;
    
    unsigned long user_id;
    unsigned long room_id;
} Client;

static Client *client_list = NULL;

// 유틸리티: 논블로킹 설정
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static MYSQL *db_conn;
//mysql database 연결
void db_connect() {
    db_conn = mysql_init(NULL);
    if (!db_conn) {
        fprintf(stderr, "mysql_init() failed\n");
        exit(1);
    }
    if (!mysql_real_connect(db_conn,
            "localhost",      // 호스트
            "chatbot",        // 사용자
            "Str0ng_P@ssw0rd!",  // 비밀번호
            "chat_app",       // 데이터베이스
            0, NULL, 0)) {
        fprintf(stderr, "mysql_real_connect(): %s\n", mysql_error(db_conn));
        exit(1);
    }
    // UTF-8 설정
    mysql_set_character_set(db_conn, "utf8mb4");
}
//클라이언트 접속 시 최근 메세지 히스토리 보내기
void send_history(Client *c, unsigned long room_id) {
    // 최근 50개 메시지 조회
    char query[256];
    snprintf(query, sizeof(query),
        "SELECT u.nickname, m.content, m.created_at "
        "FROM Messages m JOIN Users u ON m.sender_id=u.id "
        "WHERE m.room_id=%lu AND m.is_deleted=0 "
        "ORDER BY m.created_at DESC LIMIT 50",
        room_id);
    if (mysql_query(db_conn, query)) {
        fprintf(stderr, "History query failed: %s\n", mysql_error(db_conn));
        return;
    }
    MYSQL_RES *res = mysql_store_result(db_conn);
    MYSQL_ROW row;
    // 역순으로 보내려면 배열에 담았다가 뒤집어 보내도 좋음
    while ((row = mysql_fetch_row(res))) {
        // JSON 패킷 만들기
        char packet[1024];
        snprintf(packet, sizeof(packet),
            "{\"type\":\"msg\",\"nick\":\"%s\",\"text\":\"%s\",\"time\":\"%s\"}",
            row[0], row[1], row[2]);
        send_ws_message(c->sock, packet);
    }
    mysql_free_result(res);
}

bool verify_password(const char *plain, const char *hash) {
    // crypt() 내부적으로 hash 안의 salt($id$rounds$salt) 부분을 인식해 동일한 방식으로 해싱합니다.
    errno = 0;
    char *calculated = crypt(plain, hash);
    if (!calculated) {
        perror("crypt");
        return false;
    }
    return strcmp(calculated, hash) == 0;
}

void handle_login(Client *c, cJSON *json) {
    // 1) 요청 파싱
    cJSON *juser = cJSON_GetObjectItem(json, "username");
    cJSON *jpass = cJSON_GetObjectItem(json, "password");
    if (!cJSON_IsString(juser) || !cJSON_IsString(jpass)) {
        send_ws_message(c->sock,
            "{\"type\":\"login_result\",\"success\":false,\"error\":\"invalid input\"}");
        return;
    }
    const char *plain = jpass->valuestring;

    // 2) 사용자명 이스케이프
    char user_esc[128];
    mysql_real_escape_string(c->db, user_esc, juser->valuestring, strlen(juser->valuestring));

    // 3) DB에서 저장된 해시 가져오기
    char query[256];
    snprintf(query, sizeof(query),
        "SELECT id, password_hash, nickname FROM Users WHERE username='%s'",
        user_esc);
    if (mysql_query(c->db, query) != 0) {
        send_ws_message(c->sock,
            "{\"type\":\"login_result\",\"success\":false,\"error\":\"db error\"}");
        return;
    }
    MYSQL_RES *res = mysql_store_result(c->db);
    if (!res) {
        send_ws_message(c->sock,
            "{\"type\":\"login_result\",\"success\":false,\"error\":\"db error\"}");
        return;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) {
        mysql_free_result(res);
        send_ws_message(c->sock,
            "{\"type\":\"login_result\",\"success\":false,\"error\":\"user not found\"}");
        return;
    }
    unsigned long user_id = strtoul(row[0], NULL, 10);
    const char *stored = row[1];
    const char *stored_nick = row[2];
    size_t stored_len = strlen(stored);
    mysql_free_result(res);

    // 4) 입력 비밀번호 해시 생성
    char input_hash[65] = {0};
    memset(input_hash, 0, sizeof(input_hash));
    if (stored_len == 32) {
        // 기존 MD5
        unsigned char md5sum[MD5_DIGEST_LENGTH];
        MD5((unsigned char*)plain, strlen(plain), md5sum);
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            sprintf(input_hash + i*2, "%02x", md5sum[i]);
        }
    }
    else if (stored_len == 64) {
        // 새 SHA-256
        unsigned char sha256sum[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)plain, strlen(plain), sha256sum);
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(input_hash + i*2, "%02x", sha256sum[i]);
        }
    }
    else {
        send_ws_message(c->sock,
            "{\"type\":\"login_result\",\"success\":false,\"error\":\"invalid hash format\"}");
        return;
    }

    // 5) 해시 비교
    if (strcmp(input_hash, stored) != 0) {
        send_ws_message(c->sock,
            "{\"type\":\"login_result\",\"success\":false,\"error\":\"wrong password\"}");
        return;
    }

    // 6) MD5 사용자 자동 SHA-256 마이그레이드 (선택)
    if (stored_len == 32) {
        unsigned char new_sha[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)plain, strlen(plain), new_sha);
        char new_hex[65] = {0};
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(new_hex + i*2, "%02x", new_sha[i]);
        }
        char upd[256];
        snprintf(upd, sizeof(upd),
            "UPDATE Users SET password_hash='%s' WHERE id=%lu",
            new_hex, user_id);
        mysql_query(c->db, upd);
    }

    // 7) 로그인 성공 응답 및 세션 설정
    c->user_id = user_id;  // 세션에 로그인 정보 저장
    strncpy(c->nickname, stored_nick, sizeof(c->nickname)-1);
    send_ws_message(c->sock,
        "{\"type\":\"login_result\",\"success\":true}");
}

void handle_signup(Client *c, cJSON *json) {
    printf("[DEBUG] handle_signup() called\n");
    cJSON *juser = cJSON_GetObjectItem(json, "username");
    cJSON *jpass = cJSON_GetObjectItem(json, "password");
    cJSON *jmail = cJSON_GetObjectItem(json, "email");
    
    // 유효성 검사
    if (!cJSON_IsString(juser) || !cJSON_IsString(jpass) || !cJSON_IsString(jmail) ||
        strlen(juser->valuestring) < 3 || strlen(jpass->valuestring) < 6) {
        send_ws_message(c->sock,
            "{\"type\":\"signup_result\",\"success\":false,\"error\":\"invalid input\"}");
        return;
    }

    // 1) 비밀번호 SHA-256 해시 계산
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)jpass->valuestring,
           strlen(jpass->valuestring), hash);
    // 16진수 문자열로 변환
    char hexhash[SHA256_DIGEST_LENGTH*2 + 1] = {0};
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hexhash + i*2, "%02x", hash[i]);

    // 2) DB에 INSERT
    MYSQL *db = c->db;
    char user_esc[128], mail_esc[128], hash_esc[128];
    mysql_real_escape_string(db, user_esc, juser->valuestring, strlen(juser->valuestring));
    mysql_real_escape_string(db, mail_esc, jmail->valuestring, strlen(jmail->valuestring));
    mysql_real_escape_string(db, hash_esc, hexhash, strlen(hexhash));

    char query[512];
    snprintf(query, sizeof(query),
        "INSERT INTO Users (username, password_hash, email, nickname, created_at) "
        "VALUES ('%s','%s','%s','%s',NOW())",
        user_esc, hash_esc, mail_esc, user_esc);

    if (mysql_query(db, query) != 0) {
        int code = mysql_errno(db);
        const char *err = code == 1062
            ? "username or email exists"
            : mysql_error(db);
        char buf[256];
        snprintf(buf, sizeof(buf),
            "{\"type\":\"signup_result\",\"success\":false,\"error\":\"%s\"}",
            err);
        send_ws_message(c->sock, buf);
        return;
    }

    // 3) 성공 응답
    send_ws_message(c->sock,
        "{\"type\":\"signup_result\",\"success\":true}");
}


void handle_user_info(Client *c, cJSON *json) {
    printf("[DEBUG] handle_user_info() called (user_id=%lu)\n", c->user_id);
    // 1) 로그인 확인
    if (c->user_id == 0) {
        send_ws_message(c->sock,
            "{\"type\":\"user_info\",\"error\":\"not logged in\"}");
        return;
    }

    // 2) DB에서 유저 정보 조회
    MYSQL *db = c->db;
    char query[256];
    snprintf(query, sizeof(query),
        "SELECT id, username, email, nickname, created_at "
        "FROM Users WHERE id = %lu",
        c->user_id);

    if (mysql_query(db, query) != 0) {
        char buf[512];
        snprintf(buf, sizeof(buf),
            "{\"type\":\"user_info\",\"error\":\"%s\"}",
            mysql_error(db));
        send_ws_message(c->sock, buf);
        return;
    }

    MYSQL_RES *res = mysql_store_result(db);
    if (!res) {
        send_ws_message(c->sock,
            "{\"type\":\"user_info\",\"error\":\"db error\"}");
        return;
    }

    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) {
        send_ws_message(c->sock,
            "{\"type\":\"user_info\",\"error\":\"user not found\"}");
        mysql_free_result(res);
        return;
    }

    // 3) JSON 포맷으로 응답
    //    row[0]=id, row[1]=username, row[2]=email, row[3]=nickname, row[4]=created_at
    char buf[1024];
    snprintf(buf, sizeof(buf),
        "{\"type\":\"user_info\",\"user\":{"
          "\"id\":%s,"
          "\"username\":\"%s\","
          "\"email\":\"%s\","
          "\"nickname\":\"%s\","
          "\"created_at\":\"%s\""
        "}}",
        row[0], row[1], row[2], row[3], row[4]
    );
    send_ws_message(c->sock, buf);
    mysql_free_result(res);
}

void handle_update_nickname(Client *c, cJSON *json) {
    // 1) 로그인 확인
    if (c->user_id == 0) {
        send_ws_message(c->sock,
            "{\"type\":\"update_nickname_result\",\"success\":false,\"error\":\"not logged in\"}");
        return;
    }
    // 2) 요청 JSON에서 nickname 추출
    cJSON *jnick = cJSON_GetObjectItem(json, "nickname");
    if (!cJSON_IsString(jnick) || strlen(jnick->valuestring) == 0) {
        send_ws_message(c->sock,
            "{\"type\":\"update_nickname_result\",\"success\":false,\"error\":\"invalid nickname\"}");
        return;
    }
    // 3) DB 업데이트
    //    (필요하면 mysql_real_escape_string으로 이스케이프)
    char safe_nick[128];
    mysql_real_escape_string(c->db, safe_nick, jnick->valuestring, strlen(jnick->valuestring));
    char query[256];
    snprintf(query, sizeof(query),
        "UPDATE Users SET nickname='%s' WHERE id=%lu",
        safe_nick, c->user_id);
    if (mysql_query(c->db, query) != 0) {
        char buf[512];
        snprintf(buf, sizeof(buf),
            "{\"type\":\"update_nickname_result\",\"success\":false,\"error\":\"%s\"}",
            mysql_error(c->db));
        send_ws_message(c->sock, buf);
        return;
    }
    // 4) 성공 응답
    send_ws_message(c->sock,
        "{\"type\":\"update_nickname_result\",\"success\":true}");
}

void handle_join(Client *c, cJSON *json) {
    unsigned long rid;
    cJSON *jrid = cJSON_GetObjectItem(json, "room_id");
    if (!jrid || jrid->type != cJSON_Number) {
        send_ws_message(c->sock,
            "{\"type\":\"join\",\"ok\":false,\"reason\":\"invalid room_id\"}");
        return;
    }
    rid = (unsigned long)jrid->valuedouble;

    // 1) 방 정보 조회: is_private 체크
    char q1[256];
    snprintf(q1, sizeof(q1),
        "SELECT is_private FROM Rooms WHERE id=%lu", rid);
    if (mysql_query(db_conn, q1) != 0) {
        send_ws_message(c->sock,
            "{\"type\":\"join\",\"ok\":false,\"reason\":\"db error\"}");
        return;
    }
    MYSQL_RES *r1 = mysql_store_result(db_conn);
    if (!r1) {
        send_ws_message(c->sock,
            "{\"type\":\"join\",\"ok\":false,\"reason\":\"db error\"}");
        return;
    }
    MYSQL_ROW row1 = mysql_fetch_row(r1);
    if (!row1) {
        mysql_free_result(r1);
        send_ws_message(c->sock,
            "{\"type\":\"join\",\"ok\":false,\"reason\":\"room not found\"}");
        return;
    }
    int is_private = atoi(row1[0]);
    mysql_free_result(r1);

    // 2) 멤버십 체크
    char q2[256];
    snprintf(q2, sizeof(q2),
        "SELECT COUNT(*) FROM Memberships WHERE user_id=%lu AND room_id=%lu",
        c->user_id, rid);
    if (mysql_query(db_conn, q2) != 0) {
        send_ws_message(c->sock,
            "{\"type\":\"join\",\"ok\":false,\"reason\":\"db error\"}");
        return;
    }
    MYSQL_RES *r2 = mysql_store_result(db_conn);
    if (!r2) {
        send_ws_message(c->sock,
            "{\"type\":\"join\",\"ok\":false,\"reason\":\"db error\"}");
        return;
    }
    MYSQL_ROW row2 = mysql_fetch_row(r2);
    int is_member = row2 ? atoi(row2[0]) : 0;
    mysql_free_result(r2);

    // 3) 공개 방이면 자동 가입
    if (!is_private && !is_member) {
        char qi[256];
        snprintf(qi, sizeof(qi),
            "INSERT INTO Memberships (user_id, room_id) VALUES (%lu,%lu)",
            c->user_id, rid);
        if (mysql_query(db_conn, qi) == 0) {
            is_member = 1;
        }
    }

    // 4) 가입 실패 처리
    if (!is_member) {
        send_ws_message(c->sock,
            "{\"type\":\"join\",\"ok\":false,\"reason\":\"no membership\"}");
        return;
    }

    // 5) 가입 성공 ACK
    c->room_id = rid;
    char resp[64];
    int n = snprintf(resp, sizeof(resp),
        "{\"type\":\"join\",\"ok\":true,\"room_id\":%lu}", rid);
    send_ws_message(c->sock, resp);
    
    send_user_list(c);
    
    broadcast_user_joined(c);

    // 6) 히스토리 전송
    send_history(c, c->room_id);
}
//HTTP 연결 파일 서빙
void serve_static_file(int sock, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        const char *notfound =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 0\r\n\r\n";
        send(sock, notfound, strlen(notfound), 0);
        return;
    }

    // 파일 크기 계산
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Content-Type 결정
    const char *ctype = "application/octet-stream";
    if (strstr(path, ".html")) ctype = "text/html; charset=UTF-8";
    else if (strstr(path, ".css")) ctype = "text/css";
    else if (strstr(path, ".js"))  ctype = "application/javascript";

    // 헤더 작성 및 전송
    char header[512];
    int len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "\r\n",
        ctype, filesize);
    send(sock, header, len, 0);

    // 바디 전송
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        send(sock, buf, n, 0);
    }
    fclose(fp);
}

void save_and_broadcast(Client *sender, const char *raw) {
    // 1) JSON 파싱
    cJSON *json = cJSON_Parse(raw);
    if (!json) return;

    // 2) 메시지 타입이 “msg” 인 경우만 DB에 저장
    cJSON *type = cJSON_GetObjectItem(json, "type");
    // JSON 만들기
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "type",   "msg");
    cJSON_AddNumberToObject(msg, "from",   c->user_id);
    cJSON_AddStringToObject(msg, "nick", c->nickname);
    cJSON_AddStringToObject(msg, "text",   text);
    char *s = cJSON_PrintUnformatted(msg);
    
    if (type && strcmp(type->valuestring, "msg") == 0) {
        cJSON *text = cJSON_GetObjectItem(json, "text");
        if (text && sender->user_id && sender->room_id) {
            // 3) SQL 인젝션 방지: text 이스케이프
            size_t len = strlen(text->valuestring);
            char *escaped = malloc(len*2 + 1);
            mysql_real_escape_string(db_conn, escaped,
                                     text->valuestring, len);

            // 4) INSERT 쿼리 실행
            char q[1024];
            snprintf(q, sizeof(q),
                "INSERT INTO Messages (room_id, sender_id, content) "
                "VALUES (%lu, %lu, '%s')",
                sender->room_id, sender->user_id, escaped);
            if (mysql_query(db_conn, q)) {
                fprintf(stderr, "DB insert error: %s\n",
                        mysql_error(db_conn));
            }
            free(escaped);
        }
        
        for (Client *c = client_list; c; c = c->next) {
          if (c == sender) continue;            // <— 여기
          if (c->room_id == sender->room_id)
            send_ws_message(c->sock, raw);
          else
            send_all(c->sock, raw, strlen(raw));
        }
        
        //broadcast(raw);
    }

    cJSON_Delete(json);

    // 5) 원본 raw JSON 문자열을 그대로 브로드캐스트
    //broadcast(raw);
}

int recv_all(int sock, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(sock, (char*)buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

int send_all(int sock, const void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(sock, (char*)buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

// 클라이언트 목록 관리
void add_client_to_list(Client *c) {
    c->next = client_list;
    client_list = c;
}

void remove_client_from_list(Client *c) {
    Client **p = &client_list;
    while (*p && *p != c) p = &(*p)->next;
    if (*p) *p = c->next;
}

// WebSocket 핸드셰이크 키 생성
void make_ws_accept_key(const char *client_key, char *out_base64) {
    unsigned char sha[SHA_DIGEST_LENGTH];
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);
    SHA1((unsigned char*)tmp, strlen(tmp), sha);
    EVP_EncodeBlock((unsigned char*)out_base64, sha, SHA_DIGEST_LENGTH);
}

// HTTP -> WebSocket 핸드셰이크
void do_ws_handshake(Client *c) {
    char *hdr = strstr(c->buffer, "Sec-WebSocket-Key:");
    if (!hdr) return;
    char client_key[64]; sscanf(hdr, "Sec-WebSocket-Key: %63s", client_key);
    char accept_key[128]; make_ws_accept_key(client_key, accept_key);

    char response[512];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        accept_key);
    send_all(c->sock, response, len);

    c->handshake_done = true;
    c->is_websocket = true;
    c->buf_len = 0;
}

// WebSocket 프레임 수신
int recv_ws_frame(int sock, char *out, size_t maxlen) {
    uint8_t hdr[2]; if (recv_all(sock, hdr, 2) != 2) return -1;
    bool masked = hdr[1] & 0x80;
    uint64_t len = hdr[1] & 0x7F;
    if (len == 126) { uint16_t ext; recv_all(sock, &ext, 2); len = ntohs(ext); }
    else if (len == 127) { uint64_t ext; recv_all(sock, &ext, 8); len = be64toh(ext); }
    uint8_t mask[4] = {0}; if (masked) recv_all(sock, mask, 4);
    if (len > maxlen - 1) return -1;
    recv_all(sock, out, len);
    for (uint64_t i = 0; i < len; i++) out[i] ^= mask[i % 4];
    out[len] = '\0'; return len;
}

// WebSocket 텍스트 전송
void send_ws_message(int sock, const char *msg) {
    size_t len = strlen(msg);
    uint8_t hdr[10]; int idx = 0;
    hdr[idx++] = 0x81;
    if (len <= 125) hdr[idx++] = (uint8_t)len;
    else if (len <= 0xFFFF) { hdr[idx++] = 126; *(uint16_t*)(hdr+idx) = htons(len); idx += 2; }
    else { hdr[idx++] = 127; *(uint64_t*)(hdr+idx) = htobe64(len); idx += 8; }
    send_all(sock, hdr, idx);
    send_all(sock, msg, len);
}

// 메시지 브로드캐스트 (JSON 형식 그대로 전송)
void broadcast(const char *msg) {
    for (Client *p = client_list; p; p = p->next) {
        if (p->is_websocket && p->handshake_done) send_ws_message(p->sock, msg);
        else send_all(p->sock, msg, strlen(msg));
    }
}

void send_user_list(Client *to) {
    cJSON *arr = cJSON_CreateArray();
    int room = to->room_id;
    for (Client *p = client_list; p; p = p->next) {
        if (p->user_id > 0 && p->room_id == room) {
            cJSON *u = cJSON_CreateObject();
            cJSON_AddNumberToObject(u, "id",       p->user_id);
            cJSON_AddStringToObject(u, "username", p->username);
            cJSON_AddStringToObject(u, "nickname", p->nickname);
            cJSON_AddItemToArray(arr, u);
        }
    }
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "type",  "user_list");
    cJSON_AddItemToObject   (msg, "users", arr);
    char *s = cJSON_PrintUnformatted(msg);
    send_ws_message(to->sock, s);
    free(s);
    cJSON_Delete(msg);
}

// 2) 새로 로그인한 유저를 제외한 모두에게 “user_joined” 알림
void broadcast_user_joined(Client *newc) {
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "type",     "user_joined");
    cJSON_AddNumberToObject(msg, "id",       newc->user_id);
    cJSON_AddStringToObject(msg, "username", newc->username);
    cJSON_AddStringToObject(msg, "nickname", newc->nickname);
    char *s = cJSON_PrintUnformatted(msg);

    for (Client *p = client_list; p; p = p->next) {
        if (p != newc && p->user_id > 0 && p->room_id == newc->room_id) {
            send_ws_message(p->sock, s);
        }
    }

    free(s);
    cJSON_Delete(msg);
}
// 채널 생성 처리 함수
void handle_create_channel(int ws, Client *client, cJSON *root) {
    cJSON *jname = cJSON_GetObjectItem(root, "name");
    cJSON *jtype = cJSON_GetObjectItem(root, "channel_type");
    cJSON *jmax = cJSON_GetObjectItem(root, "max_members");
    cJSON *jtoken = cJSON_GetObjectItem(root, "invite_token");
    if (!cJSON_IsString(jname) || !cJSON_IsString(jtype)
        || !cJSON_IsNumber(jmax) || !cJSON_IsString(jtoken)) {
        const char *resp = "{\"type\":\"create_channel\",\"ok\":false,\"reason\":\"Invalid parameters\"}";
        send_ws_message(ws, resp);
        return;
    }
    const char *name = jname->valuestring;
    int is_private = (strcmp(jtype->valuestring, "private") == 0) ? 1 : 0;
    int max_members = jmax->valueint;
    const char *invite_token = jtoken->valuestring;
    
    // SQL 인젝션 방어
    char esc_name[256];
    mysql_real_escape_string(client->db, esc_name, name, strlen(name));

    char query[512];
    snprintf(query, sizeof(query),
             "INSERT INTO Rooms (name, is_private, created_by) VALUES ('%s', %d, %lu)",
             esc_name, is_private, client->user_id);

    if (mysql_query(client->db, query)) {
        char buf[512];
        snprintf(buf, sizeof(buf),
                 "{\"type\":\"create_channel\",\"ok\":false,\"reason\":\"%s\"}",
                 mysql_error(client->db));
        send_ws_message(ws, buf);
    } else {
        unsigned long room_id = mysql_insert_id(client->db);
        char buf[512];
        snprintf(buf, sizeof(buf),
                 "{\"type\":\"create_channel\",\"ok\":true,"
                 "\"id\":%lu,\"name\":\"%s\",\"invite_token\":\"%s\"}",
                 room_id, esc_name, invite_token);
        send_ws_message(ws, buf);
    }
}

// 방 목록 조회 및 전송
void handle_list_rooms(Client *c) {
    // 1) SQL 실행: id, name, invite_token 컬럼을 조회
    const char *query = "SELECT id, name, invite_token FROM Rooms";
    if (mysql_query(db_conn, query) != 0) {
        send_ws_message(c->sock,
            "{\"type\":\"list_channels\",\"channels\":[],\"error\":\"db error\"}");
        return;
    }
    MYSQL_RES *res = mysql_store_result(db_conn);
    if (!res) {
        send_ws_message(c->sock,
            "{\"type\":\"list_channels\",\"channels\":[],\"error\":\"db error\"}");
        return;
    }

    // 2) JSON 배열 생성
    cJSON *channels = cJSON_CreateArray();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res)) != NULL) {
        unsigned long *lengths = mysql_fetch_lengths(res);
        cJSON *ch = cJSON_CreateObject();
        // id
        unsigned long id = strtoul(row[0], NULL, 10);
        cJSON_AddNumberToObject(ch, "id", id);
        // name
        cJSON_AddStringToObject(ch, "name", row[1] ? row[1] : "");
        // invite_token
        cJSON_AddStringToObject(ch, "invite_token", row[2] ? row[2] : "");
        cJSON_AddItemToArray(channels, ch);
    }
    mysql_free_result(res);

    // 3) 루트 객체 생성
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "list_channels");
    cJSON_AddItemToObject(root, "channels", channels);

    // 4) 문자열화 및 전송
    char *text = cJSON_PrintUnformatted(root);
    if (text) {
        send_ws_message(c->sock, text);
        free(text);
    }
    cJSON_Delete(root);
}

void handle_client_event(int epfd, Client *c) {
    // 1) WebSocket 미연결 시: raw recv → 핸드셰이크 or HTTP 서빙
    if (!c->is_websocket) {
        ssize_t n = recv(c->sock, c->buffer + c->buf_len,
                         BUF_SIZE - c->buf_len, 0);
        if (n <= 0) {
            // 연결 종료
            epoll_ctl(epfd, EPOLL_CTL_DEL, c->sock, NULL);
            close(c->sock);
            remove_client_from_list(c);
            free(c);
            return;
        }
        c->buf_len += n;
        c->buffer[c->buf_len] = '\0';

        // Debug: 요청 헤더 찍어보기
        fprintf(stderr, "---- RAW REQUEST ----\n%s\n", c->buffer);

        // WebSocket 업그레이드 요청 감지
        bool is_ws_handshake =
               strcasestr(c->buffer, "Upgrade: websocket")
            && strcasestr(c->buffer, "Sec-WebSocket-Key");

        if (!c->handshake_done && is_ws_handshake) {
            // 2) 최초 한 번만 핸드셰이크
            do_ws_handshake(c);
            send_history(c, /* room */ 1);
            return;
        }

        // 3) 일반 HTTP GET 요청: index.html 서빙
        if (!c->handshake_done && strncmp(c->buffer, "GET ", 4) == 0) {
            // 요청 라인에서 경로만 추출 (예: "GET /js/app.js HTTP/1.1")
            char method[8], url[256];
            sscanf(c->buffer, "%s %s", method, url);

            // 루트 요청은 index.html 로 매핑
            if (strcmp(url, "/") == 0) {
                strcpy(url, "/index.html");
            }

            // 실제 파일 경로 구성
            char fullpath[512];
            snprintf(fullpath, sizeof(fullpath), "./public%s", url);

            // 정적 파일 전송
            serve_static_file(c->sock, fullpath);

            // 연결 정리
            epoll_ctl(epfd, EPOLL_CTL_DEL, c->sock, NULL);
            close(c->sock);
            remove_client_from_list(c);
            free(c);
            return;
        }
        /*
        // 4) 아직 WebSocket 세션이 열리지 않은 TCP 클라이언트 메시지
        if(!c->handshake_done){
          broadcast(c->buffer);
          c->buf_len = 0;
          return;
        }
        */
    }

    // 5) WebSocket 연결된 경우: 프레임 단위 메시지 처리
    if(c->handshake_done)
    {
        char msg[BUF_SIZE];
        int len = recv_ws_frame(c->sock, msg, sizeof(msg));
        if (len <= 0) {
            // 연결 종료
            epoll_ctl(epfd, EPOLL_CTL_DEL, c->sock, NULL);
            close(c->sock);
            remove_client_from_list(c);
            free(c);
            return;
        }

        // Debug: 들어온 WS 페이로드 찍어보기
        fprintf(stderr, "---- WS MESSAGE ----\n%s\n", msg);

        // JSON 파싱 및 타입별 처리
        cJSON *json = cJSON_Parse(msg);
        if (!json) return;
        cJSON *jtype = cJSON_GetObjectItem(json, "type");
        if (!jtype || !jtype->valuestring) { cJSON_Delete(json); return; }

        if (strcmp(jtype->valuestring, "login") == 0) {
            handle_login(c, json);
        }
        
        else if (strcmp(jtype->valuestring, "signup") == 0) {
          printf("[DEBUG] dispatch → handle_signup user_id=%lu\n", c->user_id);
          handle_signup(c, json);
          cJSON_Delete(json);
          return;
        }
        
        else if (strcmp(jtype->valuestring, "join") == 0) {
            handle_join(c, json);
        }
        // --- CREATE_CHANNEL 처리 분기 추가 ---
        else if (strcmp(jtype->valuestring, "create_channel") == 0) {
            handle_create_channel(c->sock, c, json);
        }
        // --- LIST_CHANNELS 처리 분기 추가 ---
        else if (strcmp(jtype->valuestring, "list_channels") == 0) {
            handle_list_rooms(c);
        }
        // --- USER_INFO 처리 분기 추가 ---
        else if (strcmp(jtype->valuestring, "get_user_info") == 0) {
            printf("[DEBUG] dispatch → handle_user_info user_id=%lu\n", c->user_id);
            handle_user_info(c, json);
        }
        // --- UPDATE_NICKNAME 처리 분기 추가 ---
        else if (strcmp(jtype->valuestring, "update_nickname") == 0) {
            handle_update_nickname(c, json);
        }
        // --- 기존 메시지 분기들 (login, join, msg 등) 이어서 처리 --- 
        else if (strcmp(jtype->valuestring, "msg") == 0) {
            // 로그인·룸 참가 확인 후 처리
            if (c->user_id == 0 || c->room_id == 0) {
                send_ws_message(c->sock,
                  "{\"type\":\"error\",\"reason\":\"not in room\"}");
            } else {
                save_and_broadcast(c, msg);
            }
        }
        return;
        cJSON_Delete(json);
    }
}


int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 8080;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    db_connect();

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listen_fd, SOMAXCONN);
    set_nonblocking(listen_fd);

    int epfd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);

    printf("Server listening on port %d\n", port);

    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == listen_fd) {
                // 신규 연결
                while (1) {
                    int sock = accept(listen_fd, NULL, NULL);
                    if (sock < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        perror("accept"); break;
                    }
                    set_nonblocking(sock);
                    Client *c = calloc(1, sizeof(Client));
                    c->sock = sock;
                    add_client_to_list(c);
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.ptr = c;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
                    c->db = db_conn;
                }
            } else {
                Client *c = (Client *)events[i].data.ptr;
                handle_client_event(epfd, c);
            }
        }
    }
    close(listen_fd);
    return 0;
}

