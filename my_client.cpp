// ISA 2021 Projekt - Reverse-engineering neznámeho protokolu 
// Autor: Vojtech Fiala

#include <iostream>
#include <tuple>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <regex>
#include <vector>
#include <fstream>
#include <sstream>
#include "base64.h"

void print_help() {
    printf("usage: client [ <option> ... ] <command> [<args>] ...\n\n");
    printf("<option> is one of\n\n");
    printf("    -a <addr>, --address <addr>\n        Server hostname or address to connect to\n");
    printf("    -p <port>, --port <port>\n        Server port to connect to\n");
    printf("    --help, -h\n        Show this help\n");
    printf("    --\n");
    printf("        Do not treat any remaining argument as a switch (at this level)\n\n");
    printf("Multiple single-letter switches can be combined after\n");
    printf("one `-`. For example, `-h-` is the same as `-h --`.\n");
    printf("Supported commands:\n");
    printf("    register <username> <password>\n");
    printf("    login <username> <password>\n");
    printf("    list\n    send <recipient> <subject> <body>\n    fetch <id>\n    logout\n");
}

struct Send_cmds {
    char* recipient;
    char* subject;
    char* body;
};

Send_cmds Send_cmd(int index, char **args) {
    return Send_cmds{args[index+1], args[index+2], args[index+3]};
}

std::tuple<char*, char*> get_user_data(int index, char **args) {
    return std::make_tuple(args[index+1], args[index+2]);
}

struct Parsed_args {
    char *user_name, *user_password, *recipient, *subject, *body, *id;
    bool reg, list, send, fetch, logout, login;
    char *addr, *port;
};

Parsed_args parse_args(int argc, char *argv[]) {
    char *user_name, *user_password, *recipient, *subject, *body, *id;
    user_name = user_password = recipient = subject = body = id = nullptr;
    bool reg, list, send, fetch, logout, login;
    reg = list = send = fetch = logout = login = false;
    char *addr, *port;
    addr = port = nullptr;

    if (argc == 1) {
        printf("client: expects <command> [<args>] ... on the command line, given 0 arguments\n");
        exit(1);
    }


    for (int i = 1; i < argc; i++) {

        if (!strcmp(argv[i], "register")) {
            if (i+2 > argc-1 || i+2 < argc-1) {
                printf("register <username> <password>\n");
                exit(1);
            }
            else {
                std::tie(user_name, user_password) = get_user_data(i, argv);
                reg = true;
                break;
            }
        }

        else if (!strcmp(argv[i], "login")) {
            if (i+2 > argc-1 || i+2 < argc-1) {
                printf("login <username> <password>\n");
                exit(1);
            }
            else {
                std::tie(user_name, user_password) = get_user_data(i, argv);
                login = true;
                break;
            }
        }
        else if (!strcmp(argv[i], "list")) {
            if (i < argc-1) {
                printf("list\n");
                exit(1);
            }
            list = true;
            break;
        }
        
        else if (!strcmp(argv[i], "send")) {
            if (i+3 > argc-1) {
                printf("send <recipient> <subject> <body>\n");
                exit(1);
            }
            else {
                Send_cmds ret = Send_cmd(i, argv);
                recipient = ret.recipient;
                subject = ret.subject;
                body = ret.body;
                send = true;
                break;
            }
        }

        else if (!strcmp(argv[i], "fetch")) {
            if (i+1 > argc-1) {
                printf("fetch <id>\n");
                exit(1);
            }
            else {
                id = argv[i+1];
                fetch = true;
                break;
            }
        }

        else if (!strcmp(argv[i], "logout")) {
            if (i < argc-1) {
                printf("logout\n");
                exit(1);
            }
            else {
                logout = true;
                break;
            }
        }

        else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--addr")) {
            if (i+1 > argc-1) {
                printf("client: expects <command> [<args>] ... on the command line, given 0 arguments\n");
                exit(1);
            }
            else {
                addr = argv[i+1];
                i++;
            }
        }
        
        else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            if (i+1 > argc-1) {
                printf("client: expects <command> [<args>] ... on the command line, given 0 arguments\n");
                exit(1);
            }
            else {
                port = argv[i+1];
                i++;
            }
        }

        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_help();
            exit(1);
        }

        else {
            printf("unknown command\n");
            exit(1);
        }
    }

    if (!reg && !list && !send && !fetch && !logout && !login) {
        printf("client: expects <command> [<args>] ... on the command line, given 0 arguments\n");
        exit(1);
    }

    // Nechat co mam jak je, pridat if jesatli zacina '-' a potom zparsovat (do toho ifu dat moje p, a, h)
    return Parsed_args{user_name, user_password, recipient, subject, body, id,
                       reg, list, send, fetch, logout, login, addr, port};
}

// https://stackoverflow.com/questions/2602013/read-whole-ascii-file-into-c-stdstring
std::string read_user_token() {

    std::ifstream f("login-token");
    if (!f.is_open()) {
        printf("Not logged in\n");
        exit(1);
    }
    std::stringstream token;
    token << f.rdbuf();
    f.close();

    return token.str();
}

std::string create_login_register_message(Parsed_args args, std::string msg) {

    if (args.login) {
        msg += "login \"";
    }
    else if (args.reg) {
        msg += "register \"";
    }
    std::vector<unsigned char> password(args.user_password, args.user_password + strlen(args.user_password));
    std::string encoded_password = base64_encode(&password[0], password.size());
    msg = msg + args.user_name + "\" \"" +  encoded_password + "\"";
    return msg;
}

std::string create_send_message(Parsed_args args, std::string msg) {
    std::string user_token = read_user_token();
    msg = msg + "send " + user_token + " \"" + args.recipient + "\" \"" + args.subject + "\" \"" + args.body + "\"";
    return msg;
}

std::string create_fetch_message(Parsed_args args, std::string msg) {
    std::string user_token = read_user_token();
    msg = msg +  "fetch " + user_token + " " + args.id;
    return msg;
}

std::string create_list_message(std::string msg) {
    std::string user_token = read_user_token();
    msg = msg + "list " + user_token;
    return msg;
}

std::string create_logout_message(std::string msg) {
    std::string user_token = read_user_token();
    msg = msg + "logout " + user_token;
    return msg;
}

std::string create_tcp_body(Parsed_args args) {
    std::string msg;
    msg += '(';

    // Tvorba tela TCP paketu, ktery budu posilat
    if (args.list) {
        msg = create_list_message(msg);
    }

    else if (args.login || args.reg) {
        msg = create_login_register_message(args, msg);
    }

    else if (args.send) {
        msg = create_send_message(args, msg);
    }

    else if (args.fetch) {
        msg = create_fetch_message(args, msg);
    }

    else if (args.logout) {
        msg = create_logout_message(msg);
    }

    msg += ')';

    return msg;
}

std::string get_nth_part_of_response(std::string response, int part) {
    int counter = 0;
    int begin;
    int end;
    if (part > 1)
        part += part-1;
    begin = end = -1;
    for (unsigned int i = 0; i < response.length(); i++) {
        if (response[i] == 34) {
            counter++;
            if (begin != -1) {
                end = i;
                break;
            }
            if (counter == part) {
                begin = i;
            }
        }
    }
    std::string result = response.substr(begin+1, (end-begin-1));
    return result;
}

void print_list_messages(std::string buffer_string) {
    
}

void print_response(Parsed_args args, char* buffer) {
    std::regex error_reg("^\\(err");
    std::regex ok_reg("^\\(ok+");
    std::smatch result_match;
    std::string buffer_string(buffer);

    //char* sub = strstr(buffer, "(ok");

    if (std::regex_search(buffer_string, result_match, ok_reg)) {
        /* 
         * login: User logged in
         * register: registered user <user>
         * list: Not logged in
         * send: message sent
         * fetch: Not logged in, message id not found
         * logout: logged out
        */

        // User logged in + vytvori login-token
        if (args.login) {
            std::string body = get_nth_part_of_response(buffer_string, 1);
            printf("SUCCESS: %s\n", body.c_str());
            std::string token = get_nth_part_of_response(buffer_string, 2);
            std::ofstream login_token("login-token");
            login_token << "\"" << token << "\"";
            login_token.close();
        }
        // registered user <user>
        else if (args.reg) {
            std::string body = get_nth_part_of_response(buffer_string, 1);
            printf("SUCCESS: %s\n", body.c_str());
        }
        else if (args.list) { // SUCCESS: zpravy
            printf("SUCCESS:\n");
            print_list_messages(buffer_string);

        }   // message sent
        else if (args.send) {
            std::string body = get_nth_part_of_response(buffer_string, 1);
            printf("SUCCESS: %s\n", body.c_str());
        }
        else if (args.fetch) {

        }   // logged out + smaze login-token
        else if (args.logout) {
            if (remove( "login-token" ) != 0) {
                printf("Internal client error when logging out!\n");
                exit(1);
            }
            std::string body = get_nth_part_of_response(buffer_string, 1);
            printf("SUCCESS: %s\n", body.c_str());
        }   

    }
    else if (std::regex_search(buffer_string, result_match, error_reg)) {
        /* Vypada to, ze vsechno jsou 1 radkove errory a nemusim rozlisovat, odkud prisli
         * login: incorrect password, unknown user
         * register: user already registered
         * list: Not logged in
         * send: Not logged in, unknown recipient
         * fetch: Not logged in, message id not found
         * logout: Not logged in
        */

        std::string body = get_nth_part_of_response(buffer_string, 1);
        printf("ERROR: %s\n", body.c_str());
    }
    
    else {
        printf("Unknown error\n");
        exit(1);
    }
}

// https://www.geeksforgeeks.org/socket-programming-cc/
void send_and_receive(Parsed_args args) {


    struct sockaddr_in serv_addr;
    char buffer[2048];

    std::string msg = create_tcp_body(args);

    //printf("%ld %s\n", strlen(msg), msg);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Couldnt open a connection\n");
        exit(1);
    }

    // Nastav protokol a port
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(args.port));


    // IP muze byt i hostname, takze prelozit
    int res = inet_pton(AF_INET, args.addr, &serv_addr.sin_addr);
    if (res <= 0) {
        // Prvni pokus byl error, tzn. IPv4 to neni, zkusime hostname
        auto he = gethostbyname (args.addr);
        // Kdyz to neni ani hostname, tak nic
        if (he == NULL) {
            printf("tcp-connect: host not found\n");
            exit(1);
        }
        else {
            // Ziskanou adresu je potreba zkonvertovat z bytu na char*
            int res = inet_pton(AF_INET, inet_ntoa(*(struct in_addr*)he->h_addr), &serv_addr.sin_addr);
            if (res <= 0) {
                // Tohle by teoreticky nemelo nastat
                printf("Couldnt open a connection\n");
                exit(1);
            }
        }
    }

    int connection = connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (connection == -1) {
        printf("Couldnt open a connection\n");
        exit(1);
    }

    send(sock, msg.c_str(), msg.length(), 0);

    int valread = read(sock, buffer, 2048);
    if (valread == -1) {
        printf("Unknown error\n");
        exit(1);
    }


    print_response(args, buffer);
}

bool is_number(std::string string) {
    size_t limit = string.length();
    for (size_t i = 0; i < limit; i++) {
        if (!(isdigit(string[i])))
            return false;
    }
    return true;
}

void check_args(Parsed_args args) {
    if (!(is_number(args.port))) {
        printf("Port number is not a string\n");
        exit(1);
    }
    return;
}

int main(int argc, char **argv) {

    Parsed_args args = parse_args(argc, argv);
    check_args(args);
    send_and_receive(args);
    return 0;
}
