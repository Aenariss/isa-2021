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

#define print(x) (std::cout << x << '\n');  // debug makro

/* Funkce na vypsani napovedy podle referencniho klienta */
void print_help() {
    std::cout << "usage: client [ <option> ... ] <command> [<args>] ...\n\n";
    std::cout << "<option> is one of\n\n";
    std::cout << "   -a <addr>, --address <addr>\n     Server hostname or address to connect to\n";
    std::cout << "   -p <port>, --port <port>\n     Server port to connect to\n";
    std::cout << "   --help, -h\n     Show this help\n";
    std::cout << "   --\n";
    std::cout << "    Do not treat any remaining argument as a switch (at this level)\n\n";
    std::cout << " Multiple single-letter switches can be combined after\n";
    std::cout << " one `-`. For example, `-h-` is the same as `-h --`.\n";
    std::cout << " Supported commands:\n";
    std::cout << "   register <username> <password>\n";
    std::cout << "   login <username> <password>\n";
    std::cout << "   list\n   send <recipient> <subject> <body>\n   fetch <id>\n   logout\n";
}

/* Funkce na zjisteni, jestli je zadany string cislo */
bool is_number(std::string string) {
    size_t limit = string.length();
    // Jestlize nejaka hodnota ve stringu neni cislo, tak se o cislo nejedna
    for (size_t i = 0; i < limit; i++) {
        if (!(isdigit(string[i])))
            return false;
    }
    return true;
}

/* Pomocna struktura pro ukladani dat zpravy typu "send" */
struct Send_cmds {
    char* recipient;
    char* subject;
    char* body;
};

/* Funkce pro naplneni pomocne struktury pro zpracovani prikazu "send" */
Send_cmds Send_cmd(int index, char **args) {
    return Send_cmds{args[index+1], args[index+2], args[index+3]};
}

/* Funkce pouzivana pro nacteni uzivatelskych dat (jmeno a heslo) */
std::tuple<char*, char*> get_user_data(int index, char **args) {
    return std::make_tuple(args[index+1], args[index+2]);
}

/* Pomocna struktura na zpracovavani argumentu - obsahuje vsechny mozne argumenty */
struct Parsed_args {
    char *user_name, *user_password, *recipient, *subject, *body, *id;
    bool reg, list, send, fetch, logout, login;
    char *addr, *port;
};

/* Funkce na vypis adresy a portu, pouzivana v pripade chyby -- ukonci program s chybou */
void print_error(Parsed_args args) {
    std::cout << "  hostname: " << args.addr << '\n';
    std::cout << "  port number: " << args.port << '\n';
    exit(1);
}

/* Funkce pro escapovani nekterych charakteru (viz referencni klient) */
std::string escape_characters(std::string message) {
    for (unsigned int i = 0; i < message.length(); i++) {
        // Jestlize je nejaky charakter "\", musim zkontrolovat chrakter hned za nim
        if (message[i] == 92) {
            // Za \ se musi nachazet i nejaky znak
            if ((i + 1) >= message.length()) {
                std::cerr << "error while escaping characters \n";
                exit(1);
            }
            else {
                if (message[i+1] == 'n') {
                    message = message.substr(0, i) + '\n' + message.substr(i+2, message.length()-i);
                }
                if (message[i+1] == 't') {
                    message = message.substr(0, i) + '\t' + message.substr(i+2, message.length()-i);
                }
            }
        }
    }
    return message;
}

/* Funkce pro zpracovani argumentu */
Parsed_args parse_args(int argc, char *argv[]) {
    char *user_name, *user_password, *recipient, *subject, *body, *id;
    user_name = user_password = recipient = subject = body = id = nullptr;
    bool reg, list, send, fetch, logout, login;
    reg = list = send = fetch = logout = login = false;
    std::string addr, port;

    if (argc == 1) {
        std::cerr << "client: expects <command> [<args>] ... on the command line, given 0 arguments\n";
        exit(1);
    }

    std::regex switch_reg("^-");
    std::regex check_reg("^--");
    std::smatch result_match;
    bool found = false;

    for (int i = 1; i < argc; i++) {

        std::string str(argv[i]);
        if (!std::regex_search(str, result_match, check_reg)) {
            if (std::regex_search(str, result_match, switch_reg)) {
                size_t length = strlen(argv[i]);
                for (size_t k = 1; k < length; k++) {

                    if (argv[i][k] == 'h') {
                        print_help();
                        exit(0);
                    }
                    else if (argv[i][k] == 'p') {
                        if (i+1 > argc-1) {
                            std::cerr << "client: the \"-p\" option needs 1 argument, but 0 provided\n";
                            exit(1);
                        }
                        else {
                            port = argv[i+1];
                            found = true;
                            // Port a jeho kontrola maji prednost pred vsim ostatnim, podle ref. reseni
                            if(!(is_number(port))) {
                                std::cerr << "Port number is not a string\n";
                                exit(1);
                            }
                        }
                    }
                    else if (argv[i][k] == 'a') {
                        if (i+1 > argc-1) {
                            std::cerr << "client: the \"-a\" option needs 1 argument, but 0 provided\n";
                            exit(1);
                        }
                        else {
                            addr = argv[i+1];
                            found = true;
                        }
                    }
                    else {
                        std::cerr << "client: unknown switch: -" << argv[i][k] << '\n';
                        exit(1); 
                    }
                }
            }
        }
        // Jestlize jsem nasel port nebo adresu uz pri multi-prepinaci, musim se posunout o 2
        // 1 za zpracovany multiprepinac, 1 za zpracovany argument
        if ((port.empty() || addr.empty()) && (found)) {
            i+=2;
        }
        
        // Jinak prirazuju defaultni hodnoty
        if (port.empty())
            port = "32323";
        if (addr.empty())
            addr = "localhost";


        if (!strcmp(argv[i], "register")) {
            if (i+2 > argc-1 || i+2 < argc-1 || port.empty() || addr.empty()) {
                std::cerr << "register <username> <password>\n";
                exit(1);
            }
            else {
                std::tie(user_name, user_password) = get_user_data(i, argv);
                reg = true;
                break;
            }
        }

        else if (!strcmp(argv[i], "login")) {
            if (i+2 > argc-1 || i+2 < argc-1 || port.empty() || addr.empty()) {
                std::cerr << "login <username> <password>\n";
                exit(1);
            }
            else {
                std::tie(user_name, user_password) = get_user_data(i, argv);
                login = true;
                break;
            }
        }
        else if (!strcmp(argv[i], "list")) {
            if (i < argc-1 || port.empty() || addr.empty()) {
                std::cerr << "list\n";
                exit(1);
            }
            list = true;
            break;
        }
        
        else if (!strcmp(argv[i], "send")) {
            if (i+3 > argc-1 || port.empty() || addr.empty()) {
                std::cerr << "send <recipient> <subject> <body>\n";
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
            if (i+1 > argc-1 || port.empty() || addr.empty()) {
                std::cerr << "fetch <id>\n";
                exit(1);
            }
            else {
                id = argv[i+1];
                fetch = true;
                break;
            }
        }

        else if (!strcmp(argv[i], "logout")) {
            if (i < argc-1 || port.empty() || addr.empty()) {
                std::cerr << "logout\n";
                exit(1);
            }
            else {
                logout = true;
                break;
            }
        }

        else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--address")) {
            if (i+1 > argc-1) {
                std::cerr << "client: the \"-a\" option needs 1 argument, but 0 provided\n";
                exit(1);
            }
            else {
                addr = argv[i+1];
                i++;
            }
        }
        
        else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            if (i+1 > argc-1) {
                std::cerr << "client: the \"-p\" option needs 1 argument, but 0 provided\n";
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
            std::cerr << "unknown command\n";
            std::cerr << argv[i] << '\n';
            exit(1);
        }
    }

    if (!reg && !list && !send && !fetch && !logout && !login) {
        std::cerr << "client: expects <command> [<args>] ... on the command line, given 0 arguments\n";
        exit(1);
    }

    // Vracim strukturu se vsema argumentama - kdyz je uzivatel nezadal, jsou prazdne (nullptr)
    return Parsed_args{user_name, user_password, recipient, subject, body, id,
                       reg, list, send, fetch, logout, login, (char*) addr.c_str(), (char*) port.c_str()};
}

// https://stackoverflow.com/questions/2602013/read-whole-ascii-file-into-c-stdstring
/* Funkce pro nacteni user tokenu ze souboru */
std::string read_user_token() {

    std::ifstream f("login-token");
    if (!f.is_open()) {
        std::cout << "Not logged in\n";
        exit(1);
    }
    std::stringstream token;
    token << f.rdbuf();
    f.close();

    return token.str();
}

/* Vytvoreni zpravy pro prikazy "login" a "register" */
std::string create_login_register_message(Parsed_args args, std::string msg) {

    if (args.login) {
        msg += "login \"";
    }
    else if (args.reg) {
        msg += "register \"";
    }

    // U prikazu login a register se pouziva base64 kodovani pro heslo 
    std::vector<unsigned char> password(args.user_password, args.user_password + strlen(args.user_password));
    std::string encoded_password = base64_encode(&password[0], password.size());
    msg = msg + args.user_name + "\" \"" +  encoded_password + "\"";
    return msg;
}

/* Vytvoreni zpravy pro prikaz "send" */
std::string create_send_message(Parsed_args args, std::string msg) {
    std::string user_token = read_user_token();
    msg = msg + "send " + user_token + " \"" + args.recipient + "\" \"" + args.subject + "\" \"" + args.body + "\"";
    return msg;
}

/* Vytvoreni zpravy pro prikaz "fetch" */
std::string create_fetch_message(Parsed_args args, std::string msg) {
    std::string user_token = read_user_token();
    msg = msg +  "fetch " + user_token + " " + args.id;
    return msg;
}

/* Vytvoreni zpravy pro prikaz "list" */
std::string create_list_message(std::string msg) {
    std::string user_token = read_user_token();
    msg = msg + "list " + user_token;
    return msg;
}

/* Vytvoreni zpravy pro prikaz "logout" */
std::string create_logout_message(std::string msg) {
    std::string user_token = read_user_token();
    msg = msg + "logout " + user_token;
    return msg;
}

/* Funkce pro vytvoreni tela TCP paketu, kterym je zprava,
 * ktera je na server poslana 
*/
std::string create_tcp_body(Parsed_args args) {
    std::string msg;
    // Zprava vzdy zacina zavorkou
    msg += '(';

    // Tvorba tela TCP paketu, ktery budu posilat
    // Podle zadanych argumentu rozlisuju, jaka zprava to bude
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

    // Zprava vzdy zavorkou i konci
    msg += ')';

    return msg;
}

/* Funkce pro ziskani N-te casti odpovedi (casti uvnitr uvozovek) */
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

/* Funkce pro vypsani odpovedi na prikaz "list" */
void print_list_messages(std::string buffer_string) {
    std::vector<std::string> list_of_strings;
    int first_bracket, second_bracket;
    first_bracket = second_bracket = -1;
    bool flag1, flag2;
    flag1 = flag2 = false;
    for(unsigned int i = 1; i < buffer_string.length()-1; i++) {

        if (buffer_string[i] == '(') {
            first_bracket = i;
            flag1 = true;
        }
        else if (buffer_string[i] == ')') {
            second_bracket = i;
            flag2 = true;
        }

        if (flag1 && flag2) {
            std::string message = buffer_string.substr(first_bracket+1, (second_bracket-first_bracket-1));
            list_of_strings.push_back(message);
            if (message == "") {
                return;
            }
            flag1 = flag2 = false;
        }
    }
    for (std::string message : list_of_strings) {
        std::cout << message[0] << ':' << '\n';
        std::cout << "  From: " <<  get_nth_part_of_response(message, 1) << '\n';
        std::cout << "  Subject: " << get_nth_part_of_response(message, 2) << '\n';
    }


}

/* Vypsani odpovedi na ostatni prikazy */
void print_response(Parsed_args args, char* buffer) {
    std::regex error_reg("^\\(err");
    std::regex ok_reg("^\\(ok+");
    std::smatch result_match;
    std::string buffer_string(buffer);


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
            std::cout << "SUCCESS: " << body << '\n';
            std::string token = get_nth_part_of_response(buffer_string, 2);
            std::ofstream login_token("login-token");
            login_token << "\"" << token << "\"";
            login_token.close();
        }   // registered user <user>
        else if (args.reg) {
            std::string body = get_nth_part_of_response(buffer_string, 1);
            std::cout << "SUCCESS: " << body << '\n';
        }   // SUCCESS: zpravy
        else if (args.list) {
            std::cout << "SUCCESS:\n";
            print_list_messages(buffer_string);

        }   // message sent
        else if (args.send) {
            std::string body = get_nth_part_of_response(buffer_string, 1);
            std::cout << "SUCCESS: " << body << '\n';
        }
        else if (args.fetch) {
            std::string sender = get_nth_part_of_response(buffer_string, 1);
            std::string subject = get_nth_part_of_response(buffer_string, 2);
            std::string body = get_nth_part_of_response(buffer_string, 3);

            subject = escape_characters(subject);
            body = escape_characters(body);

            std::cout << "SUCCESS:\n\n" << "From: " << sender << '\n';
            std::cout << "Subject: " << subject << "\n\n";
            std::cout << body;
        }   // logged out + smaze login-token
        else if (args.logout) {
            if (remove("login-token") != 0) {
                std::cout << "Internal client error when logging out!\n";
                exit(1);
            }
            std::string body = get_nth_part_of_response(buffer_string, 1);
            std::cout << "SUCCESS: " << body << '\n';
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
        std::cerr << "ERROR: " << body << '\n';
    }
    
    else {
        std::cerr << "Unknown internal server-side error (client received wrong packet)\n";
        exit(1);
    }
}

/* Funkce na kontrolu argumentu, ktera vlastne akorat zkontroluje, jestli je port cislo */
void check_args(Parsed_args args) {
    if (!(is_number(args.port))) {
        std::cerr << "Port number is not a string\n";
        exit(1);
    }
}

// https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
/*
 * Hlavni ridici funkce, ktera posila zpravy na server a zpracovava odpovedi
*/
void send_and_receive(Parsed_args args) {
    
    struct addrinfo hints;
    struct addrinfo *result, *tmp;
    int sock, s;
    char buffer[2048];

    hints.ai_family = AF_UNSPEC;     // Pro IPv4 i IPv6
    hints.ai_socktype = SOCK_STREAM; // SOCK_STREAM pro TCP
    hints.ai_flags = 0;              // Nastavuju v podstate jenom kvuli getaddrinfo
    hints.ai_protocol = 0;           // Protokol pro socktype

    // Konverze adresy (i pripadneho hostname) na neco, s cim muzu pracovat
    s = getaddrinfo(args.addr, args.port, &hints, &result);
    if (s != 0) {
        std::cerr << "Error with address resolution \n";
        exit(1);
    }

    /* getaddrinfo vraci seznam adresovych struktur, takze musim zjistit,
     * na jakou z nich se mi povede pripojit 
    */
    for (tmp = result; tmp != NULL; tmp = tmp->ai_next) {
        sock = socket(tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
        // Kdyz byla tahle adresa neuspech (Nepovedlo se vytvorit socket), pokracuju dal
        if (sock == -1)
            continue;

        // Pokud se povedlo vytvorit socket a pripojit se na nej, muzu koncit prohledavani
        if (connect(sock, tmp->ai_addr, tmp->ai_addrlen) != -1)
            break;
    }

    // Pokud se na zadnou adresu pripojit nepovedlo, je neco spatne a musim skoncit
    if (tmp == NULL) {
        std::cerr << "tcp connection failed:" << '\n';
        print_error(args);
    }
    
    // Pokud jsem se dostal az sem, tak se vsechno povedlo a ja muzu poslat paket se zpravou
    check_args(args);
    std::string msg = create_tcp_body(args);
    send(sock, msg.c_str(), msg.length(), 0);

    std::string received_msg = "";
    int valread = -1;

    // Pokud by byla vysledna zprava moc velka, musim resit i to, ze ji prectu celou
    do {
        valread = read(sock, buffer, 2048);
        std::string tmp_buf (buffer);
        received_msg += tmp_buf;
        // Server uz nema co poslat, tak muzu skoncit
        if (valread == 0)
            break;
         // Jestlize se nepovedlo zpracovat odpoved, doslo k nejake chybe po ceste paketu
        else if (valread == -1) {
            std::cerr << "Unknown error during packet reading\n";
            exit(1);
        }
    } while (valread > 0);

    // Jestlize k chybe nedoslo, muzu uvolnit pamet, vypsat odpoved serveru a skoncit
    close(sock);
    freeaddrinfo(result);

    print_response(args, (char*) received_msg.c_str());
}

int main(int argc, char **argv) {
    Parsed_args args = parse_args(argc, argv);
    send_and_receive(args);
    return 0;
}
