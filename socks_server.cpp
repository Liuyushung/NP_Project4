#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <utility>
#include <strings.h>
#include <regex>
#include <boost/asio.hpp>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#define BUFFER_SIZE         65535
#define SOCKS_HEADER_SIZE    1+1+2+4

using boost::asio::ip::address;
using boost::asio::ip::tcp;
using boost::asio::io_service;
using namespace std;

typedef struct socks_info {
    uint8_t  version;
    uint8_t  command;
    uint16_t port;
    uint16_t bind_port;
    string   address;
    string   hostname;
    bool     need_resolve;
    bool     is_accept;
} SocksInfo;

const uint8_t COMMAND_CONNECT = 1;
const uint8_t COMMAND_BIND    = 2;
const uint8_t COMMAND_ACCEPT  = 90;
const uint8_t COMMAND_REJECT  = 91;

boost::asio::io_context io_context;
regex SOCKS_4A_PATTERN("0\\.0\\.0\\.([1-9]|[1-9]\\d|[1]\\d\\d|[2][0-5][0-5])"); // Match 0.0.0.1 ~ 0.0.0.255

void signal_server_handler(int sig) {
    if (sig == SIGCHLD) {
        int stat;
        while(waitpid(-1, &stat, WNOHANG) > 0) {
            // Remove zombie process
        }
    }
}

inline string raw_ip2str(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    char buffer[16];
    bzero(buffer, 16);

    sprintf(buffer, "%d.%d.%d.%d", a, b, c, d);

    return string(buffer);
}

inline uint16_t raw_port(uint8_t a, uint8_t b)  {
    uint16_t port = (a << 8) + b;

    return port;
}

inline string cmd2str(uint8_t command) {
    string result;

    switch (command) {
    case COMMAND_CONNECT:
        result = "CONNECT";
        break;
    case COMMAND_BIND:
        result = "BIND";
        break;
    case COMMAND_ACCEPT:
        result = "Accept";
        break;
    case COMMAND_REJECT:
        result = "Reject";
        break;
    default:
        cerr << "[ERROR]: Command to String, unknown code: " << command << endl;
        break;
    }

    return result;
}

inline void show_error(const char *func_name, int code, string msg) {
    fprintf(stderr, "[%s]: (%d, %s)\n", func_name, code, msg.c_str());
}

class ProxyHandler: public enable_shared_from_this<ProxyHandler> {
public:
    ProxyHandler(tcp::socket sock): client_sock(move(sock)), server_sock(io_context), resolver_(io_context), acceptor_(io_context) {
        // Initialize buffer
        bzero(client_buffer, BUFFER_SIZE);
        bzero(server_buffer, BUFFER_SIZE);

        // Setup client endpoint for showing message
        client_ep = client_sock.remote_endpoint();

        // Parse firewall rules
        parse_firewall();
    }

    void start() {
        read_control_message_from_client();
    }

    void parse_firewall() {
        ifstream config_file("socks.conf");
        string line;

        while(getline(config_file, line)) {
            istringstream iss(line);
            string type, value;
            vector<string> tmp;

            getline(iss, value, ' '); // Ignore operation
            getline(iss, type, ' '); // Get type

            // Parse IP address
            while(getline(iss, value, '.')) {
                tmp.push_back(value);
            }

            if (type.compare("b") == 0) {
                /* Bind */
                bind_firewall_rules.push_back(tmp);
            } else if (type.compare("c") == 0) {
                /* Connect */
                connect_firewall_rules.push_back(tmp);
            } else {
                cerr << "Unknown type: " << type << endl;
            }
        }

        config_file.close();
    }

    bool check_firewall(vector<vector<string>> &firewall_rules, string address) {
        bool result = false;

        if (firewall_rules.size() == 0) {
            // No rule for connect, default is deny
            return result;
        }

        int n[4];
        sscanf(address.c_str(), "%d.%d.%d.%d", &n[0], &n[1], &n[2], &n[3]);

        for(size_t x=0; x < firewall_rules.size(); ++x) {
            for(size_t y=0; y < firewall_rules[x].size(); ++y) {
                if (firewall_rules[x][y].compare("*") == 0) {
                    // Wild Card
                    result = true;
                    goto done;
                } else if (firewall_rules[x][y].compare(to_string(n[y])) == 0) {
                    // Pass
                    if (y == 3) {
                        // All pass
                        result = true;
                        goto done;
                    }
                    continue;
                } else {
                    result = false;
                    break;
                }
            }
        }

    done:
        return result;
    }

    void do_firewall_check() {
        // Check firewall rules
        request.is_accept = check_firewall(
            ((request.command == COMMAND_CONNECT) ? connect_firewall_rules : bind_firewall_rules),
            request.address
        );

        if (request.is_accept) {
            /* Accept */
            // Handle by command
            switch (request.command) {
            case COMMAND_CONNECT:
                handle_connect();
                break;
            case COMMAND_BIND:
                handle_bind();
                break;
            default:
                cerr << "Unknown command: " << request.command << endl;
                break;
            }
        } else {
            /* Reject */
            do_write_reply();
        }
    }

    void read_control_message_from_client() {
        #if 0
        cout << "read_control_message_from_client" << endl;
        #endif
        /* Handle SOCKS Request */
        bzero(client_buffer, BUFFER_SIZE);
        auto self(shared_from_this());
        client_sock.async_read_some(boost::asio::buffer(client_buffer, BUFFER_SIZE),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    // Get SOCKS Request
                    request.version = client_buffer[0];
                    request.command = client_buffer[1];
                    request.port = raw_port(client_buffer[2], client_buffer[3]);
                    request.address = raw_ip2str(client_buffer[4], client_buffer[5], client_buffer[6], client_buffer[7]);
                    request.need_resolve = false;

                    // Check it it has hostname
                    smatch no_use;
                    if (regex_match(request.address, no_use, SOCKS_4A_PATTERN)) {
                        char hostname_buffer[256] = {'\0'};

                        int null_counter = 0;
                        for (size_t x=SOCKS_HEADER_SIZE, idx=0; x < length; ++x) {
                            if (client_buffer[x] == '\0') {
                                ++null_counter;
                                continue;
                            }
                            if (null_counter == 1) {
                                // This is domain name
                                hostname_buffer[idx] = client_buffer[x];
                                ++idx;
                            } else {
                                // Ignore other value
                            }
                        }

                        request.hostname = string(hostname_buffer);
                        request.need_resolve = true;
                        #if 0
                        cout << "Request.Hostname: " << request.hostname << endl;
                        #endif
                    }

                    if (request.need_resolve) {
                        // SOCKS 4a
                        do_resolve();
                    } else {
                        setup_server_endpoint(request.address, request.port);
                        do_firewall_check();
                    }
                } else {
                    show_error("read_control_message_from_client", ec.value(), ec.message());
                    do_close();
                }
            }
        );
    }

    void handle_connect() {
        // Establish the connection to foreign server
        do_connect();
    }

    void handle_bind() {
        // Bind a random port on SOCKS Server
        tcp::endpoint ep(tcp::v4(), 0);

        acceptor_.open(ep.protocol());
        acceptor_.bind(ep);
        acceptor_.listen();
        request.bind_port = acceptor_.local_endpoint().port();

        // Bind: First reply
        do_write_reply();
        // Wait server establish connection
        do_accept();

        #if 0
        cout << "\tBind Port: " << request.bind_port << endl;
        #endif
    }

    void do_resolve() {
        #if 0
        cout << "do_resolve" << endl;
        #endif
        tcp::resolver::query q(request.hostname, to_string(request.port));
        auto self(shared_from_this());
        resolver_.async_resolve(q,
            [this, self](boost::system::error_code ec, tcp::resolver::iterator iter) {
                if (!ec) {
                    request.address = iter->endpoint().address().to_string(); // firewall check need
                    setup_server_endpoint(request.address, request.port);
                    do_firewall_check();
                } else {
                    show_error("do_resolve", ec.value(), ec.message());
                }
            }
        );
    }

    void do_connect() {
        #if 0
        cout << "Connect to: " << server_ep.address().to_string() << ":" << server_ep.port() << endl;
        #endif

        auto self(shared_from_this());
        server_sock.async_connect(server_ep,
            [this, self](boost::system::error_code ec) {
                if (!ec) {
                    // Connect successfully
                    request.is_accept = true;
                    do_write_reply();
                } else {
                    show_error("do_connect", ec.value(), ec.message());
                    request.is_accept = false;
                    do_write_reply();
                    do_close();
                }
            }
        );
    }

    void do_write_reply() {
        #if 0
        cout << "do_write_reply" << endl;
        #endif
        char reply[SOCKS_HEADER_SIZE] = {'\0'};

        // Version
        reply[0] = 0;
        // Command
        reply[1] = ((request.is_accept == true) ? COMMAND_ACCEPT : COMMAND_REJECT);
        // Address and Port
        if (request.command == COMMAND_CONNECT) {
            // CONNECT, ignore address and port
        } else {
            // BIND, setup port and use wildcard address
            reply[2] = request.bind_port / 256;
            reply[3] = request.bind_port % 256;
        }

        auto self(shared_from_this());
        client_sock.async_send(boost::asio::buffer(reply, SOCKS_HEADER_SIZE),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    show_socks();

                    if (request.is_accept) {
                        /* Accept */
                        if (request.command == COMMAND_CONNECT) {
                            /* CONNECT */
                            start_data_session();
                        } else {
                            /* BIND */
                        }
                    } else {
                        /* Reject */
                        do_close();
                    }
                } else {
                    show_error("do_write_reply", ec.value(), ec.message());
                    do_close();
                }
            }
        );
    }

    void do_accept() {
        // For bind operation
        auto self(shared_from_this());
        acceptor_.async_accept(
            [this, self](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    server_sock = move(socket);
                } else {
                    show_error("ProxyHandler do_accept", ec.value(), ec.message());
                }
                // Only accept one connection
                acceptor_.close();

                // Bind: Second reply
                do_write_reply();

                // Start data session
                start_data_session();
            }
        );
    }

    void start_data_session() {
        read_from_client();
        read_from_server();
    }

    void read_from_client() {
        #if 0
        cout << "read_from_client waiting..." << endl;
        #endif

        bzero(server_buffer, BUFFER_SIZE);
        auto self(shared_from_this());
        client_sock.async_read_some(boost::asio::buffer(server_buffer, BUFFER_SIZE),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    #if 0
                    cout << "read_from_client got " << length << " data" << endl;
                    #endif

                    send_to_server(length);
                } else {
                    if (ec.value() == boost::asio::error::eof) {
                        // Client close the connection
                        #if 0
                        cout << "Shutdown C -> S" << endl;
                        #endif
                        send_to_server(length);
                        try {
                            server_sock.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
                        } catch (exception &e) {
                            // Transport endpoint is not connected
                        }
                    } else if (ec.value() == boost::asio::error::operation_aborted) {
                        // Stop doing anything
                    } else if (ec.value() == boost::asio::error::connection_reset || ec.value() == boost::asio::error::bad_descriptor) {
                        client_sock.close();
                        server_sock.cancel();
                    } else {
                        show_error("read_from_client", ec.value(), ec.message());
                    }
                }
            }
        );
    }

    void send_to_server(size_t data_length) {
        #if 0
        cout << "send_to_server" << endl;
        #endif

        auto self(shared_from_this());
        server_sock.async_send(boost::asio::buffer(server_buffer, data_length),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    #if 0
                    cout << "send_to_server write " << length << " data" << endl;
                    #endif
                    if (length > 0) {
                        read_from_client();
                    }
                } else if (ec.value() == boost::asio::error::operation_aborted) {
                    #if 0
                    cout << "send_to_server aborted" << endl;
                    #endif
                } else {
                    show_error("send_to_server", ec.value(), ec.message());
                }
            }
        );
    }

    void read_from_server() {
        #if 0
        cout << "read_from_server waiting..." << endl;
        #endif

        bzero(client_buffer, BUFFER_SIZE);
        auto self(shared_from_this());
        server_sock.async_read_some(boost::asio::buffer(client_buffer, BUFFER_SIZE),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    #if 0
                    cout << "read_from_server got " << length << " data" << endl;
                    #endif

                    send_to_client(length);
                } else {
                    if (ec.value() == boost::asio::error::eof) {
                        // Server close the connection
                        #if 0
                        cout << "Shutdown S -> C" << endl;
                        #endif
                        send_to_client(length);
                        try {
                            client_sock.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
                        } catch (exception &e) {
                            // Transport endpoint is not connected
                        }
                    } else if (ec.value() == boost::asio::error::operation_aborted) {
                        #if 0
                        cout << "read_from_server aborted" << endl;
                        #endif
                    } else {
                        show_error("read_from_server", ec.value(), ec.message());
                    }
                }
            }
        );
    }
    
    void send_to_client(size_t data_length) {
        #if 0
        cout << "send_to_client" << endl;
        #endif

        auto self(shared_from_this());
        client_sock.async_send(boost::asio::buffer(client_buffer, data_length),
            [this, self, data_length](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    #if 0
                    cout << "send_to_client write " << length << " data" << endl;
                    #endif

                    if (length > 0) {
                        read_from_server();
                    }
                } else if (ec.value() == boost::asio::error::operation_aborted) {
                    #if 0
                    cout << "send_to_client aborted" << endl;
                    #endif
                    client_sock.close();
                } else if (ec.value() == boost::asio::error::broken_pipe) {
                    // Write on a closed socket
                    // Peer has already close the socket
                    client_sock.cancel();
                } else if (ec.value() == boost::asio::error::bad_descriptor) {
                    // Local has aready close the socket
                } else if (ec.value() == boost::asio::error::connection_reset) {
                    // Read on a closed socket
                    // Peer has already close the socket
                    client_sock.close();
                    server_sock.cancel();
                } else {
                    show_error("send_to_client", ec.value(), ec.message());
                }
            }
        );
    }
    
    void do_close() {
        #if 0
        cout << "do_close" << endl;
        #endif
        client_sock.close();
        server_sock.close();
    }

    void setup_server_endpoint(string address, uint16_t port) {
        server_ep = tcp::endpoint(address::from_string(address), port);
    }

    void show_socks() {
        cout << "<S_IP>: " << client_ep.address().to_string() << endl
            << "<S_PORT>: " << client_ep.port() << endl
            << "<D_IP>: " << server_ep.address().to_string() << endl
            << "<D_PORT>: " << server_ep.port() << endl
            << "<Command>: " << cmd2str(request.command) << endl
            << "<Reply>: " << cmd2str((request.is_accept == true) ? COMMAND_ACCEPT : COMMAND_REJECT) << endl;
    }

private:
    tcp::socket client_sock, server_sock;
    SocksInfo request;
    tcp::resolver resolver_;
    tcp::acceptor acceptor_;
    tcp::endpoint client_ep;
    tcp::endpoint server_ep;
    
    char client_buffer[BUFFER_SIZE];
    char server_buffer[BUFFER_SIZE];

    vector<vector<string>> connect_firewall_rules;
    vector<vector<string>> bind_firewall_rules;
};

class Server {
public:
    Server(short port): acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
        boost::asio::socket_base::reuse_address option(true);
        acceptor_.set_option(option);

        do_accept();
    }

    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    pid_t pid;
                    io_context.notify_fork(boost::asio::io_context::fork_prepare);
                    pid = fork();

                    if (pid < 0) {
                        socket.close();
                        perror("Fork");
                    } else if (pid == 0) {
                        // Child
                        io_context.notify_fork(boost::asio::io_context::fork_child);
                        acceptor_.close();
                        make_shared<ProxyHandler>(move(socket))->start();
                    } else {
                        // Parent
                        io_context.notify_fork(boost::asio::io_context::fork_parent);
                        socket.close();
                        do_accept();
                    }
                } else {
                    show_error("server do_accept", ec.value(), ec.message());
                }
            }
        );
    }

private:
    tcp::acceptor acceptor_;
};

int main(int argc, char* argv[]) {
    try {
        if (argc != 2) {
            cerr << "Usage: socks_server <port>\n";
            return 1;
        }
        signal(SIGCHLD, signal_server_handler);

        Server server_(atoi(argv[1]));

        io_context.run();
    } catch (exception &e) {
        // cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}