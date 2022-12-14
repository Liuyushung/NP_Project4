#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <strings.h>
#include <boost/asio.hpp>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#define BUFFER_SIZE         4096
#define SOCKS_REPLY_SIZE    1+1+2+4

using boost::asio::ip::address;
using boost::asio::ip::tcp;
using boost::asio::io_service;
using namespace std;

boost::asio::io_context io_context;

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
        bzero(client_buffer, BUFFER_SIZE);
        bzero(server_buffer, BUFFER_SIZE);

        parse_firewall();
    }

    void start() {
        check_firewall();
        if (request.is_accept == true) {
            read_control_message_from_client();
        } else {
            // TODO
        }
    }

    void parse_firewall() {
        // TODO
    }

    void check_firewall() {
        // TODO

        request.is_accept = true;
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
                    if (request.address.find("0.0.0.") != string::npos) {
                        char tmp_buffer[256] = {'\0'};

                        int x = 8, idx = 0;
                        while(client_buffer[x] != '\0') {
                            tmp_buffer[idx] = client_buffer[x];
                            ++x;
                            ++idx;
                        }

                        request.hostname = string(tmp_buffer);
                        request.need_resolve = true;
                        #if 1
                        cout << "Request.Hostname: " << request.hostname << endl;
                        #endif
                    }

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
                    show_error("do_inner_read", ec.value(), ec.message());
                    do_close();
                }
            }
        );
    }

    void handle_connect() {
        // Establish the connection to foreign server
        if(request.need_resolve) {
            do_resolve();
        } else {
            do_connect();
        }
    }

    void handle_bind() {
        // Bind a random port on SOCKS Server
        tcp::endpoint ep(tcp::v4(), 0);

        acceptor_.open(ep.protocol());
        acceptor_.bind(ep);
        acceptor_.listen();
        request.bind_port = acceptor_.local_endpoint().port();

        do_write_reply();

        #if 1
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
                    do_connect(iter);
                } else {
                    show_error("do_resolve", ec.value(), ec.message());
                }
            }
        );
    }

    void do_connect() {
        #if 0
        cout << "do_connect" << endl;
        #endif
        tcp::endpoint remote_ep(address::from_string(request.address), request.port);
        #if 0
        cout << "Connect to: " << remote_ep.address().to_string() << ":" << remote_ep.port() << endl;
        #endif

        auto self(shared_from_this());
        server_sock.async_connect(remote_ep,
            [this, self](boost::system::error_code ec) {
                if (!ec) {
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

    void do_connect(tcp::resolver::iterator iter) {
        #if 0
        cout << "do_connect with iter" << endl;
        #endif
        auto self(shared_from_this());
        server_sock.async_connect(*iter,
            [this, self, iter](boost::system::error_code ec) {
                if (!ec) {
                    request.is_accept = true;
                    do_write_reply();
                } else {
                    show_error("do_connect with iter", ec.value(), ec.message());
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
        char reply[SOCKS_REPLY_SIZE] = {'\0'};

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
        client_sock.async_write_some(boost::asio::buffer(reply, SOCKS_REPLY_SIZE),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    if (request.is_accept) {
                        /* Accept */
                        if (request.command == COMMAND_CONNECT) {
                            /* CONNECT */
                            start_data_session();
                        } else {
                            /* BIND */
                            do_accept();
                        }
                    } else {
                        /* Reject */
                        do_close();
                    }

                    show_socks();
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
                // add_pairs(client_sock.remote_endpoint(), server_sock.remote_endpoint());

                // Only accept one connection
                acceptor_.close();
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
                        cout << client_sock.remote_endpoint().address().to_string() << ":"
                            << client_sock.remote_endpoint().port()
                            << " Close connection" << endl;
                    } else if (ec.value() == 125) {
                        // Close by another connection
                    } else {
                        show_error("read_from_client", ec.value(), ec.message());
                    }
                    do_close();
                }
            }
        );
    }

    void send_to_server(size_t data_length) {
        #if 0
        cout << "send_to_server" << endl;
        #endif
        auto self(shared_from_this());
        server_sock.async_write_some(boost::asio::buffer(server_buffer, data_length),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    #if 0
                    cout << "send_to_server write " << length << " data" << endl;
                    #endif
                    // Clean Buffer
                    bzero(server_buffer, BUFFER_SIZE);
                    
                    read_from_client();
                } else {
                    show_error("send_to_server", ec.value(), ec.message());
                    do_close();
                }
            }
        );
    }

    void read_from_server() {
        #if 0
        cout << "read_from_server waiting..." << endl;
        #endif
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
                        cout << server_sock.remote_endpoint().address().to_string() << ":"
                            << server_sock.remote_endpoint().port()
                            << " Close connection" << endl;
                    } else if (ec.value() == 125) {
                        // Close by another connection
                    } else {
                        show_error("read_from_server", ec.value(), ec.message());
                    }

                    do_close();
                }
            }
        );
    }
    
    void send_to_client(size_t data_length) {
        #if 0
        cout << "send_to_client" << endl;
        #endif
        auto self(shared_from_this());
        client_sock.async_write_some(boost::asio::buffer(client_buffer, data_length),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    #if 0
                    cout << "send_to_client write " << length << " data" << endl;
                    #endif
                    // Clean Buffer
                    bzero(client_buffer, BUFFER_SIZE);

                    read_from_server();
                } else {
                    show_error("send_to_client", ec.value(), ec.message());
                    do_close();
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

    void show_socks() {
        string src_ip_addr = client_sock.remote_endpoint().address().to_string();
        string src_port = to_string(static_cast<unsigned short>(client_sock.remote_endpoint().port()));

        cout << "<S_IP>: " << src_ip_addr << endl
            << "<S_PORT>: " << src_port << endl
            << "<D_IP>: " << request.address << endl
            << "<D_PORT>: " << request.port << endl
            << "<Command>: " << cmd2str(request.command) << endl
            << "<Reply>: " << cmd2str((request.is_accept == true) ? COMMAND_ACCEPT : COMMAND_REJECT) << endl;
    }

private:
    tcp::socket client_sock, server_sock;
    SocksInfo request;
    tcp::resolver resolver_;
    tcp::acceptor acceptor_;
    
    char client_buffer[BUFFER_SIZE];
    char server_buffer[BUFFER_SIZE];
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
                    }
                }
                do_accept();
            }
        );
    }

private:
    tcp::acceptor acceptor_;
};

int main(int argc, char* argv[]) {
    try {
        if (argc != 2) {
            cerr << "Usage: http_server <port>\n";
            return 1;
        }
        signal(SIGCHLD, signal_server_handler);

        Server server_(atoi(argv[1]));

        io_context.run();
    } catch (exception& e) {
        cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}