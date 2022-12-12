#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <strings.h>
#include <boost/asio.hpp>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096

using boost::asio::ip::tcp;
using boost::asio::io_service;
using namespace std;

boost::asio::io_service my_io_service;
boost::asio::io_context io_context;

typedef struct socks_header {
    uint8_t version;
    uint8_t command;
    uint16_t port;
    string address;
    string hostname;
} SocksHeader;

const uint8_t SOCKS_VERSION = 04;

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
    case 1:
        result = "CONNECT";
        break;
    case 2:
        result = "BIND";
        break;
    case 90:
        result = "Accept";
        break;
    case 91:
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
    ProxyHandler(tcp::socket sock): inner_sock(move(sock)), outer_sock(io_context) {
        bzero(inner_buffer, BUFFER_SIZE);
        bzero(outer_buffer, BUFFER_SIZE);

    }

    void start() {
        do_inner_read_control();
    }

    void do_inner_read_control() {
        auto self(shared_from_this());
        inner_sock.async_read_some(boost::asio::buffer(inner_buffer, BUFFER_SIZE),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    bool need_resolve = false;

                    // Get SOCKS Request
                    request.version = inner_buffer[0];
                    request.command = inner_buffer[1];
                    request.port = raw_port(inner_buffer[2], inner_buffer[3]);
                    request.address = raw_ip2str(inner_buffer[4], inner_buffer[5], inner_buffer[6], inner_buffer[7]);
                    if (request.address.find("0.0.0.") != string::npos) {
                        char tmp_buffer[256];
                        bzero(tmp_buffer, 256);

                        int x = 8, idx = 0;
                        while(inner_buffer[x] != '\0') {
                            tmp_buffer[idx] = inner_buffer[x];
                            ++x;
                            ++idx;
                        }

                        request.hostname = string(tmp_buffer);
                        need_resolve = true;
                    }

                    do_connect(need_resolve);
                } else {
                    show_error("do_inner_read", ec.value(), ec.message());
                }
            }
        );

    }

    void do_connect(bool need_resolve) {

    }

    void do_close() {
        inner_sock.close();
        outer_sock.close();
    }

    void show_socks() {
        string src_ip_addr = inner_sock.remote_endpoint().address().to_string();
        string src_port = to_string(static_cast<unsigned short>(inner_sock.remote_endpoint().port()));

        cout << "<S_IP>: " << src_ip_addr << endl
            << "<S_PORT>: " << src_port << endl
            << "<D_IP>: " << request.address << endl
            << "<D_PORT>: " << request.port << endl
            << "<Command>: " << cmd2str(request.command) << endl
            << "<Reply>: " << cmd2str(90) << endl;
    }

private:
    tcp::socket inner_sock, outer_sock;
    SocksHeader request;
    
    char inner_buffer[BUFFER_SIZE];
    char outer_buffer[BUFFER_SIZE];
};

class Server {
public:
    Server(short port): acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
        boost::asio::socket_base::reuse_address option(true);
        acceptor_.set_option(option);

        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    make_shared<ProxyHandler>(move(socket))->start();
                }

                do_accept();
            }
        );
    }

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