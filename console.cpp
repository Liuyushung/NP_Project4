#include <strings.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>

#define MAX_SERVER      5
#define ATTRIBUTES_SIZE 3
#define BUFFER_SIZE     4096
#define SOCKS_HEADER_SIZE  1+1+2+4 

using boost::asio::ip::tcp;
using namespace std;

typedef struct client_info {
    string host;
    string port;
    string fname;
    bool   is_active;
} ClientInfo;

const uint8_t SOCK4_VERSION   = 04;
const uint8_t COMMAND_CONNECT = 1;
const uint8_t COMMAND_BIND    = 2;
const uint8_t COMMAND_ACCEPT  = 90;
const uint8_t COMMAND_REJECT  = 91;

vector<ClientInfo> clients;
string socks_server_hostname;
string socks_server_port;

inline void show_error(const char *func_name, int code, string msg) {
    fprintf(stderr, "[%s]: (%d, %s)\n", func_name, code, msg.c_str());
}

class session: public enable_shared_from_this<session> {
public:
    session(boost::asio::io_context& io_context, int session_id):
        resolver_(io_context),
        sock(io_context) {
            string test_path = "./test_case/";

            this->session_id = session_id;
            bzero(data_buffer, BUFFER_SIZE);
            input_file.open(test_path + clients[session_id].fname, ios::in);
            if (input_file.fail()) {
                perror("Open file");
            }
        }

    void start() {
        #if 0
        cerr << "Sesion " << session_id << " start" << endl;
        #endif
        // do_resolve(clients[session_id].host, clients[session_id].port);
        do_resolve(socks_server_hostname, socks_server_port);
    }

    void do_resolve(string hostname, string port) {
        tcp::resolver::query q(hostname, port);

        auto self(shared_from_this());
        resolver_.async_resolve(q,
            [this, self](boost::system::error_code ec, tcp::resolver::iterator iter) {
                if (!ec) {
                    #if 0
                    cerr << "Resolve reuslt: " << iter->endpoint().address().to_string() << ":" << iter->endpoint().port() << endl;
                    #endif
                    do_connect(iter);
                } else {
                    show_error("do_resolve", ec.value(), ec.message());
                }
            }
        );
    }

    void do_connect(tcp::resolver::iterator iter) {
        auto self(shared_from_this());
        sock.async_connect(*iter,
            [this, self, iter](boost::system::error_code ec) {
                if (!ec) {
                    handle_SOCKS();
                } else {
                    #if 0
                    cerr << "Connect to " << iter->endpoint().address().to_string() << ":" << iter->endpoint().port() << endl;
                    #endif
                    show_error("do_connect", ec.value(), ec.message());
                    sock.close();
                }
            }
        );
    }

    void handle_SOCKS() {
        /* Build SOCKS CONNECT Request */
        uint32_t request_size = SOCKS_HEADER_SIZE + clients[session_id].host.length() + 1 + 1;  // 2 NULLs
        char *request = (char *)malloc(request_size);
        bzero(request, request_size);

        // Version
        request[0] = SOCK4_VERSION;
        // Command
        request[1] = COMMAND_CONNECT;
        // Port
        uint16_t port = static_cast<uint16_t>(stoi(clients[session_id].port));
        request[2] = port / 256;
        request[3] = port % 256;
        // IP Address, 0.0.0.x
        request[7] = 01;
        // User ID, Ignore
        // Hostname
        memcpy(&request[SOCKS_HEADER_SIZE+1], clients[session_id].host.c_str(), clients[session_id].host.length());

        /* Send SOCKS CONNECT Request */
        auto self(shared_from_this());
        sock.async_send(boost::asio::buffer(request, request_size),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    // Do nothing
                } else {
                    show_error("[handle_SOCKS]: send reqeust", ec.value(), ec.message());
                }
            }
        );

        /* Read SOCKS Reply */
        sock.async_receive(boost::asio::buffer(socks_reply, SOCKS_HEADER_SIZE),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    uint8_t command = socks_reply[1];

                    switch (command) {
                    case COMMAND_ACCEPT:
                        // Start Data Session
                        do_read();
                        break;
                    case COMMAND_REJECT:
                        // Close connection
                        sock.close();
                        break;
                    default:
                        cerr << "Unknown command: " << command << endl;
                        sock.close();
                        break;
                    }
                } else {
                    show_error("handle_SOCKS, receive socks_reply", ec.value(), ec.message());
                }
            }
        );
    }

    void do_read() {
        auto self(shared_from_this());
        sock.async_read_some(boost::asio::buffer(data_buffer, BUFFER_SIZE),
            [this, self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    full_message += data_buffer;
                    memset(data_buffer, '\0', length);

                    print_result(full_message);
                    if (full_message.find("% ") != string::npos) {
                        do_write();
                    }
                    full_message.clear();

                    do_read();
                } else {
                    if (ec.value() == boost::asio::error::eof) {
                        do_close();
                    } else {
                        perror("Do read");
                    }
                }
            }
        );
    }

    void do_write() {
        string command;

        auto self(shared_from_this());

        if (input_file.eof()) {
            cerr << "Read EOF" << endl;
            // TODO: close here?
            return;
        }
        if (!getline(input_file, command)) {
            perror("Do write, read from file");
        }
        command += "\n";
        print_command(command);

        sock.async_write_some(boost::asio::buffer(command.c_str(), command.length()), 
            [this,self](boost::system::error_code ec, size_t length) {
                if (!ec) {
                    // do nothing
                } else {
                    perror("Do write, write message");
                }
            }
        );
    }

    void do_close() {
        input_file.close();
        sock.close();
    }

    void string2html(string &input) {
        boost::algorithm::replace_all(input,"&","&amp;");
        boost::algorithm::replace_all(input,"<","&lt;");
        boost::algorithm::replace_all(input,">","&gt;");
        boost::algorithm::replace_all(input,"\"","&quot;");
        boost::algorithm::replace_all(input,"\'","&apos;");
        boost::algorithm::replace_all(input,"\r\n","\n");
        boost::algorithm::replace_all(input,"\n","<br>");
    }

    void print_result(string content) {
        #if 0
        cerr << "Recv result: " << content << endl;
        #endif 
        string2html(content);
        printf("<script>document.getElementById('s%d').innerHTML += '%s';</script>",
            session_id, content.c_str());
        cout.flush();
    }

    void print_command(string command) {
        #if 0
        cerr << "Send command: " << command << endl;
        #endif 
        string2html(command);
        printf("<script>document.getElementById('s%d').innerHTML += '<b>%s</b>';</script>",
            session_id, command.c_str());
        cout.flush();
    }

private:
    tcp::resolver resolver_;
    tcp::socket sock;
    int session_id;
    char data_buffer[BUFFER_SIZE];
    char socks_reply[SOCKS_HEADER_SIZE];
    ifstream input_file;
    string full_message;
};


void debug_clients() {
    int n = 0;

    for (auto c: clients) {
        if (c.is_active) {
            cerr << "Host: " << c.host << " Port: " << c.port << " File: " << c.fname << endl;
            ++n;
        }
    }
    cerr << "Active sessions: " << n << endl;
}

vector<string> my_split(string str, char delimeter) {
    stringstream ss(str);
    string token;
    vector<string> result;

    while (getline(ss, token, delimeter)) {
        result.push_back(token);
    }

    return result;
}

void parse_query() {
    vector<string> raw_queries;
    string query = getenv("QUERY_STRING");
    string host, port, fname;
    int counter = 0;
    #if 0
    cerr << query << endl;
    #endif

    // Example: h0=nplinux1.cs.nctu.edu.tw&p0=65530&f0=t1.txt&h1=nplinux2.cs.nctu.edu.tw&p1=65531&f1=t2.txt&h2=&p2=&f2=&h3=&p3=&f3=&h4=&p4=&f4=&sh=npbsd1.cs.nctu.edu.tw&sp=8787
    raw_queries = my_split(query, '&');

    for (auto &s: raw_queries) {
        int x = s.find("=");
        string value;

        if (s.find("sh") != string::npos) {
            // Retrieve SOCKS server hostname
            socks_server_hostname = s.substr(x+1, s.length() - x - 1);

        } else if (s.find("sp") != string::npos) {
            // Retrieve SOCKS server port
            socks_server_port = s.substr(x+1, s.length() - x - 1);
        } else {
            // Handle RWD server hostname, port and file name
            if (s.length() == 3) {
                // Only key, no value, ignore
                continue;
            } else {
                value = s.substr(x+1, s.length() - x - 1);
            }

            switch (counter % ATTRIBUTES_SIZE) {
                case 0:
                    /* host */
                    host = value;
                    break;
                case 1:
                    /* port */
                    port = value;
                    break;
                case 2:
                    /* file */
                    fname = value;
                    break;
            }
            ++counter;

            if (host != "" && port != "" && fname != "") {
                ClientInfo client = { host, port, fname, true };
                clients.push_back(client);
                host.clear();
                port.clear();
                fname.clear();
            }
        }
    }

    #if 0
    cerr << "SOCKS Server: " << socks_server_hostname << ":" << socks_server_port << endl;
    #endif
    
    return;
}

void print_html() {
    cout << "Content-type: text/html\r\n\r\n";
    cout << "\
<!DOCTYPE html>\
<html lang=\"en\">\
  <head>\
    <meta charset=\"UTF-8\" />\
    <title>NP Project 3 Console</title>\
    <link\
      rel=\"stylesheet\"\
      href=\"https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css\"\
      integrity=\"sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2\"\
      crossorigin=\"anonymous\"\
    />\
    <link\
      href=\"https://fonts.googleapis.com/css?family=Source+Code+Pro\"\
      rel=\"stylesheet\"\
    />\
    <link\
      rel=\"icon\"\
      type=\"image/png\"\
      href=\"https://cdn0.iconfinder.com/data/icons/small-n-flat/24/678068-terminal-512.png\"\
    />\
    <style>\
      * {\
        font-family: 'Source Code Pro', monospace;\
        font-size: 1rem !important;\
      }\
      body {\
        background-color: #212529;\
      }\
      pre {\
        color: #cccccc;\
      }\
      b {\
        color: #01b468;\
      }\
    </style>\
  </head>\
  <body>\
    <table class=\"table table-dark table-bordered\">\
      <thead>\
        <tr id=\"table_head\"> </tr>\
      </thead>\
      <tbody>\
        <tr id=\"session\"> </tr>\
      </tbody>\
    </table>\
  </body>\
</html>";

    cout.flush();
}

void print_table(int session_id, string host, string port){
    printf("<script>var table = document.getElementById('table_head'); table.innerHTML += '<th scope=\"col\">%s:%s</th>';</script>", host.c_str(), port.c_str());
    printf("<script>var table = document.getElementById('session'); table.innerHTML += '<td><pre id=\\'s%d\\' class=\\'mb-0\\'></pre></td>&NewLine;' </script>", session_id);
    cout.flush();
}

int main(int argc, char *argv[]) {
    // setenv("QUERY_STRING", "h0=nplinux2.cs.nctu.edu.tw&p0=43645&f0=t1.txt&h1=nplinux2.cs.nctu.edu.tw&p1=44899&f1=t2.txt&h2=nplinux2.cs.nctu.edu.tw&p2=35451&f2=t3.txt&h3=&p3=&f3=&h4=&p4=&f4=", 1);
    // setenv("QUERY_STRING", "h0=nplinux2.cs.nctu.edu.tw&p0=50500&f0=t1.txt&h1=&p1=&f1=&h2=&p2=&f2=&h3=&p3=&f3=&h4=&p4=&f4=&sh=nplinux6.cs.nctu.edu.tw&sp=8787", 1);
    // setenv("QUERY_STRING", "h0=nplinux2.cs.nctu.edu.tw&p0=50500&f0=t1.txt&h1=&p1=&f1=&h2=&p2=&f2=&h3=&p3=&f3=&h4=&p4=&f4=&sh=socks&sp=8787", 1);
    parse_query();
    print_html();
    for (size_t i = 0; i < clients.size(); i++) {
        if (clients[i].is_active) {
            print_table(i, clients[i].host, clients[i].port);
        }
    }

    #if 0
    debug_clients();
    #endif

    try {
        boost::asio::io_context io_context;

        for (size_t i = 0; i < clients.size(); i++) {
            if (clients[i].is_active) {
                make_shared<session>(io_context, i)->start();
            }
        }

        io_context.run();
    } catch(exception& e) {
        // cerr << "Exception : " << e.what() << "\n";
    }

    return 0;
}