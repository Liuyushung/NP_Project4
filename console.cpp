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

using boost::asio::ip::tcp;
using namespace std;

typedef struct client_info {
    string host;
    string port;
    string fname;
    bool   is_active;
} ClientInfo;
// ClientInfo clients[MAX_SERVER];
vector<ClientInfo> clients;

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
        do_resolve();
    }

    void do_resolve() {
        tcp::resolver::query q(clients[session_id].host, clients[session_id].port);

        auto self(shared_from_this());
        resolver_.async_resolve(q,
            [this, self](boost::system::error_code ec, tcp::resolver::iterator iter) {
                if (!ec) {
                    do_connect(iter);
                } else {
                    perror("Do resolve");
                }
            }
        );
    }

    void do_connect(tcp::resolver::iterator iter) {
        auto self(shared_from_this());
        sock.async_connect(*iter,
            [this, self, iter](boost::system::error_code ec) {
                if (!ec) {
                    do_read();
                } else {
                    perror("Do connect");
                    sock.close();
                    do_connect(iter);
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

void init_global() {
    // bzero(clients, sizeof(ClientInfo)*5);
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

    raw_queries = my_split(query, '&');

    for (auto &s: raw_queries) {
        int x = s.find("=");
        string value;
        if (s.length() == 3) {
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
    // setenv("QUERY_STRING", "h0=nplinux1.cs.nctu.edu.tw&p0=65531&f0=t1.txt&h1=nplinux2.cs.nctu.edu.tw&p1=65532&f1=t2.txt&h2=nplinux3.cs.nctu.edu.tw&p2=65533&f2=t3.txt&h3=nplinux4.cs.nctu.edu.tw&p3=65534&f3=t4.txt&h4=nplinux5.cs.nctu.edu.tw&p4=65535&f4=t5.txt", 1);
    // setenv("QUERY_STRING", "h0=nplinux2.cs.nctu.edu.tw&p0=43645&f0=t1.txt&h1=nplinux2.cs.nctu.edu.tw&p1=44899&f1=t2.txt&h2=nplinux2.cs.nctu.edu.tw&p2=35451&f2=t3.txt&h3=&p3=&f3=&h4=&p4=&f4=", 1);
    // setenv("QUERY_STRING", "h0=nplinux2.cs.nctu.edu.tw&p0=65531&f0=t1.txt&h1=&p1=&f1=&h2=&p2=&f2=&h3=&p3=&f3=&h4=&p4=&f4=", 1);
    init_global();
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
        cerr << "Exception : " << e.what() << "\n";
    }

    return 0;
}