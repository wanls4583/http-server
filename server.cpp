#include <fstream>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>


using namespace std;

int initServSock();
int initClntSock(int);
char* readFile(ifstream&, int&);
string findFileName(string);
string getType(string);
void notFound(int);

const int port = 8080;

int main() {
    int servSock = initServSock();    

    while(1) {
        initClntSock(servSock);
    }

    shutdown(servSock, SHUT_RDWR);

    return 0;
}

int initServSock() {
    int servSock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servAddr;

    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family = AF_INET;
    // servAddr.sin_addr.s_addr = inet_addr('127.0.0.1');
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);

    bind(servSock, (struct sockaddr*)&servAddr, sizeof(servAddr));

    listen(servSock, 10);

    return servSock;
}

int initClntSock(int servSock) {
    char buf[10240];
    struct sockaddr_in clntAddr;
    socklen_t clntAddrLen = sizeof(clntAddr);
    int clntSock = accept(servSock, (struct sockaddr*)&clntAddr, &clntAddrLen);
    
    read(clntSock, buf, sizeof(buf));

    string fName = findFileName(buf);

    if (fName.length()) {
        fName = "www" + fName;
        ifstream inFile(fName.c_str(), ios::in | ios::binary);
         
        if (inFile.good()) {
            string head = "HTTP/1.1 200 OK\n";
            string type = getType(fName);
            int len = 0;
            char* data = readFile(inFile, len);

            head += "Content-Type: " + type + "\n";
            head += "Connection: close\n";
            head += "Content-Length: " + to_string(len) + "\n";
            head += "\n";
            
            cout<<fName<<":"<<len<<endl;

            write(clntSock, const_cast<char*>(head.c_str()), head.length());
            write(clntSock, data, len);
            delete[] data;
        } else {
            notFound(clntSock);
        }
    } else {
        notFound(clntSock);
    }

    shutdown(clntSock, SHUT_RDWR);
 
    return clntSock;
}

void notFound(int clntSock) {
    string s = "HTTP/1.1 404 Not Found\nConnection: close\n\n404 Not Found";
    write(clntSock, s.c_str(), s.length());
}

string getType(string fName) {
    if (fName.find(".png") == fName.length() - 4) {
        return "image/apng";
    } else if (fName.find(".jpg") == fName.length() - 4) {
        return "image/jpg";
    } else {
        return "text/html";
    }
}

char* readFile(ifstream& inFile, int& len) {
    
    inFile.seekg(0, inFile.end);

    len = inFile.tellg();

    inFile.seekg(0, inFile.beg);

    char* arr = new char[len];

    inFile.read(arr, len);

    return arr;
}

string findFileName(string s) {
    int n = s.find("\r\n"), n1 = 0;
    if (n < 0) {
        return "";
    }
    s = s.substr(0, n);
    n = s.find(" ");
    n1 = s.rfind(" ");
    s = s.substr(n+1, n1 - n - 1);
    return s;
}