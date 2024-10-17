#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>

namespace fs = std::filesystem;

const int BUFFER_SIZE = 1024;

struct Message {
    std::string sender;
    std::string receiver;
    std::string subject;
    std::string content;
};

class MailServer {
public:
    MailServer(int port, const std::string& mailDir)
        : port(port), mailDir(mailDir) {
        if (!fs::exists(mailDir)) {
            fs::create_directory(mailDir);
        }
    }

    void run();

private:
    int port;
    std::string mailDir;

    void handleClient(int clientSock);
    std::string readLine(int sock);
    void sendResponse(int sock, const std::string& response);
    bool validateUsername(const std::string& username);
    void saveMessage(const Message& msg);
    std::vector<std::string> listMessages(const std::string& username);
    std::string readMessage(const std::string& username, int msgNum);
    bool deleteMessage(const std::string& username, int msgNum);
};

void MailServer::run() {
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in serverAddr{}, clientAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSock, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind failed");
        close(serverSock);
        exit(EXIT_FAILURE);
    }

    if (listen(serverSock, 5) < 0) {
        perror("Listen failed");
        close(serverSock);
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port " << port << "\n";

    while (true) {
        socklen_t clientLen = sizeof(clientAddr);
        int clientSock = accept(serverSock, (sockaddr*)&clientAddr, &clientLen);
        if (clientSock < 0) {
            perror("Accept failed");
            continue;
        }

        handleClient(clientSock);
        close(clientSock);
    }

    close(serverSock);
}

void MailServer::handleClient(int clientSock) {
    while (true) {
        std::string command = readLine(clientSock);
        if (command == "SEND") {
            Message msg;
            msg.sender = readLine(clientSock);
            msg.receiver = readLine(clientSock);
            msg.subject = readLine(clientSock);

            std::ostringstream contentStream;
            std::string line;
            while ((line = readLine(clientSock)) != ".") {
                contentStream << line << "\n";
            }
            msg.content = contentStream.str();

            if (validateUsername(msg.sender) && validateUsername(msg.receiver)) {
                saveMessage(msg);
                sendResponse(clientSock, "OK\n");
            } else {
                sendResponse(clientSock, "ERR\n");
            }
        } else if (command == "LIST") {
            std::string username = readLine(clientSock);
            if (validateUsername(username)) {
                auto subjects = listMessages(username);
                sendResponse(clientSock, std::to_string(subjects.size()) + "\n");
                for (const auto& subj : subjects) {
                    sendResponse(clientSock, subj + "\n");
                }
            } else {
                sendResponse(clientSock, "0\n");
            }
        } else if (command == "READ") {
            std::string username = readLine(clientSock);
            int msgNum = std::stoi(readLine(clientSock));
            if (validateUsername(username)) {
                std::string msgContent = readMessage(username, msgNum);
                if (!msgContent.empty()) {
                    sendResponse(clientSock, "OK\n" + msgContent);
                } else {
                    sendResponse(clientSock, "ERR\n");
                }
            } else {
                sendResponse(clientSock, "ERR\n");
            }
        } else if (command == "DEL") {
            std::string username = readLine(clientSock);
            int msgNum = std::stoi(readLine(clientSock));
            if (validateUsername(username) && deleteMessage(username, msgNum)) {
                sendResponse(clientSock, "OK\n");
            } else {
                sendResponse(clientSock, "ERR\n");
            }
        } else if (command == "QUIT") {
            break;
        } else {
            sendResponse(clientSock, "ERR\n");
        }
    }
}

std::string MailServer::readLine(int sock) {
    char c;
    std::string line;
    while (recv(sock, &c, 1, 0) > 0) {
        if (c == '\n') break;
        line += c;
    }
    return line;
}

void MailServer::sendResponse(int sock, const std::string& response) {
    send(sock, response.c_str(), response.length(), 0);
}

bool MailServer::validateUsername(const std::string& username) {
    if (username.length() > 8) return false;
    for (char c : username) {
        if (!std::isalnum(c) || std::isupper(c)) return false;
    }
    return true;
}

void MailServer::saveMessage(const Message& msg) {
    std::string userDir = mailDir + "/" + msg.receiver;
    if (!fs::exists(userDir)) {
        fs::create_directory(userDir);
    }
    int msgCount = std::distance(fs::directory_iterator(userDir), fs::directory_iterator{});
    std::string msgFile = userDir + "/" + std::to_string(msgCount + 1) + ".txt";

    std::ofstream outFile(msgFile);
    outFile << "From: " << msg.sender << "\n";
    outFile << "To: " << msg.receiver << "\n";
    outFile << "Subject: " << msg.subject << "\n";
    outFile << msg.content;
    outFile.close();
}

std::vector<std::string> MailServer::listMessages(const std::string& username) {
    std::vector<std::string> subjects;
    std::string userDir = mailDir + "/" + username;
    if (!fs::exists(userDir)) return subjects;

    for (const auto& entry : fs::directory_iterator(userDir)) {
        std::ifstream inFile(entry.path());
        std::string line;
        while (std::getline(inFile, line)) {
            if (line.find("Subject: ") == 0) {
                subjects.push_back(line.substr(9));
                break;
            }
        }
    }
    return subjects;
}

std::string MailServer::readMessage(const std::string& username, int msgNum) {
    std::string userDir = mailDir + "/" + username;
    std::string msgFile = userDir + "/" + std::to_string(msgNum) + ".txt";
    if (!fs::exists(msgFile)) return "";

    std::ifstream inFile(msgFile);
    std::ostringstream msgStream;
    msgStream << inFile.rdbuf();
    return msgStream.str();
}

bool MailServer::deleteMessage(const std::string& username, int msgNum) {
    std::string userDir = mailDir + "/" + username;
    std::string msgFile = userDir + "/" + std::to_string(msgNum) + ".txt";
    if (fs::exists(msgFile)) {
        fs::remove(msgFile);
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: ./twmailer-server <port> <mail-spool-directory>\n";
        return EXIT_FAILURE;
    }

    int port = std::stoi(argv[1]);
    std::string mailDir = argv[2];

    MailServer server(port, mailDir);
    server.run();

    return EXIT_SUCCESS;
}
