#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

const int BUFFER_SIZE = 1024;

class MailClient {
public:
    MailClient(const std::string& ip, int port)
        : serverIP(ip), serverPort(port) {}

    void run();

private:
    std::string serverIP;
    int serverPort;
    int sockfd;

    bool connectToServer();
    void interact();
    void sendCommand(const std::string& cmd);
    std::string readResponse();
};

bool MailClient::connectToServer() {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return false;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);

    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
        perror("Invalid address");
        return false;
    }

    if (connect(sockfd, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Connection failed");
        return false;
    }

    return true;
}

void MailClient::sendCommand(const std::string& cmd) {
    send(sockfd, cmd.c_str(), cmd.length(), 0);
}

std::string MailClient::readResponse() {
    char buffer[BUFFER_SIZE];
    std::string response;
    int bytesRead = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
    if (bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response = buffer;
    }
    return response;
}

void MailClient::interact() {
    std::string input;
    while (true) {
        std::cout << "Enter command (SEND, LIST, READ, DEL, QUIT): ";
        std::getline(std::cin, input);

        if (input == "SEND") {
            std::string sender, receiver, subject, messageLine, messageContent;

            std::cout << "Sender: ";
            std::getline(std::cin, sender);
            std::cout << "Receiver: ";
            std::getline(std::cin, receiver);
            std::cout << "Subject: ";
            std::getline(std::cin, subject);
            std::cout << "Message (end with a single '.'): \n";

            while (true) {
                std::getline(std::cin, messageLine);
                if (messageLine == ".") break;
                messageContent += messageLine + "\n";
            }

            std::ostringstream cmdStream;
            cmdStream << "SEND\n" << sender << "\n" << receiver << "\n" << subject << "\n" << messageContent << ".\n";
            sendCommand(cmdStream.str());

            std::string response = readResponse();
            std::cout << response;
        } else if (input == "LIST") {
            std::string username;
            std::cout << "Username: ";
            std::getline(std::cin, username);

            std::ostringstream cmdStream;
            cmdStream << "LIST\n" << username << "\n";
            sendCommand(cmdStream.str());

            std::string response = readResponse();
            std::cout << response;
        } else if (input == "READ") {
            std::string username, msgNum;
            std::cout << "Username: ";
            std::getline(std::cin, username);
            std::cout << "Message Number: ";
            std::getline(std::cin, msgNum);

            std::ostringstream cmdStream;
            cmdStream << "READ\n" << username << "\n" << msgNum << "\n";
            sendCommand(cmdStream.str());

            std::string response = readResponse();
            std::cout << response;
        } else if (input == "DEL") {
            std::string username, msgNum;
            std::cout << "Username: ";
            std::getline(std::cin, username);
            std::cout << "Message Number: ";
            std::getline(std::cin, msgNum);

            std::ostringstream cmdStream;
            cmdStream << "DEL\n" << username << "\n" << msgNum << "\n";
            sendCommand(cmdStream.str());

            std::string response = readResponse();
            std::cout << response;
        } else if (input == "QUIT") {
            sendCommand("QUIT\n");
            break;
        } else {
            std::cout << "Unknown command.\n";
        }
    }
}

void MailClient::run() {
    if (connectToServer()) {
        interact();
        close(sockfd);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: ./twmailer-client <ip> <port>\n";
        return EXIT_FAILURE;
    }

    std::string ip = argv[1];
    int port = std::stoi(argv[2]);

    MailClient client(ip, port);
    client.run();

    return EXIT_SUCCESS;
}
