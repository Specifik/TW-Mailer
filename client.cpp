// client.cpp
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <termios.h>  // Include termios for disabling echo

const int BUFFER_SIZE = 1024;

class MailClient {
public:
    MailClient(const std::string& ip, int port)
        : serverIP(ip), serverPort(port), authenticated(false) {}

    void run();

private:
    std::string serverIP;
    int serverPort;
    int sockfd;
    bool authenticated;

    bool connectToServer();
    void interact();
    void sendCommand(const std::string& cmd);
    std::string readResponse();
    bool login();

    std::string getPassword();  // Function to read password without echo
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

std::string MailClient::getPassword() {
    std::string password;
    struct termios oldt, newt;

    // Save old terminal attributes
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    // Disable echo
    newt.c_lflag &= ~(ECHO);

    // Set new terminal attributes
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Read password
    std::getline(std::cin, password);

    // Restore old terminal attributes
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    // Move to the next line after password input
    std::cout << std::endl;

    return password;
}

bool MailClient::login() {
    for (int attempt = 0; attempt < 3; ++attempt) {
        std::string username, password;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        std::cout << "Password: ";

        // Read password without echo
        password = getPassword();

        std::ostringstream cmdStream;
        cmdStream << "LOGIN\n" << username << "\n" << password << "\n";
        sendCommand(cmdStream.str());

        std::string response = readResponse();
        if (response == "OK\n") {
            authenticated = true;
            std::cout << "Login successful.\n";
            return true;
        } else {
            std::cout << "Login failed.\n";
        }
    }
    return false;
}

void MailClient::interact() {
    if (!login()) {
        std::cout << "Failed to login after 3 attempts. Exiting.\n";
        return;
    }

    std::string input;
    while (true) {
        std::cout << "Enter command (SEND, LIST, READ, DEL, QUIT): ";
        std::getline(std::cin, input);

        if (input == "SEND") {
            std::string receiver, subject, messageLine, messageContent;

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
            cmdStream << "SEND\n" << receiver << "\n" << subject << "\n" << messageContent << ".\n";
            sendCommand(cmdStream.str());

            std::string response = readResponse();
            std::cout << response;
        } else if (input == "LIST") {
            sendCommand("LIST\n");
            std::string response = readResponse();
            std::istringstream respStream(response);
            std::string line;
            if (std::getline(respStream, line)) {
                int count = std::stoi(line);
                std::cout << "You have " << count << " messages:\n";
                for (int i = 0; i < count; ++i) {
                    if (std::getline(respStream, line)) {
                        std::cout << i + 1 << ": " << line << "\n";
                    }
                }
            } else {
                std::cout << "Error reading response.\n";
            }
        } else if (input == "READ") {
            std::string msgNum;
            std::cout << "Message Number: ";
            std::getline(std::cin, msgNum);

            std::ostringstream cmdStream;
            cmdStream << "READ\n" << msgNum << "\n";
            sendCommand(cmdStream.str());

            std::string response = readResponse();
            if (response.substr(0, 3) == "OK\n") {
                std::cout << "Message Content:\n" << response.substr(3);
            } else {
                std::cout << "Error reading message.\n";
            }
        } else if (input == "DEL") {
            std::string msgNum;
            std::cout << "Message Number: ";
            std::getline(std::cin, msgNum);

            std::ostringstream cmdStream;
            cmdStream << "DEL\n" << msgNum << "\n";
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
        std::cerr << "Usage: ./client <ip> <port>\n";
        return EXIT_FAILURE;
    }

    std::string ip = argv[1];
    int port = std::stoi(argv[2]);

    MailClient client(ip, port);
    client.run();

    return EXIT_SUCCESS;
}
