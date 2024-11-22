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
#include <thread>
#include <mutex>
#include <ctime>
#include <ldap.h>
#include <arpa/inet.h>

namespace fs = std::filesystem;

const int BUFFER_SIZE = 1024;
const std::string LDAP_HOST = "ldap.technikum.wien.at";
const int MY_LDAP_PORT = 389;
const int MAX_LOGIN_ATTEMPTS = 3;
const int BLACKLIST_DURATION = 60; // in seconds

struct Message {
    std::string sender;
    std::string receiver;
    std::string subject;
    std::string content;
};

struct ClientSession {
    bool authenticated = false;
    std::string username;
    std::string password;
    int loginAttempts = 0;
};

struct ThreadArgs {
    int clientSock;
    sockaddr_in clientAddr;
    class MailServer* server;
};

class MailServer {
public:
    MailServer(int port, const std::string& mailDir)
        : port(port), mailDir(mailDir) {
        if (!fs::exists(mailDir)) {
            fs::create_directory(mailDir);
        }
        loadBlacklist();
    }

    void run();
    void handleClient(int clientSock, sockaddr_in clientAddr);

private:
    int port;
    std::string mailDir;

    std::unordered_map<std::string, time_t> blacklist;
    std::mutex sessionMutex;
    std::mutex fsMutex;

    std::string readLine(int sock);
    void sendResponse(int sock, const std::string& response);
    bool validateUsername(const std::string& username, const ClientSession& session);
    bool authenticateUser(const std::string& username, const std::string& password);
    void saveMessage(const Message& msg);
    std::vector<std::string> listMessages(const std::string& username);
    std::string readMessage(const std::string& username, int msgNum);
    bool deleteMessage(const std::string& username, int msgNum);

    void loadBlacklist();
    void saveBlacklist();
};

void* clientHandler(void* arg) {
    ThreadArgs* threadArgs = (ThreadArgs*)arg;
    int clientSock = threadArgs->clientSock;
    sockaddr_in clientAddr = threadArgs->clientAddr;
    MailServer* server = threadArgs->server;
    delete threadArgs;

    server->handleClient(clientSock, clientAddr);

    close(clientSock);
    pthread_exit(nullptr);
}

void MailServer::run() {
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in serverAddr{};
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
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSock = accept(serverSock, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
        if (clientSock < 0) {
            perror("MailServer::run - Accept failed");
            continue;
        }

        // Launch a new thread for each client
        std::thread(&MailServer::handleClient, this, clientSock, clientAddr).detach();
    }

    close(serverSock);
}

void MailServer::handleClient(int clientSock, sockaddr_in clientAddr) {
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);

    // Session data for this client
    ClientSession session;
    session.loginAttempts = 0;
    session.authenticated = false;

    // Check if client IP is blacklisted
    {
        std::lock_guard<std::mutex> lock(sessionMutex);

        // Clean up expired blacklist entries
        for (auto it = blacklist.begin(); it != blacklist.end(); ) {
            if (it->second <= std::time(nullptr)) {
                it = blacklist.erase(it);
            } else {
                ++it;
            }
        }

        if (blacklist.find(clientIP) != blacklist.end()) {
            sendResponse(clientSock, "ERR\n");
            return;
        }
    }

    while (true) {
        std::string command = readLine(clientSock);
        if (command.empty()) break;

        if (command == "LOGIN") {
            std::string username = readLine(clientSock);
            std::string password = readLine(clientSock);

            if (authenticateUser(username, password)) {
                session.authenticated = true;
                session.username = username;
                session.password = password;
                session.loginAttempts = 0;
                sendResponse(clientSock, "OK\n");
            } else {
                session.loginAttempts++;
                if (session.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                    // Add client IP to blacklist
                    {
                        std::lock_guard<std::mutex> lock(sessionMutex);
                        blacklist[clientIP] = std::time(nullptr) + BLACKLIST_DURATION;
                        saveBlacklist();
                    }
                    sendResponse(clientSock, "ERR\n");
                    return; // Disconnect the client
                } else {
                    sendResponse(clientSock, "ERR\n");
                }
            }
        } else if (session.authenticated) {
            if (command == "SEND") {
                Message msg;
                msg.sender = session.username;
                msg.receiver = readLine(clientSock);
                msg.subject = readLine(clientSock);

                std::ostringstream contentStream;
                std::string line;
                while ((line = readLine(clientSock)) != ".") {
                    contentStream << line << "\n";
                }
                msg.content = contentStream.str();

                if (validateUsername(msg.receiver, session)) {
                    saveMessage(msg);
                    sendResponse(clientSock, "OK\n");
                } else {
                    sendResponse(clientSock, "ERR\n");
                }
            } else if (command == "LIST") {
                auto subjects = listMessages(session.username);
                sendResponse(clientSock, std::to_string(subjects.size()) + "\n");
                for (const auto& subj : subjects) {
                    sendResponse(clientSock, subj + "\n");
                }
            } else if (command == "READ") {
                std::string msgNumStr = readLine(clientSock);
                int msgNum = std::stoi(msgNumStr);
                std::string msgContent = readMessage(session.username, msgNum);
                if (!msgContent.empty()) {
                    sendResponse(clientSock, "OK\n" + msgContent);
                } else {
                    sendResponse(clientSock, "ERR\n");
                }
            } else if (command == "DEL") {
                std::string msgNumStr = readLine(clientSock);
                int msgNum = std::stoi(msgNumStr);
                if (deleteMessage(session.username, msgNum)) {
                    sendResponse(clientSock, "OK\n");
                } else {
                    sendResponse(clientSock, "ERR\n");
                }
            } else if (command == "QUIT") {
                break;
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
    while (true) {
        ssize_t n = recv(sock, &c, 1, 0);
        if (n <= 0) {
            return "";
        }
        if (c == '\n') {
            break;
        }
        line += c;
    }
    return line;
}

void MailServer::sendResponse(int sock, const std::string& response) {
    send(sock, response.c_str(), response.length(), 0);
}

bool MailServer::validateUsername(const std::string& username, const ClientSession& session) {
    std::cout << "Validating username: " << username << "\n";

    LDAP* ldapHandle;
    int rc = ldap_initialize(&ldapHandle, "ldap://ldap.technikum-wien.at:389");
    if (rc != LDAP_SUCCESS) {
        std::cerr << "LDAP initialization failed: " << ldap_err2string(rc) << "\n";
        return false;
    }

    // Set LDAP protocol version to 3
    int ldapVersion = LDAP_VERSION3;
    rc = ldap_set_option(ldapHandle, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
    if (rc != LDAP_OPT_SUCCESS) {
        std::cerr << "ldap_set_option(PROTOCOL_VERSION): " << ldap_err2string(rc) << "\n";
        ldap_unbind_ext_s(ldapHandle, nullptr, nullptr);
        return false;
    }

    // Start TLS session
    rc = ldap_start_tls_s(ldapHandle, nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
        std::cerr << "MailServer::validateUsername - ldap_start_tls_s(): " << ldap_err2string(rc) << "\n";
        ldap_unbind_ext_s(ldapHandle, nullptr, nullptr);
        return false;
    }

    // Bind using the user's credentials
    std::string bindDN = "uid=" + session.username + ",ou=people,dc=technikum-wien,dc=at";

    // Prepare credentials
    BerValue bindCredentials;
    bindCredentials.bv_val = const_cast<char*>(session.password.c_str());
    bindCredentials.bv_len = session.password.length();

    // Perform bind (authentication)
    BerValue* servercredp = nullptr;
    rc = ldap_sasl_bind_s(
        ldapHandle,
        bindDN.c_str(),
        LDAP_SASL_SIMPLE,
        &bindCredentials,
        nullptr,
        nullptr,
        &servercredp);
    if (rc != LDAP_SUCCESS) {
        std::cerr << "MailServer::validateUsername - LDAP bind error: " << ldap_err2string(rc) << "\n";
        ldap_unbind_ext_s(ldapHandle, nullptr, nullptr);
        return false;
    }

    // Perform LDAP search
    std::string baseDN = "dc=technikum-wien,dc=at";
    std::string filter = "(uid=" + username + ")";
    std::cout << "LDAP search base DN: " << baseDN << "\n";
    std::cout << "LDAP search filter: " << filter << "\n";

    LDAPMessage* result = nullptr;
    rc = ldap_search_ext_s(
        ldapHandle,
        baseDN.c_str(),
        LDAP_SCOPE_SUBTREE,
        filter.c_str(),
        nullptr,
        0,
        nullptr,
        nullptr,
        nullptr,
        0,
        &result
    );

    if (rc != LDAP_SUCCESS) {
        std::cerr << "MailServer::validateUsername - LDAP search failed: " << ldap_err2string(rc) << "\n";
        ldap_unbind_ext_s(ldapHandle, nullptr, nullptr);
        return false;
    }

    int entryCount = ldap_count_entries(ldapHandle, result);
    bool userExists = (entryCount > 0);
    std::cout << "LDAP search entry count: " << entryCount << "\n";
    std::cout << "Username " << username << " validation result: " << (userExists ? "valid" : "invalid") << "\n";

    if (result) {
        ldap_msgfree(result);
    }
    ldap_unbind_ext_s(ldapHandle, nullptr, nullptr);

    return userExists;
}

bool MailServer::authenticateUser(const std::string& username, const std::string& password) {
    LDAP *ldapHandle;
    int rc = ldap_initialize(&ldapHandle, "ldap://ldap.technikum-wien.at:389");
    if (rc != LDAP_SUCCESS) {
        std::cerr << "MailServer::authenticateUser - LDAP initialization failed: " << ldap_err2string(rc) << "\n";
        return false;
    }

    // Set LDAP version
    int ldapVersion = LDAP_VERSION3;
    rc = ldap_set_option(ldapHandle, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
    if (rc != LDAP_OPT_SUCCESS) {
        std::cerr << "MailServer::authenticateUser - ldap_set_option(PROTOCOL_VERSION): " << ldap_err2string(rc) << "\n";
        ldap_unbind_ext_s(ldapHandle, NULL, NULL);
        return false;
    }

    // Construct the bind DN
    std::string bindDN = "uid=" + username + ",ou=people,dc=technikum-wien,dc=at";

    // Prepare credentials
    BerValue bindCredentials;
    bindCredentials.bv_val = const_cast<char*>(password.c_str());
    bindCredentials.bv_len = password.length();

    // Perform bind (authentication)
    BerValue* servercredp = nullptr;
    rc = ldap_sasl_bind_s(
        ldapHandle,
        bindDN.c_str(),
        LDAP_SASL_SIMPLE,
        &bindCredentials,
        nullptr,
        nullptr,
        &servercredp);
    if (rc != LDAP_SUCCESS) {
        std::cerr << "MailServer::authenticateUser - LDAP bind error: " << ldap_err2string(rc) << "\n";
        ldap_unbind_ext_s(ldapHandle, nullptr, nullptr);
        return false;
    }

    // Successful authentication
    ldap_unbind_ext_s(ldapHandle, nullptr, nullptr);
    std::cout << "MailServer::authenticateUser - User " << username << " authenticated successfully.\n";
    return true;
}



void MailServer::saveMessage(const Message& msg) {
    std::lock_guard<std::mutex> lock(fsMutex);

    std::string userDir = mailDir + "/" + msg.receiver;
    if (!fs::exists(userDir)) {
        fs::create_directory(userDir);
    }

    int msgNum = std::distance(fs::directory_iterator(userDir), fs::directory_iterator()) + 1;

    std::string msgFile = userDir + "/" + std::to_string(msgNum) + ".txt";
    std::ofstream outfile(msgFile);
    if (outfile.is_open()) {
        outfile << "From: " << msg.sender << "\n";
        outfile << "To: " << msg.receiver << "\n";
        outfile << "Subject: " << msg.subject << "\n";
        outfile << "Date: " << std::time(nullptr) << "\n";
        outfile << "\n" << msg.content;
        outfile.close();
        std::cout << "Message saved to " << msgFile << "\n";
    } else {
        std::cerr << "Failed to open file " << msgFile << " for writing\n";
    }
}

std::vector<std::string> MailServer::listMessages(const std::string& username) {
    std::lock_guard<std::mutex> lock(fsMutex);

    std::vector<std::string> subjects;
    std::string userDir = mailDir + "/" + username;
    if (!fs::exists(userDir)) {
        return subjects;
    }

    for (auto& p : fs::directory_iterator(userDir)) {
        std::ifstream infile(p.path());
        std::string line;
        while (std::getline(infile, line)) {
            if (line.find("Subject: ") == 0) {
                subjects.push_back(line.substr(9));
                break;
            }
        }
    }
    return subjects;
}

std::string MailServer::readMessage(const std::string& username, int msgNum) {
    std::lock_guard<std::mutex> lock(fsMutex);

    std::string userDir = mailDir + "/" + username;
    std::string msgFile = userDir + "/" + std::to_string(msgNum) + ".txt";
    if (!fs::exists(msgFile)) {
        return "";
    }

    std::ifstream infile(msgFile);
    if (!infile.is_open()) {
        return "";
    }

    std::stringstream buffer;
    buffer << infile.rdbuf();
    return buffer.str();
}

bool MailServer::deleteMessage(const std::string& username, int msgNum) {
    std::lock_guard<std::mutex> lock(fsMutex);

    std::string userDir = mailDir + "/" + username;
    std::string msgFile = userDir + "/" + std::to_string(msgNum) + ".txt";
    if (!fs::exists(msgFile)) {
        return false;
    }

    fs::remove(msgFile);
    return true;
}

void MailServer::loadBlacklist() {
    std::lock_guard<std::mutex> lock(sessionMutex);
    std::ifstream infile("blacklist.txt");
    if (!infile.is_open()) return;

    std::string ip;
    time_t until;
    while (infile >> ip >> until) {
        if (until > std::time(nullptr)) {
            blacklist[ip] = until;
        }
    }
    infile.close();
}

void MailServer::saveBlacklist() {
    std::lock_guard<std::mutex> lock(sessionMutex);
    std::ofstream outfile("blacklist.txt");
    if (!outfile.is_open()) return;

    for (const auto& entry : blacklist) {
        outfile << entry.first << " " << entry.second << "\n";
    }
    outfile.close();
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
