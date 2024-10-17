# TW-Mailer

# make to create the executables
make

# start the server and connect the client
./server <port> <mail-directory>
./client <ip> <port>

# after the client is conncected you can enter the commands example:
Enter command (SEND, LIST, READ, DEL, QUIT): SEND 
Sender: <sender-name>
Receiver: <receiver-name>
Subject: test
Message (end with a single '.'): 
testtesttest
.
OK
Enter command (SEND, LIST, READ, DEL, QUIT):