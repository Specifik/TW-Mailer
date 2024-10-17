# TW-Mailer

# make to create the executables
make

# start the server and connect the client
./server &lt;port&gt; &lt;mail-directory&gt;
./client &lt;ip&gt; &lt;port&gt;

# after the client is connected you can enter the commands example:
Enter command (SEND, LIST, READ, DEL, QUIT): SEND 
Sender: &lt;sender-name&gt;
Receiver: &lt;receiver-name&gt;
Subject: test
Message (end with a single '.'): 
testtesttest
.
OK
Enter command (SEND, LIST, READ, DEL, QUIT):