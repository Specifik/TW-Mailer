# TW-Mailer

# make to create the executables
make

# start the server and connect the client
./server &lt;port&gt; &lt;mail-directory&gt;<br>
./client &lt;ip&gt; &lt;port&gt;

# after the client is connected you can enter the commands example:
Enter command (SEND, LIST, READ, DEL, QUIT): SEND <br>
Sender: &lt;sender-name&gt;<br>
Receiver: &lt;receiver-name&gt;<br>
Subject: test<br>
Message (end with a single '.'): <br>
testtesttest<br>
.<br>
OK<br>
Enter command (SEND, LIST, READ, DEL, QUIT):