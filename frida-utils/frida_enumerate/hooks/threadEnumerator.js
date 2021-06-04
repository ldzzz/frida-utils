var appThreads = Process.enumerateThreads();

var send_message = {
    'threads': appThreads,
};

send(send_message);