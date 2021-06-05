var appThreads = Process.enumerateThreads();

var send_message = {
    'threads': appThreads,
};

onEnter(log, args, state) {
    console.log("ENTERED");
  };

//send(send_message);


