var appModules = Process.enumerateModules();

var send_message = {
    'modules': appModules,
};

send(send_message);