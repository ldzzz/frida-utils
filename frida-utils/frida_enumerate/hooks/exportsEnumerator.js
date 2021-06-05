var appModules = Process.enumerateModules();

var moduleExports = {};

appModules.forEach(element => {
    moduleExports[element.name] = element.enumerateExports();
});

var send_message = {
    'exports': moduleExports,
};

send(send_message);