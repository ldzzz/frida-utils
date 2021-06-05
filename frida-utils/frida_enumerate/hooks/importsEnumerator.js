var appModules = Process.enumerateModules();

var moduleImports = {};

appModules.forEach(element => {
    moduleImports[element.name] = element.enumerateImports();
});

var send_message = {
    'imports': moduleImports,
};

send(send_message);