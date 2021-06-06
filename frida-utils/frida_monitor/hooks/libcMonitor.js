// lets search for common shared lib
var myModule = Process.getModuleByName('libc.so');
var myFuncs = ['recv', 'send'];

// attach only to functions that have recv or send in name (includes recv, recvmsg, recvfrom, send ,sendmsg, sendto)
myModule.enumerateExports().filter(module_export => module_export.type === 'function' && myFuncs.some(fName => module_export.name.includes(fName)))
.forEach(module_export => {
  Interceptor.attach(module_export.address, {
    onEnter: function (args) { // every time we enter one of the functions, we will log this
      //get function args
      var fd = args[0].toInt32(); // every function has first argument an FD, so it is safe to do this

      // error mitigation checks
      // from frida.Socket (check if socket is TCP and if it has an external IP address)
      var socktype = Socket.type(fd); 
      var sockaddr = Socket.peerAddress(fd);
      if ((socktype !== 'tcp' && socktype !== 'tcp6') || sockaddr === null)
        return;

      try {
        var len = args[2].toInt32(); 
        var buf = Memory.readByteArray(args[1], len);
        var data = {
          'event': module_export.name,
          'fd': fd,
          'sockaddr': sockaddr,
          'socktype': socktype,
          'buffer': bytesToHex(buf)
        }

        send(data); // send to Python callback for parsing and printing
      }
      catch(err) {
        console.log("Something went wrong");
      }
    }
  })
})


function buf2hex(buffer) { // buffer is an ArrayBuffer
	var ha = new Uint8Array(buffer);
	return ha.map(x => x.toString(16).padStart(2, '0')).join('');
  }

  function bytesToHex(bytes) {
    var barray = new Uint8Array(bytes);
    for (var hex = [], i = 0; i < barray.length; i++) { 
        hex.push(((barray[i] >>> 4) & 0xF).toString(16).toUpperCase());
        hex.push((barray[i] & 0xF).toString(16).toUpperCase());
        hex.push(" ");
    }
    return hex.join("");
}