
var data = {
    'available': Java.available,
    'java_classes': 0
}

if(Java.available){
    Java.performNow(function() {
        var javaClasses = Java.enumerateLoadedClassesSync();
        data['java_classes'] = javaClasses;
    });
}

// send data
send(data);
