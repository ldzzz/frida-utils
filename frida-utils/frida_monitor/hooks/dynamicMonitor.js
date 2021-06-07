var classes= ['crypto'];
var methods = ['init']

var data = { 
  'available': Java.available,
  'java_classes': 0
}

if(Java.available){
  Java.performNow(function() {
      var javaClasses = Java.enumerateLoadedClassesSync().filter(cls => classes.some(userCls => cls.includes(userCls)));//.filter(cls => classes.includes(cls));
      console.log('Chosen classes: ' + javaClasses);
      console.log('methods ' + javaClasses[0].$methods);
      javaClasses.forEach(cls => {
        var m = Java.enumerateMethods(cls+'!*init*');//.filter(ms => methods.some(userMethods => ms.includes(userMethods)));
        m.forEach(mtd => {
          mtd['classes'].forEach(e => {
            e['methods'].forEach(f => {
              if(f.indexOf("$") == -1){ 
                console.log('here ' + cls + '.' + f);
                const clsUse = Java.use(cls);
                var lent = clsUse[f].overloads.length;
                for(var i = 0; i < lent;i++) {
                  var tps = clsUse[f].overloads[i].argumentTypes;
                  clsUse[f].overloads[i].implementation = function() {
                    console.log('ENTERED: ' + cls + "." + f); 
                    console.log('TPSÄ '+ JSON.stringify(tps[0]));
                    for (var j=0; j < tps.length; j++) {
                      console.log('in tps '+ j)
                      console.log('CLASS NAME: ' +tps[j]['className']);
                    }                  
                    this[f].apply(this, arguments); // With apply , you can write a method once, and then inherit it in another object, 
                                                    // without having to rewrite the method for the new object. apply is very similar to call() , 
                                                    // except for the type of arguments it supports. You use an arguments array instead of a list of arguments (parameters).
                  }
                }
              }
            });
          });
        });
      });
  });

}
// TODO: cleanup prints
// TODO: print all args based on their cast and object type from tps var up there
// TODO: optimize foreach's
// TODO: change dynamicMonitor -> cryptoMonitor
// TODO: print nicely
// TODO: hook only with a set of user methods
// send data
//send(data);