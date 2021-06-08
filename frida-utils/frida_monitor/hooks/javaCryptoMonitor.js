var uClasses = ['crypto'];
var uMethods = ['init'];
//var uArgInfo = [{'class': 'AndroidKeyStoreRSAPublicKey', 'info_to_get': ['getAlgorithm()']}]

var data = { 
  'available': Java.available,
  'java_classes': 0
}

// extract methods by name, based on user-provided methods list
function extractMethods(m) {
  var eMethods = [];
  m.forEach(e => {
    e['classes'].forEach(c => {
      var mFound = c['methods'].filter(ms => uMethods.includes(ms));
      eMethods = eMethods.concat(mFound);
    })
  })

  return eMethods;
}

function getAttachDetails(cls, f, aTypes) {
  var argS = "(";
  aTypes.forEach(e => {
    argS += e['className'] + ", ";
  })
  argS = argS.slice(0, -2);
  argS += ")";
  return ('Attaching to: ' + cls + "." + f + argS);
}

if(Java.available){
  Java.performNow(function() {
    var javaClasses = Java.enumerateLoadedClassesSync().filter(cls => uClasses.some(userCls => cls.includes(userCls)));//.filter(cls => classes.includes(cls));
    javaClasses.forEach(cls => {
      var m = Java.enumerateMethods(cls+'!*'); // find all methods from given class
      var cMethods = extractMethods(m);
      cMethods.forEach(f => {
        // use this class implementation
        const clsUse = Java.use(cls);
        for(var i = 0; i < clsUse[f].overloads.length;i++) {    // for every method we can overload (varying amount of parameters)
          var argTypes = clsUse[f].overloads[i].argumentTypes;  // get argument Types of the method we want to overload currently
          var details = getAttachDetails(cls, f, argTypes); // just some more info
          send({'attach': details});
          clsUse[f].overloads[i].implementation = function() {  // overload implementation to log function call and its args
            var event_data = {
              'name': `${cls}.${f}`,
              'args': []
            }

            // get argument instance types
            for (var j=0; j < argTypes.length; j++) {
              event_data['args'].push(arguments[j]);
            }

            send(event_data);               
            this[f].apply(this, arguments); // With apply , you can write a method once, and then inherit it in another object, 
                                            // without having to rewrite the method for the new object. apply is very similar to call() , 
                                            // except for the type of arguments it supports. You use an arguments array instead of a list of arguments (parameters).
          }
        }
      });
    });
  });
}

// TODO: print all args based on their cast and object type from tps var up there
// TODO: print nicely
// TODO: hook only with a set of user methods