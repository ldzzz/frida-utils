// JS Colours: https://stackoverflow.com/questions/9781218/how-to-change-node-jss-console-font-color
// Just some terminal colours for nicer debugging
let colours = {
    reset: "\x1b[0m",
    bright: "\x1b[1m",
    dim: "\x1b[2m",
    underscore: "\x1b[4m",
    blink: "\x1b[5m",
    reverse: "\x1b[7m",
    hidden: "\x1b[8m",

    fg: {
        black: "\x1b[30m",
        red: "\x1b[31m",
        green: "\x1b[32m",
        yellow: "\x1b[33m",
        blue: "\x1b[34m",
        magenta: "\x1b[35m",
        cyan: "\x1b[36m",
        white: "\x1b[37m",
        crimson: "\x1b[38m" // Scarlet
    },
    bg: {
        black: "\x1b[40m",
        red: "\x1b[41m",
        green: "\x1b[42m",
        yellow: "\x1b[43m",
        blue: "\x1b[44m",
        magenta: "\x1b[45m",
        cyan: "\x1b[46m",
        white: "\x1b[47m",
        crimson: "\x1b[48m"
    }
}
// We need to convert the ouput to hex from bytes
// thanks: https://awakened1712.github.io/hacking/hacking-frida/
function bytes2hex(array) {
    let result = '';
    for (let i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
};


class BleLogger {

    // General message
    static info(message) {
        console.log(colours.fg.blue + colours.bright + "[MSG] [INFO    ] " + message + colours.reset)
    }
    static warn(message) {
        console.log(colours.fg.yellow + colours.bright + "[MSG] [WARN    ] " + message + colours.reset)
    }
    static error(message) {
        console.log(colours.fg.red + colours.bright + "[MSG] [ERR     ] " + message + colours.reset)
    }

    // BLE Specific messages
    static on_scan_result(scan_result, _retval) {
        console.log(colours.fg.green + "[BLE] [SCAN    ]" + colours.fg.yellow + scan_result.toString() + colours.reset);
    }

}

if (Java.available) {
    BleLogger.info("Starting scan script ...")
    Java.perform(function () {
        BleLogger.info("Performing ... ")
        // https://developer.android.com/reference/android/bluetooth/le/ScanCallback
        // Find the class that it interesting for us, ScanCallback
        let ble_scan_cb = Java.use("android.bluetooth.le.ScanCallback");
        ble_scan_cb.$init.overload().implementation = function () {

            BleLogger.info("android.bluetooth.le.ScanCallback called by " + this.$className);
            let ble_scan_cb_new = Java.use(this.$className);

            // Override BluetoothGattCallback functions, log their output and return the same retval 
            ble_scan_cb_new.onScanResult.implementation = function (cbType, result) {
                let retval = ble_scan_cb_new.onScanResult.call(this, cbType, result);
                BleLogger.on_scan_result(result)
                return retval;
            };

            return this.$init();
        };

    }); // end perform
} else {
    BleLogger.error("Only Android is supported.")
}


