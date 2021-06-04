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
    static on_read(chr, _retval) {
        let uuid = chr.getUuid()
        console.log(colours.fg.green + "[BLE] [READ    ]" + colours.fg.yellow + " UUID: " + uuid.toString() + colours.fg.magenta + " | data: 0x" + bytes2hex(chr.getValue()) + colours.reset);
    }
    static on_write(chr, _retval) {
        let uuid = chr.getUuid()
        console.log(colours.fg.cyan + "[BLE] [WRITE   ]" + colours.fg.yellow + " UUID: " + uuid.toString() + colours.fg.magenta + " | data: 0x" + bytes2hex(chr.getValue()) + colours.reset);
    }
    // This could be both notify and indicate
    static on_changed(chr, _retval) {
        let uuid = chr.getUuid()
        console.log(colours.fg.blue + "[BLE] [CHANGE  ]" + colours.fg.yellow + " UUID: " + uuid.toString() + colours.fg.magenta + " | data: 0x" + bytes2hex(chr.getValue()) + colours.reset);
    }


}

if (Java.available) {
    Java.perform(function () {
        // https://developer.android.com/reference/android/bluetooth/BluetoothGattCallback
        // Find the class that it interesting for us, BluetoothGattCallback
        // then we can log data that is returned and sent to the ble device 
        let ble_gatt_cb = Java.use("android.bluetooth.BluetoothGattCallback");
        ble_gatt_cb.$init.overload().implementation = function () {
            //
            BleLogger.info("android.bluetooth.BluetoothGattCallback called by " + this.$className);
            let ble_gatt_cb_new = Java.use(this.$className);

            // Override BluetoothGattCallback functions, log their output and return the same retval 
            ble_gatt_cb_new.onCharacteristicRead.implementation = function (gatt, chr, status) {
                let retval = ble_gatt_cb_new.onCharacteristicRead.call(this, gatt, chr, status);
                BleLogger.on_read(chr, retval)
                return retval;
            };

            ble_gatt_cb_new.onCharacteristicWrite.implementation = function (gatt, chr, status) {
                let retval = ble_gatt_cb_new.onCharacteristicWrite.call(this, gatt, chr, status);
                BleLogger.on_write(chr, retval)
                return retval;
            };

            ble_gatt_cb_new.onCharacteristicChanged.implementation = function (gatt, chr) {
                let retval = ble_gatt_cb_new.onCharacteristicChanged.call(this, gatt, chr);
                BleLogger.on_changed(chr, retval)
                return retval;
            };

            return this.$init();
        };

    }); // end perform
} else {
    BleLogger.error("Only Android is supported.")
}


