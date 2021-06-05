
rpc.exports = {
    setuuid: setuuid
};

var uuid_to_fuzz = "00010203-0405-0607-0809-0a0b0c0d2b10"

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

// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random
function getRandomIntInclusive(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1) + min); //The maximum is inclusive and the minimum is inclusive
}

// https://www.programmersought.com/article/11391532753/
function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
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

    static fuzzer_original(original) {
        console.log(colours.fg.crimson + "[BLE] [FUZZ    ]" + colours.fg.blue + " original: 0x" + bytes2hex(original) + colours.reset);
    }
    static fuzzer_new(new_val) {
        console.log(colours.fg.crimson + "[BLE] [FUZZ    ]" + colours.fg.cyan + " new_val: 0x" + bytes2hex(new_val) + colours.reset);
    }


}



var bt_gatt = null;

if (Java.available) {
    BleLogger.info("Starting enumerate script ...")
    Java.perform(function () {
        let ble_gatt_cb = Java.use("android.bluetooth.BluetoothGattCallback");
        ble_gatt_cb.$init.overload().implementation = function () {
            BleLogger.info("android.bluetooth.BluetoothGattCallback called by " + this.$className);
            let ble_gatt_cb_new = Java.use(this.$className);
            ble_gatt_cb_new.onServicesDiscovered.implementation = function (gatt, status) {
                let retval = ble_gatt_cb_new.onServicesDiscovered.call(this, gatt, status);
                //bt_gatt = Java.cast(gatt, Java.use("android.bluetooth.BluetoothGatt"))
                return retval;
            };

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


                if (uuid_to_fuzz != null) {
                    fuzz_value(chr)
                }

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

function calc_xor(data) {
    let tmp = 0
    for (let i = 0; i < data.length - 1; i++) {
        tmp ^= data[i]
    }
    data[data.length - 1] = tmp
    return data
}

// Ignore first few messages so the connection can be established in app
var ignore_times = 10

function fuzz_value(chr) {
    let uuid = chr.getUuid()
    if (uuid_to_fuzz != uuid.toString()) {
        BleLogger.info("Not the right char, do nothing.")
        return;
    }

    let current_value = chr.getValue()

    if (current_value.length < 0)
        return;

    if (ignore_times > 0) {
        ignore_times--
        return
    }

    BleLogger.fuzzer_original(current_value)
    // Simple random fuzzer POC for this example
    // Choose how many bytes to edit at random
    let num_changes = getRandomIntInclusive(0, (current_value.length / 2))
    let max_len = current_value.length - 1
    // Change number of bytes previously decided
    for (let i = 0; i < num_changes; i++) {
        // Get random index to change
        // Target certain bytes
        let rnd_index = getRandomIntInclusive(2, max_len / 2)
        // Get random value to replace
        let rnd_value = getRandomIntInclusive(2, 254)
        // Replace value with randomlly generated one
        current_value[rnd_index] = rnd_value
    }
    current_value = calc_xor(current_value)
    chr.setValue(current_value)
    BleLogger.fuzzer_new(current_value)
}

function setuuid(uuid) {
    uuid_to_fuzz = uuid
}