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

// https://developer.android.com/reference/android/bluetooth/BluetoothGattCharacteristic#PROPERTY_BROADCAST
const ble_properties = {
    BROADCAST: 0x00000001,
    EXTENDED_PROPS: 0x00000080,
    INDICATE: 0x00000020,
    NOTIFY: 0x00000010,
    READ: 0x00000002,
    SIGNED_WRITE: 0x00000040,
    WRITE: 0x00000008,
    WRITE_NO_RESPONSE: 0x00000004,
}

// We need to convert the ouput to hex from bytes
// thanks: https://awakened1712.github.io/hacking/hacking-frida/
function bytes2hex(array) {
    let result = '';
    for (let i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
};

function parse_props(props) {
    let builder = ""

    for (let prop in ble_properties) {
        if ((ble_properties[prop] & props) == ble_properties[prop]) {
            builder += prop
            builder += " "
        }
    }
    return builder
}

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
    static on_services(gatt) {

        let services = gatt.getServices()
        if (services.size() < 0)
            console.log(colours.fg.blue + "[BLE] [GATT    ] " + colours.reset + "No discovered services");

        console.log(colours.fg.blue + "[BLE] [GATT    ] " + colours.reset + "Discovered services");
        console.log(colours.fg.blue + "[BLE] [GATT    ] " + colours.reset + "------------------------------------");
        let it = services.iterator()
        while (it.hasNext()) {
            let srv = it.next()
            let srv_new = Java.cast(srv, Java.use("android.bluetooth.BluetoothGattService"))
            console.log(colours.fg.blue + "[BLE] [GATT    ] " + colours.reset + srv_new.getUuid())
            let chars = srv_new.getCharacteristics()
            let char_it = chars.iterator()
            while (char_it.hasNext()) {
                let chr = char_it.next()
                let chr_new = Java.cast(chr, Java.use("android.bluetooth.BluetoothGattCharacteristic"))
                let props = chr_new.getProperties()
                let props_new = parse_props(props)
                console.log(colours.fg.blue + "[BLE] [GATT    ]   " + colours.reset + chr_new.getUuid() + " | " + props_new)
            }
            console.log(colours.fg.blue + "[BLE] [GATT    ] " + colours.reset + "------------------------------------");
        }


        //console.log(colours.fg.magenta + "[BLE] [     SRV]"  +  colours.reset + s.getUuid().toString());
    }
}

if (Java.available) {
    BleLogger.info("Starting enumerate script ...")
    Java.perform(function () {
        let ble_gatt_cb = Java.use("android.bluetooth.BluetoothGattCallback");
        ble_gatt_cb.$init.overload().implementation = function () {
            BleLogger.info("android.bluetooth.BluetoothDevice called by " + this.$className);
            let ble_gatt_cb_new = Java.use(this.$className);
            ble_gatt_cb_new.onServicesDiscovered.implementation = function (gatt, status) {
                let retval = ble_gatt_cb_new.onServicesDiscovered.call(this, gatt, status);
                BleLogger.on_services(gatt)
                return retval;
            };

            return this.$init();
        };

    }); // end perform
} else {
    BleLogger.error("Only Android is supported.")
}


