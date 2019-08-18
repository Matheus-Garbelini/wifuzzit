# Define variables
# SETTINGS is [ (AP_NUMBER, SAVE_RESULTS, SKIP) ]

TEST_SETTINGS_INDEX = 0

SETTINGS = [
            (0, 0, 0),
            ]

# Defining the fuzzing MAC address device
STA_MAC = "28:c6:3f:a8:af:c5"

# Defining the injection/monitor interface
# Use airmon-ng
IFACE   = "wlan1mon"

##### BELOW VARIABLES SHOULD NOT BE TWEAKED BY THE USER

AP_NUMBER = SETTINGS[TEST_SETTINGS_INDEX][0]
SAVE_RESULTS = SETTINGS[TEST_SETTINGS_INDEX][1]
SKIP = SETTINGS[TEST_SETTINGS_INDEX][2]

# Defining fuzzing specific variables
AP = [
        ('esp8266', '24:0a:c4:9a:58:28', 1, 'WPA-PSK'),
        ][AP_NUMBER]

SSID = AP[0]
AP_MAC = AP[1]
CHANNEL = chr(AP[2])
AP_CONFIG = AP[3]

# Defining the number of retries when authenticating/associating to the AP
CRASH_RETRIES = 10
DELAY = 1
STATE_WAIT_TIME = 2
DELAY_REBOOT = 10
LOG_LEVEL = 3
CRASH_THRESHOLD = 3
TRUNCATE = True

# Defining the log file
FNAME = [None, 'audits/ap-%s-%s.session' % (AP_MAC, AP_CONFIG)][SAVE_RESULTS]
