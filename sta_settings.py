# Define variables
# SETTINGS is [ (STA_NUMBER, SAVE_RESULTS, SKIP) ]

TEST_SETTINGS_INDEX = 1

SETTINGS = [
            (0, 1, 0),
            (1, 1, 0),
            ]

# Defining the fuzzing MAC address device
AP_MAC  = "28:c6:3f:a8:af:c5"

# Defining the injection interface
IFACE   = "wlan1"

##### BELOW VARIABLES SHOULD NOT BE TWEAKED BY THE USER

STA_NUMBER = SETTINGS[TEST_SETTINGS_INDEX][0]
SAVE_RESULTS = SETTINGS[TEST_SETTINGS_INDEX][1]
SKIP = SETTINGS[TEST_SETTINGS_INDEX][2]

# Defining fuzzing specific variables
STA = [
        ("94:65:2d:ed:34:20", 1),   # ipw3945 Linux
        ('94:65:2d:ed:34:20', 1),
        ][STA_NUMBER]

STA_MAC = STA[0]
REPEAT_TIME = STA[1]

# Tuning listen value (fuzzing speed and false positive rates)
LISTEN_TIME = 60

# Defining the logging file
FNAME = [None, 'audits/sta-%s.session' % (STA_MAC)][SAVE_RESULTS]

# Defining the step value for IE fuzzing (should be odd to reach 255)
STEP    = [1, 3, 15, 17, 51][4]

# Defining the padding value
PADDING = "A"

# Defining truncate option
TRUNCATE = True

# Defining fuzzing specific variables
SSID    = "TEST_KRA"
CHANNEL = "\x01"                # Channel should be the same that real one
