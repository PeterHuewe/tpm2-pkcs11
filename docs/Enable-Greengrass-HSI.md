# AWS Greengrass IoT Hardware Security Interface: Enable Support for Infineon OPTIGA(TM) TPM SLx 9670

**PLEASE NOTE:** This code / demo is currently in beta status as a public preview.

- It is only tested to a limited extend and might not work as expected.
- It is provided as-is, without any waranty and liability.
- This work is based on https://github.com/tpm2-software/tpm2-pkcs11 and uses the TPM Software Stack from https://github.com/tpm2-software/tpm2-tss (partially sponsored by Infineon).
- The software provides the minimum required functionality for __Greengrass Device Tester 1.3.1__ and __Greengrass IoT 1.8.x and 1.9.x__
- The software has NOT been tested for any additional functionality.
- Especially stress and reliability tests have not been performed!
- The software is *NOT* ready for use in production.

- This repository contains the necessary patches to enable compatibility with AWS Greengrass HSI.
- This repository will contain the latest working version and will be rebased regularly on upstream. Thus force-pushes will occur.


Basic AWS Greengrass knowledge is required. If you never used AWS Greengrass before, please follow the regular Raspberry Pi based tutorial:
https://docs.aws.amazon.com/greengrass/latest/developerguide/gg-gs.html


## Introduction
This software enables the use of an Infineon Optiga(TM) TPM2.0 SLx 9670 to be used as an HSM for AWS Greengrass HSI,
via a PKCS#11 provider.

This document will guide you through the installation and setup of the PKCS#11 provider.

More Details on AWS Greengrass HSI can be found here:
https://docs.aws.amazon.com/greengrass/latest/developerguide/hardware-security.html

### Supported Hardware
The Software has been tested with Infineon TPMs implementing TCG Revision 1.38 or higher, which are

 * Optiga TPM SLB 9670, FW 7.85
 * Optiga TPM SLI 9670, FW 13.11
 * Optiga TPM SLM 9670, FW 13.11

For easier integtation Infineon offers Evaluation Boards (Iridium) for the Optiga TPM, which are compatible with the Raspberry Pi.

Iridium Boards with Optiga TPM SLB 9670 might have a lower firmware (7.40 or 7.63) and may need to be upgraded first.
Iridium Boards with Optiga TPM SLI 9670 and Optiga TPM SLM 9670 should have FW 13.11.

Please refer to eltt2 section below on how to check the version of your TPM.

### Supported Software
This sofware is compatible and tested with AWS IoT Greengrass Core version 1.8.0

Please download and install AWS IoT Greengrass Core version 1.8.0 from
https://docs.aws.amazon.com/greengrass/latest/developerguide/what-is-gg.html#gg-core-download-tab
and extract and install it according to the guide to `/greengrass/`

### Limitations:
Only RSA 2K Keys and ECC_NIST_P256 Keys are supported.

## Preparation and Hardware Setup

- Download latest Raspbian (2018-11) and flash onto SD Card.
- Plugin Optiga TPM SLx 9670 Iridium Board on Raspberry Pi Header.
  - The chips must be facing the outside of the Raspberry Pi.
  - Pin 1 of the Iridium must align with Pin 1 of the Raspberry Pi.
  - Pin 1 is also marked by a rectangular solder pad on the Iridium board.
- Plugin SD Card, Monitor, Keyboard, Mouse into Raspberry Pi and power it up.
- Follow basic Raspberry Pi Setup instructions, especially Wifi and User Password.
- Use 'raspi-setup' to enable SSH and SPI.
- Update your system with `sudo apt update && sudo apt upgrade`.
- Install mandatory packages via `sudo apt install git build-essential`.
- Install latest kernel via `sudo rpi-update`.
- Edit */boot/config.txt* and add the following line:

    ```dtoverlay=tpm-slb9670```

  (this tpm-slb9670 overlay applies to SLB 9670, SLI 9670 and SLM 9670).
- Reboot your Raspberry Pi and check that */dev/tpm0* is available.

## Optional: Check TPM Functionality with eltt2
eltt2 is a small test utility provided by Infineon Technologies AG and is available on github:

    git clone https://github.com/infineon/eltt2
    cd eltt2
    make
    sudo ./eltt2 -g

The output should look similar to this:

    TPM capability information of fixed properties:
    =========================================================
    TPM_PT_FAMILY_INDICATOR:        2.0
    TPM_PT_LEVEL:                   0
    TPM_PT_REVISION:                138
    TPM_PT_DAY_OF_YEAR:             8
    TPM_PT_YEAR:                    2018
    TPM_PT_MANUFACTURER:            IFX
    TPM_PT_VENDOR_STRING:           SLI9670
    TPM_PT_VENDOR_TPM_TYPE:         0
    TPM_PT_FIRMWARE_VERSION:        13.11.4555.0

This means your Optiga TPM works as expected.
It also shows the Firmware Version of the TPM.


## Install TPM Software Stack and Tools
### Install preconditions
    sudo apt -y install autoconf automake libtool pkg-config gcc libssl-dev \
      libcurl4-gnutls-dev libdbus-1-dev libglib2.0-dev autoconf-archive libcmocka0 \
      libcmocka-dev net-tools build-essential git pkg-config gcc g++ m4 libtool \
      automake libgcrypt20-dev libssl-dev uthash-dev autoconf doxygen pandoc \
      libsqlite3-dev python-yaml p11-kit opensc gnutls-bin libp11-kit-dev \
      python3-yaml cscope

    sudo apt-get build-dep libengine-pkcs11-openssl1.1

### Download Repositories
    git clone https://github.com/tpm2-software/tpm2-tss
    git clone https://github.com/tpm2-software/tpm2-tools
    git clone https://github.com/tpm2-software/tpm2-abrmd
    git clone https://github.com/tpm2-software/tpm2-pkcs11
    git clone https://github.com/OpenSC/libp11.git


### Install libp11 in a recent version
Unfortunately the version of libp11 pkcs11 engine for openssl provided on Rasbian Stretch is too old (0.4.4) and not compatible with this software.
So we have to install it manually from the repositories.

Compile and install the correct version:

    cd libp11
    git checkout libp11-0.4.9
    ./bootstrap
    ./configure
    make -j4
    sudo make install
    cd ..


### Install tpm2-tss
    cd tpm2-tss
    git checkout 740653a12e203b214cba2f07b5395ffce74dfc03
    ./bootstrap
    ./configure --with-udevrulesdir=/etc/udev/rules.d --with-udevrulesprefix=70-
    make -j4
    sudo make install
    sudo useradd --system --user-group tss
    sudo udevadm control --reload-rules && sudo udevadm trigger
    sudo ldconfig
    cd ..

### Install tpm2-abrmd
    cd tpm2-abrmd
    git checkout 2.2.1
    ./bootstrap
    ./configure --with-dbuspolicydir=/etc/dbus-1/system.d \
      --with-systemdsystemunitdir=/lib/systemd/system \
      --with-systemdpresetdir=/lib/systemd/system-preset \
      --datarootdir=/usr/share
    make -j4
    sudo make install
    sudo ldconfig
    sudo pkill -HUP dbus-daemon
    sudo systemctl daemon-reload
    sudo systemctl enable tpm2-abrmd.service
    sudo systemctl start tpm2-abrmd.service
    dbus-send --system --dest=org.freedesktop.DBus --type=method_call \
      --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames \
      | grep "com.intel.tss2.Tabrmd" || echo "ERROR: abrmd was not installed correctly!"
    cd ..

### Install tpm2-tools
    cd tpm2-tools
    git checkout 3e8847c9a52a6adc80bcd66dc1321210611654be
    ./bootstrap
    ./configure
    make -j4
    sudo make install
    cd ..

### Install tpm2-pkcs11
    sudo mkdir -p /opt/tpm2-pkcs11
    sudo chmod 777 /opt/tpm2-pkcs11
    wget https://github.com/autoconf-archive/autoconf-archive/archive/v2018.03.13.tar.gz
    tar -xvf v2018.03.13.tar.gz
    cp -r autoconf-archive-2018.03.13/m4/ tpm2-pkcs11/
    cd tpm2-pkcs11/
    git checkout a82d0709c97c88cc2e457ba111b6f51f21c22260
    ./bootstrap -I m4
    ./configure --enable-esapi-session-manage-flags --with-storedir=/opt/tpm2-pkcs11
    make -j4
    sudo make install
    cd ..


## Using the PKCS11 Provider for Greengrass HSI.

In this example, the keystore is created under /opt/tpm2-pkcs11.
It is assumed, that the location is read-/writeable to the user.

### Initializing Keystore and Token
    cd tpm2-pkcs11/tools/

#### Init Keystore
    ./tpm2_ptool.py init --pobj-pin=123456 --path=/opt/tpm2-pkcs11/

The used options are:

    --pobj-pin POBJ_PIN   The authorization password for adding secondary objects under the primary object.
    --path PATH           The location of the store directory.


#### Init Token
    ./tpm2_ptool.py addtoken --pid=1 --pobj-pin=123456 --sopin=123456 --userpin=123456 --label=greengrass --path=/opt/tpm2-pkcs11/

The used options are:

      --pid PID             The primary object id to associate with this token.
      --sopin SOPIN         The Administrator pin. This pin is used for object recovery.
      --userpin USERPIN     The user pin. This pin is used for authentication for object use.
      --pobj-pin POBJ_PIN   The primary object password. This password is use for authentication to the primary object.
      --label LABEL         A unique label to identify the profile in use, must be unique.
      --path PATH           The location of the store directory.


#### Add a key:
    ./tpm2_ptool.py addkey --algorithm=rsa2048 --label=greengrass --userpin=123456 --key-label=greenkey --path=/opt/tpm2-pkcs11/

The used options are

    --id ID               The key id. Defaults to a random 8 bytes of hex.
    --sopin SOPIN         The Administrator pin.
    --userpin USERPIN     The User pin.
    --label LABEL         The tokens label to add a key too.
    --algorithm {rsa2048,ecc256}
                          The type of the key. Only RSA 2048 and ECC 256 are supported.
    --key-label KEY_LABEL
                          The key label to identify the key. Defaults to an integer value.
    --path PATH           The location of the store directory.

#### Find out the P11/PKCS#11 URL
Greengrass and other tools use a pkcs11 url to find the token/key object.
This URL can be determined using `p11tool`:

    p11tool --list-token-urls

This will yield a result similar to:

    pkcs11:model=p11-kit-trust;manufacturer=PKCS%2311%20Kit;serial=1;token=System%20Trust
    pkcs11:model=SLI9670;manufacturer=Infineon;serial=0000000000000000;token=greengrass

The URL for the private key can then be determined using:

    p11tool --list-privkeys pkcs11:manufacturer=Infineon
    Object 0:
        URL: pkcs11:model=SLI9670;manufacturer=Infineon;serial=0000000000000000;token=greengrass;id=%37%33%61%36%62%30%31%37%39%66%39%33%39%38%62%38;object=greenkey;type=private
        Type: Private key
        Label: greenkey
        Flags: CKA_NEVER_EXTRACTABLE; CKA_SENSITIVE;
        ID: 37:33:61:36:62:30:31:37:39:66:39:33:39:38:62:38


The URL can be trimmed of certain components, as long as it remains unique, e.g.

    pkcs11:model=SLI9670;manufacturer=Infineon;token=greengrass;object=greenkey;type=private

The Pin can be appended to the URL:

    pkcs11:model=SLI9670;manufacturer=Infineon;token=greengrass;object=greenkey;type=private;pin-value=123456

This will be the URL we will use for the Greengrass configuration.


#### Generate a Certificate Signing Request

    openssl req -engine pkcs11 -new -key "pkcs11:model=SLI9670;manufacturer=Infineon;token=greengrass;object=greenkey;type=private;pin-value=123456" -keyform engine -out /tmp/req.csr

Please answer the questions OpenSSL is asking you for the Certificate Signing Request - these information will be incorporated into the certificate.

Once completed, login to AWS and navigate to the AWS IoT Section.

Under the `Security -> Certificates` tab on the left menu, create a new certificate (Right upper corner `create`).

In the menu chose `Create with CSR` and select the `.csr` file you created using openssl. (e.g. `/tmp/req.csr`)

Download the `root.ca.crt` and the resulting `xxxxxx-certificate.pem.crt`, where _xxxxxx_ stands for a unique id, and copy both to `/greengrass/certs/`

Before closing the window, please be sure to activate the certificate and attach it to an object/policy in the dialogue on the AWS Greengrass Security Page.


#### Configure and run Greengrass with HSI
To enable and use the TPM as HSI, we need to enable it in the greengrass config.
For this we need to edit `/greengrass/config/config.json` and replace the configuration with the following content:
```yaml
    {
        "crypto": {
            "caPath": "file:///greengrass/certs/root.ca.crt",
            "PKCS11": {
                "OpenSSLEngine": "/usr/lib/arm-linux-gnueabihf/engines-1.1/pkcs11.so",
                "P11Provider": "/usr/lib/arm-linux-gnueabihf/pkcs11/libtpm2_pkcs11.so",
                "SlotLabel": "greengrass",
                "SlotUserPin": "123456"
            },
            "principals": {
                "IoTCertificate": {
                    "certificatePath": "file:///greengrass/certs/_xxxxxx_-certificate.pem.crt",
                    "privateKeyPath": "pkcs11:model=SLI9670;manufacturer=Infineon;token=greengrass;object=greenkey;type=private;pin-value=123456"

                },
                "MQTTServerCertificate": {
                    "certificatePath": "file:///greengrass/certs/_xxxxxx_-certificate.pem.crt",
                    "privateKeyPath": "pkcs11:model=SLI9670;manufacturer=Infineon;token=greengrass;object=greenkey;type=private;pin-value=123456"
                }
            }
        },
        "coreThing" : {
            "thingArn" : "arn:aws:iot:eu-central-1:ZZZZZZZZZZZZZZZ:thing/Greengrass-Test_Core",
            "iotHost" : "YYYYYYYYYYYYYYY.iot.eu-central-1.amazonaws.com",
            "ggHost" : "greengrass.iot.eu-central-1.amazonaws.com",
            "keepAlive" : 600
        },
        "runtime" : {
            "cgroup" : {
                "useSystemd" : "yes"
            }
        },
        "managedRespawn" : false
    }
```

Please adjust the `certificatePath`, `privateKeyPath`, `thingArn` and `iotHost` accordingly.

After this you can start your greengrass daemon as usual:

    cd /greengrass/ggc/core
    sudo ./greengrassd start

## Troubleshooting
### Greengrass is not starting
Please validate that your environment is prepared for Greengrass (especially memory cgroups are on), by following the regular greengrass tutorials without hsi.

Please also validate that the permissions and user groups are set up correctly.

### /dev/tpm0 is not showing up
Please make sure that you are running the latest kernel from `rpi-update`, that the SPI support is turned on using `raspi-setup` and that the overlay is enabled in `/boot/config.txt`

Please also ensure that the Iridium board is plugged in correctly.

### Debug PKCS11 Provider
In order to enable more verbose logging an environment variable can be set:

    TPM2_PKCS11_LOG_LEVEL=2

Also the pkcs11-spy from libp11 can be used to get a deeper understanding of the PKCS#11 calls.


## In case of further questions:
Please raise an issue on github or contact me via peter.huewe@infineon.com













