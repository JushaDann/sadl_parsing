<!--
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/guides/libraries/writing-package-pages).

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-library-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/developing-packages).
-->

## Features

- Decrypt and parse the contents of the South African Driver's license.
- Receive all data back in a Driver's License Class

## Getting started

You will need a way to scan the license itself. This package simply decrypts and parses the raw binary data.

## Usage
 Firstly, create a Uint8List from the raw data you got from scanning the PDF417 barcode.
 You can then call the tool to parse and decrypt the data.

 All data is kept in a class called DriversLicense.

DrivingLicense? drivingLicense;

try {
       
        final String iso = call.arguments;
        Uint8List data = Uint8List.fromList(iso.codeUnits);


        final licenseInfoDecrypted = const SadlTool().decryptData(data);
        final licenseInfo = const SadlTool().parseData(licenseInfoDecrypted); 
        drivingLicense = licenseInfo;       
        print(drivingLicense.birthdate);

          } catch (e) {
            print('parsing or decryption failed');
            }

## Additional information

Feel free to submit pull requests.
Photo is not working, that is the last thing I need to figure out how to get working.
