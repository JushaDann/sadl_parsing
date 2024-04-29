import 'package:flutter/material.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart' as pointy;

class SadlTool extends StatelessWidget {
  const SadlTool({super.key});

  final pkV1_128 =
      'MIGXAoGBAP7S4cJ+M2MxbncxenpSxUmBOVGGvkl0dgxyUY1j4FRKSNCIszLFsMNwx2XWXZg8H53gpCsxDMwHrncL0rYdak3M6sdXaJvcv2CEePrzEvYIfMSWw3Ys9cRlHK7No0mfrn7bfrQOPhjrMEFw6R7VsVaqzm9DLW7KbMNYUd6MZ49nAhEAu3l//ex/nkLJ1vebE3BZ2w==';

  final pkV1_74 =
      'MGACSwD/POxrX0Djw2YUUbn8+u866wbcIynA5vTczJJ5cmcWzhW74F7tLFcRvPj1tsj3J221xDv6owQNwBqxS5xNFvccDOXqlT8MdUxrFwIRANsFuoItmswz+rfY9Cf5zmU=';

  final pkV2_128 =
      'MIGWAoGBAMqfGO9sPz+kxaRh/qVKsZQGul7NdG1gonSS3KPXTjtcHTFfexA4MkGAmwKeu9XeTRFgMMxX99WmyaFvNzuxSlCFI/foCkx0TZCFZjpKFHLXryxWrkG1Bl9++gKTvTJ4rWk1RvnxYhm3n/Rxo2NoJM/822Oo7YBZ5rmk8NuJU4HLAhAYcJLaZFTOsYU+aRX4RmoF';

  final pkV2_74 =
      'MF8CSwC0BKDfEdHKz/GhoEjU1XP5U6YsWD10klknVhpteh4rFAQlJq9wtVBUc5DqbsdI0w/bga20kODDahmGtASy9fae9dobZj5ZUJEw5wIQMJz+2XGf4qXiDJu0R2U4Kw==';

  Uint8List decryptData(Uint8List data, {String? license}) {
    final v1 = [0x01, 0xe1, 0x02, 0x45];
    final v2 = [0x01, 0x9b, 0x09, 0x45];
    final header = data.sublist(0, 6);

    String pk128;
    String pk74;

    if (header[0] == v1[0] &&
        header[1] == v1[1] &&
        header[2] == v1[2] &&
        header[3] == v1[3]) {
      pk128 = (pkV1_128);
      pk74 = (pkV1_74);
    } else if (header[0] == v2[0] &&
        header[1] == v2[1] &&
        header[2] == v2[2] &&
        header[3] == v2[3]) {
      pk128 = (pkV2_128);
      pk74 = (pkV2_74);
    } else {
      throw const FormatException('Unknown data version');
    }

    // Convert PEM to RSAPublicKey
    pointy.RSAPublicKey publicKey128 = parsePublicKeyFromPem(pk128);
    pointy.RSAPublicKey publicKey74 = parsePublicKeyFromPem(pk74);

    var all = Uint8List(0);
    var start = 6;

    // Decrypt the blocks with pk128 key
    for (var i = 0; i < 5; i++) {
      var block = data.sublist(start, start + 128);
      all = Uint8List.fromList(all + _processBlock(block, publicKey128));
      start += 128;
    }

    // Decrypt the last block with pk74 key
    var block = data.sublist(start, start + 74);
    all = Uint8List.fromList(all + _processBlock(block, publicKey74));

    return all;
  }

  DrivingLicense parseData(Uint8List data) {
    int index = 0;
    for (int i = 0; i < data.length; i++) {
      if (data[i] == 0x82) {
        index = i;
        break;
      }
    }

    // Section 1: Strings
    var result = readStrings(data, index + 1, 4);

    var vehicleCodes = result[0];
    index = result[1];

    var readResult = readString(data, index);
    var surname = readResult[0];
    index = readResult[1];
    var delimiter = readResult[2];

    readResult = readString(data, index);
    var initials = readResult[0];
    index = readResult[1];

    var prDPCode = '';
    if (delimiter != 0xe0) {
      readResult = readString(data, index);
      prDPCode = readResult[0];
      index = readResult[1];
    }

    readResult = readString(data, index);
    var idCountryOfIssue = readResult[0];

    index = readResult[1];

    readResult = readString(data, index);
    var licenseCountryOfIssue = readResult[0];
    index = readResult[1];

    result = readStrings(data, index, 4);
    var vehicleRestrictions = result[0];

    index = result[1];

    readResult = readString(data, index);
    var licenseNumber = readResult[0];

    index = readResult[1];

    var idNumber = '';
    for (int i = 0; i < 13; i++) {
      idNumber += String.fromCharCode(data[index]);
      index++;
    }

    // Section 2: Binary Data
    var idNumberType = data[index].toString().padLeft(2, '0');
    index++;

    var nibbleQueue = <int>[];
    while (true) {
      var currentByte = data[index];
      index++;
      if (currentByte == 0x57) {
        break;
      }

      nibbleQueue.add(currentByte >> 4);
      nibbleQueue.add(currentByte & 0x0F);
    }

    var licenseCodeIssueDates = readNibbleDateList(nibbleQueue, 4);

    var driverRestrictionCodes =
        '${nibbleQueue.removeAt(0)}${nibbleQueue.removeAt(0)}';

    var prDPermitExpiryDate = readNibbleDateString(nibbleQueue);

    var licenseIssueNumber = '${nibbleQueue.removeAt(0)}${nibbleQueue.removeAt(0)}';

    var birthdate = readNibbleDateString(nibbleQueue);

    var licenseIssueDate = readNibbleDateString(nibbleQueue);

    var licenseExpiryDate = readNibbleDateString(nibbleQueue);

    var genderCode = '${nibbleQueue.removeAt(0)}${nibbleQueue.removeAt(0)}';

    var gender = genderCode == '01' ? 'male' : 'female';

    // Section 3: Image Data
    index += 3;
    var width = data[index];
    index += 2;

    var height = data[index];
    index++;

    return DrivingLicense(
      vehicleCodes: vehicleCodes,
      surname: surname,
      initials: initials,
      prDPCode: prDPCode,
      idCountryOfIssue: idCountryOfIssue,
      licenseCountryOfIssue: licenseCountryOfIssue,
      vehicleRestrictions: vehicleRestrictions,
      licenseNumber: licenseNumber,
      idNumber: idNumber,
      idNumberType: idNumberType,
      licenseCodeIssueDates: licenseCodeIssueDates,
      driverRestrictionCodes: [driverRestrictionCodes],
      prDPermitExpiryDate: prDPermitExpiryDate,
      licenseIssueNumber: licenseIssueNumber,
      birthdate: birthdate,
      licenseIssueDate: licenseIssueDate,
      licenseExpiryDate: licenseExpiryDate,
      gender: gender,
      imageWidth: width,
      imageHeight: height,
    );
  }

  pointy.RSAPublicKey parsePublicKeyFromPem(String pemString) {
    final pemContents = pemString;

    Uint8List derBytes = base64Decode(pemContents);
    final asn1Parser = pointy.ASN1Parser(derBytes);
    final topLevelSeq = asn1Parser.nextObject() as pointy.ASN1Sequence;

    final modulus = topLevelSeq.elements![0] as pointy.ASN1Integer;
    final exponent = topLevelSeq.elements![1] as pointy.ASN1Integer;

    final rsaPublicKey = pointy.RSAPublicKey(
      modulus.integer!,
      exponent.integer!,
    );

    return rsaPublicKey;
  }

  Uint8List _bigIntToUint8List(BigInt number) {
    var bytes = (number.toRadixString(16).length.isOdd
            ? '0${number.toRadixString(16)}'
            : number.toRadixString(16))
        .replaceAllMapped(RegExp(r'..'),
            (match) => String.fromCharCode(int.parse(match.group(0)!, radix: 16)))
        .codeUnits;

    var skip = 0;
    while (skip < bytes.length - 1 && bytes[skip] == 0) {
      skip++;
    }
    return Uint8List.fromList(bytes.sublist(skip));
  }

  Uint8List _processBlock(Uint8List block, pointy.RSAPublicKey publicKey) {
    final input = _uint8ListToBigInt(block);
    final output = input.modPow(publicKey.exponent!, publicKey.modulus!);
    return _bigIntToUint8List(output);
  }

// Helper function to convert Uint8List to BigInt
  BigInt _uint8ListToBigInt(Uint8List data) {
    return BigInt.parse(
        data.fold(
            "",
            (String previousValue, element) =>
                previousValue + element.toRadixString(16).padLeft(2, '0')),
        radix: 16);
  }

  Uint8List hexToUint8List(String hex) {
    var bytes = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      var hexByte = hex.substring(i, i + 2);
      var byte = int.parse(hexByte, radix: 16);
      bytes.add(byte);
    }
    return Uint8List.fromList(bytes);
  }

  String readNibbleDateString(List<int> nibbleQueue) {
    int m = nibbleQueue.removeAt(0);
    if (m == 10) {
      return '';
    }

    int c = nibbleQueue.removeAt(0);
    int d = nibbleQueue.removeAt(0);
    int y = nibbleQueue.removeAt(0);

    int m1 = nibbleQueue.removeAt(0);
    int m2 = nibbleQueue.removeAt(0);

    int d1 = nibbleQueue.removeAt(0);
    int d2 = nibbleQueue.removeAt(0);

    return '$m$c$d$y/$m1$m2/$d1$d2';
  }

  List<String> readNibbleDateList(List<int> nibbleQueue, int length) {
    List<String> dateList = [];

    for (int i = 0; i < length; i++) {
      String dateString = readNibbleDateString(nibbleQueue);
      if (dateString.isNotEmpty) {
        dateList.add(dateString);
      }
    }

    return dateList;
  }

  List<dynamic> readStrings(Uint8List data, int index, int length) {
    List<String> strings = [];
    int i = 0;

    while (i < length) {
      String value = '';
      while (true) {
        int currentByte = data[index];
        index++;

        if (currentByte == 0xe0) {
          break;
        } else if (currentByte == 0xe1) {
          if (value.isNotEmpty) {
            i++;
          }
          break;
        }

        value += String.fromCharCode(currentByte);
      }

      if (value.isNotEmpty) {
        strings.add(value);
      }
      i++;
    }

    return [strings, index];
  }

  List<dynamic> readString(Uint8List data, int index) {
    String value = '';
    int delimiter = 0xe0;

    while (true) {
      int currentByte = data[index];
      index++;

      if (currentByte == 0xe0 || currentByte == 0xe1) {
        delimiter = currentByte;
        break;
      }

      value += String.fromCharCode(currentByte);
    }

    return [value, index, delimiter];
  }

  @override
  Widget build(BuildContext context) {
    throw UnimplementedError();
  }
}

class DrivingLicense {
  final List<String> vehicleCodes;
  final String surname;
  final String initials;
  final String? prDPCode;
  final String idCountryOfIssue;
  final String licenseCountryOfIssue;
  final List<String> vehicleRestrictions;
  final String licenseNumber;
  final String idNumber;
  final String idNumberType;
  final List<String> licenseCodeIssueDates;
  final List<String> driverRestrictionCodes;
  final String? prDPermitExpiryDate;
  final String licenseIssueNumber;
  final String birthdate;
  final String licenseIssueDate;
  final String licenseExpiryDate;
  final String gender;
  final int imageWidth;
  final int imageHeight;

  DrivingLicense({
    required this.vehicleCodes,
    required this.surname,
    required this.initials,
    this.prDPCode,
    required this.idCountryOfIssue,
    required this.licenseCountryOfIssue,
    required this.vehicleRestrictions,
    required this.licenseNumber,
    required this.idNumber,
    required this.idNumberType,
    required this.licenseCodeIssueDates,
    required this.driverRestrictionCodes,
    this.prDPermitExpiryDate,
    required this.licenseIssueNumber,
    required this.birthdate,
    required this.licenseIssueDate,
    required this.licenseExpiryDate,
    required this.gender,
    required this.imageWidth,
    required this.imageHeight,
  });

  Map<String, dynamic> toJson() {
    return {
      'vehicleCodes': vehicleCodes,
      'surname': surname,
      'initials': initials,
      'prDPCode': prDPCode,
      'idCountryOfIssue': idCountryOfIssue,
      'licenseCountryOfIssue': licenseCountryOfIssue,
      'vehicleRestrictions': vehicleRestrictions,
      'licenseNumber': licenseNumber,
      'idNumber': idNumber,
      'idNumberType': idNumberType,
      'licenseCodeIssueDates': licenseCodeIssueDates,
      'driverRestrictionCodes': driverRestrictionCodes,
      'prDPermitExpiryDate': prDPermitExpiryDate,
      'licenseIssueNumber': licenseIssueNumber,
      'birthdate': birthdate,
      'licenseIssueDate': licenseIssueDate,
      'licenseExpiryDate': licenseExpiryDate,
      'gender': gender,
      'imageWidth': imageWidth,
      'imageHeight': imageHeight,
    };
  }
}
