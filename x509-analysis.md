X.509 Certificate Analysis
==========================

Introduction
------------

This document represents an analysis of a real X.509 certificate, byte by
byte.

There is a lot of documentation on X.509, ASN.1 and DER. You could even
say, too much. If you want to learn what a certificate contains and you
have not done it before, it can be intimidating. You don't know where to
start and you don't want to spend weeks reading before you can dive into
a certificate. I know, I was in that position. That is why I wrote this, so you
have a starting point. Also as a reference that I can come back to in
a year or two, to refresh my memory.

We take one real certificate (that happens to be Google's)
and break it apart to see what it's made of.

NOTE: in the following text, we work with numbers encoded in decimal,
hexadecimal (hex) and binary. In order to distinguish them, generally we
represent decimal as 134(10), hexadecimal as 86(16) or 0x86 and binary as
10000110(2) or just 10000110 if there is no ambiguity. Generally when we
are showing a byte sequence, it is shown in hex, unless we explicitly
say otherwise, so the following is a byte sequence:

02 08 20 3f 89 1f c8 b6 29 20

which consists of hex numbers 02(16), 08(16), 20(16) etc.

References
----------

I cannot possibly write all the details of X.509 and ASN.1. And besides, it
has already been done. So I will have to give you pointers to documents on
the Net with more information, in case you want to dig deeper.

ASN.1: Wikipedia page is a good starting point:
https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One

X.509 is Internet X.509 Public Key Infrastructure Certificate and
Certificate Revocation List (CRL) Profile:
https://datatracker.ietf.org/doc/rfc5280/?include_text=1

X.509, ASN.1, BER, DER:
A Layman's Guide to a Subset of ASN.1, BER, and DER
http://luca.ntop.org/Teaching/Appunti/asn1.html

DER Encoding of ASN.1 types:
https://msdn.microsoft.com/en-us/library/windows/desktop/bb648640%28v=vs.85%29.aspx

There is lots more out there on the Web, feel free to go search.


Useful Web Sites
----------------

Object identifier repository:
http://www.oid-info.com

ASN.1 for PKIX (Public-Key Infrastructure – X.509)
as defined in RFC 5280:
http://www.in2eps.com/fo-pkix/tk-fo-pkix-asn1.html

Certificate extensions:
https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2012/CertificateExtensions.html

Online ASN.1 JavaScript decoder:
https://lapo.it/asn1js/


Tools That I Used
-----------------

- openssl - for parsing a certificate
- xxd - for viewing a binary file
- Wireshark is very useful for analyzing a certificate that a web server
  sends back to the client in the negotiation phase, in a Certificate
  message
- Online JavaScript decoder - for parsing a DER file

I opened www.google.com in the browser and saved Google's certificate from
the browser to a file google.com.pem. Then I converted the file from PEM
to DER format using this command:

openssl x509 -inform PEM -outform DER -in google.com.pem -out myfile.der

(DER format is the actual certificate, a DER-encoded ASN.1 object. PEM format
is base64-encoded certificate, with lines "BEGIN CERTIFICATE" and "END
CERTIFICATE" inserted before and after.)

You can let openssl utility parse the certificate for you with the command

openssl x509 -in google.com.pem -text

(This works because PEM is the default format. You can also parse a certificate
in DER format with adding -inform DER.)

I use xxd for looking at binary files:

xxd google.com.der

which produces output like this:

0000000: 3082 06eb 3082 05d3 a003 0201 0202 0820  0...0.......... 
0000010: 3f89 1fc8 b629 2030 0d06 092a 8648 86f7  ?....) 0...*.H..
0000020: 0d01 010b 0500 3049 310b 3009 0603 5504  ......0I1.0...U.
0000030: 0613 0255 5331 1330 1106 0355 040a 130a  ...US1.0...U....
0000040: 476f 6f67 6c65 2049 6e63 3125 3023 0603  Google Inc1%0#..
...
...
00006c0: b1e7 b627 13fa dc5e b9dd eff6 a4cb 1326  ...'...^.......&
00006d0: e449 5aee 4efc 9fa1 ac61 f880 3708 4002  .IZ.N....a..7.@.
00006e0: 2964 a345 b099 f3cc 891e f9eb bec8 75    )d.E..........u

This is the format that I used to analyzed the certificate byte by
byte, starting with the first 30 and ending with the final 75.


ASN.1
-----

It stands for Abstract Syntax Notation. This is a nice idea in theory, but
it has grown so complex that it is not easy to learn and that is probably
it is not popular any more.

The basic idea is to have a standard notation to describe the structure
of a file or message. This notation defines elements, such as integers,
strings and object identifiers and rules for combining elements into more
and more complex structures. The notation is completely separate from
its representations: there are several ways to map a data structure into
a representation. These mappings are called encoding rules.

Let's see an example. Since we are dealing with certificates, here is
how a certificate is defined:

Certificate  ::=  SEQUENCE  {
  tbsCertificate       TBSCertificate,
  signatureAlgorithm   AlgorithmIdentifier,
  signatureValue       BIT STRING  }

What this says is that a Certificate is a SEQUENCE, which is similar
to a C struct. That SEQUENCE consists of three parts: tbsCertificate,
which has type TBSCertificate (I believe this stands for
to-be-signed certificate), signatureAlgorithm of type AlgorithmIdentifier,
and signatureValue of type BIT STRING.

Then further TBSCertificate is defined like this:

TBSCertificate  ::=  SEQUENCE  {
  version         [0]  EXPLICIT Version DEFAULT v1,
  serialNumber         CertificateSerialNumber,
  signature            AlgorithmIdentifier,
  issuer               Name,
  validity             Validity,
  subject              Name,
  subjectPublicKeyInfo SubjectPublicKeyInfo,
  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    -- If present, version MUST be v2 or v3
  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    -- If present, version MUST be v2 or v3
  extensions      [3]  EXPLICIT Extensions OPTIONAL
    -- If present, version MUST be v3
  }

This definition says that TBSCertificate is a SEQUENCE that contains
version, serialNumber, signature and so on.


DER
---

DER stands for Distinguished Encoding Rules and it is the ASN.1 encoding
that is used for encoding a certificate. It is a subset of BER, but such
that for any ASN.1 data structure there is exactly one way to encode it
in DER.

In DER every ASN.1 element, primitive or composed, is encoded as a TLV
triplet, where TLV stands for Tag-Length-Value.

Here's a simple example, integer 2:

02 01 02

The first byte 02 is the tag for integer. The second byte, 01, is the
length of the value part. The value part contains just one byte, with
the value 02.

That is actually not the simplest example - the simplest example is
NULL:

05 00

The tag for NULL is 05 and the length of the value part is 00.


Length
------

We need to describe how the length of a TLV triplet is encoded. For a
length that is between 0 and 127, one byte is enough. For example,
100 is 64(16) and it can be encoded with one byte.

If the length is 128 or more, then it need to be encoded in multiple
bytes, first of which encodes how many bytes after the first contain
the length. As the simplest example, 128 is encoded like this:

81 80

81(16), which is written as 10000001 in binary numbers, means that
there is one byte of length following. The highest bit of this byte
is 1, which means that the byte encodes the number of following bytes
that encode the length.

129 would be encoded as 81 81.

To take an example from the certificate, the top-level SEQUENCE has
the length part which looks like this:

82 06 eb

82 means that there are two bytes for the length, and the bytes are

06 eb

which is 06eb(16), or 1771(10). That is the length of the whole remainder
of the certificate after the initial 4 bytes, which are

30 82 06 eb

(30 is the tag for a SEQUENCE and 82 06 eb is the encoded length.)

Note that there are always multiple ways to encode the same length, but
DER by definition always uses the shortest one. So, for example 127
can be encoded as 7f, but also as 81 7f or 82 00 7f etc. But in DER,
only the first one, 7f, is valid.


Primitive Types
------------

ASN.1 has a number of primitive types. Here we list the primitive types used in
X.509 certificates and their DER encoding.

- INTEGER is encoded with tag 02. Example from the certificate we are
analyzing:

02 08 20 3f 89 1f c8 b6 29 20 - INTEGER with length 08 and value
203f891fc8b62920(16)

06 09 2a 86 48 86 f7 0d 01 01 0b - OBJECT IDENTIFIER (tag 06) with length 09
and value 2a864886f70d01010b. We describe how to read an OBJECT IDENTIFIER
in the next section.

- Strings come in several varieties, of which we will see the following in
our certificate:
  - PrintableString is encoded with tag 13(16):
  
  13 02 55 53 is the encoding of "US" - 13(16) is the tag, 02 is the length
  of the value part and the value is 55 53, which are ASCII coded for 'U'
  and 'S'.

  - UTF8String is encoded with tag 0c(16):
  
  0c 0a 43 61 6c 69 66 6f 72 6e 69 61 is the encoding of "California"

There are other types of string in ASN.1, but we will not encounter them in
our certificate.

- BIT STRING is encoded with tag 03. It is an array of bits of any length and
  padding is appended at the end to make it an even number of bytes. The
  first byte of value is the number of padding bits. Here's an example:

03 02 07 80

Here 03 is the tag, 02 is the length, 07 is the number of padding bits. The
bits of the bit string are encoded in the byte 80, which in binary is

10000000

The last 7 bits are the padding, so this bit string contains only one bit,
which has the value 1.

As another example, a public key is encoded as a bit string:

03 42 00 04 da 15 df a8 21 8a 6a dc 69 d9 4d c6
b8 e3 3b 2a 92 26 62 41 94 9a 81 79 fc 9c 3f 3f
65 b0 94 a1 f9 31 b4 0b 79 14 eb ea 95 13 5b d5
b5 26 e5 57 4e ef 89 11 fb 51 0c 2d 23 4e 4e 62
74 9f 5b 79

Here, the length is 42(16) or 66(10). The fist byte of the value is
00, which means there are 0 padding bits at the end. The actual bits
of the bit string are encoded in the 65 bytes that follow, starting
with 04(16) and ending with 79(16).

- OCTET STRING is encoded with tag 04. The value is simply an array
of bytes, for example:

04 04 03 02 07 80

Here the tag is 04, the length is 04 and the value contains 4 bytes,
03 02 07 80. Because this example was taken from the certificate, it
so happens that the value has a structure (it is a BIT STRING), but
that is not a general requirement for an OCTET STRING, which is simply
an array of bytes.

- BOOLEAN is encoded with tag 01, length 01 and one byte of value, which is
00 for FALSE and ff for TRUE. Again, DER does not allow multiple ways of
encoding the same value (unlike its superset BER), so all other values are
illegal.

- NULL is encoded with tag 05 and it has only one encoding: 05 00 (as we
have already seen).

- UTCTime is encoded with tag 17 and it encoded Coordinated Universal Time.
Its value consists of 13 bytes that encode the Greenwich Mean Time in the
format YYMMDDhhmmssZ, for example bytes

17 0d 31 35 31 30 32 38 31 38 35 32 31 32 5a

encode string

"151028185212Z",

which represents this time:

2015-10-28 18:52:12

('Z' is literally ASCII code for capital letter Z, which apparently stands
for Zulu time.)

Notice that the year is encoded as only two ASCII characters: numbers
"00" - "50" mean years 2000 - 2050, and numbers "51" - "99" mean years
1951 - 1999.

There is also a way to represent time in a different time zone, for example
in the format YYMMDDhhmm+hh'mm' the part +hh'mm' means in a time zone so
many hours and minutes after GMT. However, the certificate that we are
analyzing does not contain anything like that. By the way, the only two
times in the certificate are the "not before" and "not after" times for
the certificate validity period.


Object Identifiers
------------------

We saw an example of an object identifier in the previous section:

    06 09 2a 86 48 86 f7 0d 01 01 0b

When this is decoded, it becomes 1.2.840.113549.1.1.11.

How do we decode the value? It is actually weird, but after you have seen it
a few times, which we will in course of analyzing the certificate, you will
get used to it.

The first byte is special and is decoded in a different way from the rest.
Here the first byte is 2a or 42(10). This is 1*40 + 2, so the first two numbers
in the object identifier are 1 and 2.

Next, we take bytes with the most significant bit 1 and stop when we find a byte
with the most significant bit 0. In this case:

86 48

These bytes, when converted to binary, give us

10000110 01001000

Next, we remove the most significant bit from each byte:

0000110 1001000

After we concatenate these bits and padd two 0s on the left to make it two bytes,
we get:

00000011 01001000

which is 0348(16) or 840(10).

The next three bytes are

86 f7 0d

We go through the same steps again:

10000110 11110111 00001101 -> 0000110 1110111 0001101 -> 000011011101110001101
-> 00001 10111011 10001101 -> 00000001 10111011 10001101 -> 1 bb 8d(16) ->
1bb8d(16) -> 113549(10)

The remaining three bytes, 01 01 0b, all have 0 as the most significant bit,
so they are three numbers, 1, 1, and 11. That gives are the OID

1.2.840.113549.1.1.11

In order to find what this OID means, we can use web site
http://http://www.oid-info.com. There is a box with the label Display OID, and
we copy-paste our OID to the text box. After we click on the Go button, the
web app gives us the meaning of our OID. Here it is in  the ASN.1 notation:

{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1)
sha256WithRSAEncryption(11)}

So this OID encodes the signature algorithm SHA256 with RSA encryption.


Structured Types
----------------

Structured types are types that contain components, which are either primitive
types or structured types. In ASN.1 there are four structured types: SEQUENCE,
SEQUENCE OF, SET and SET OF.

SEQUENCE is a collection of one or more types. SEQUENCE OF is a collection of
zero or more occurrences of another type. In DER they both have the same tag,
30.

SEQUENCE is by far the most common in X.509 certificates. Here is an example:

30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00

This decodes to

SEQUENCE (length 0d(16) = 13(10))
  OBJECT IDENTIFIER 1.2.840.113549.1.1.11
  NULL

SET is very similar to SEQUENCE; it is a collection in which semantically the
order of components is not important. SET OF is just like set, but all its
components are occurrences of the same type. In DER both SET and SET OF have
the same tag, 31(16).

In our certificate we will see a SET in, for example, specifying the
distinguished names of the issuer and the subject.

31 0b 30 09 06 03 55 04 06 13 02 55 53

This is decoded into

SET
  SEQUENCE
    OBJECT IDENTIFIER 2.5.4.6 ({joint-iso-itu-t(2) ds(5) attributeType(4)
      countryName(6)})
    PrintableString "US"


Certificate Analysis
--------------------

Now, finally, we dive into the certificate:

Certificate  ::=  SEQUENCE  {
  tbsCertificate       TBSCertificate,
  signatureAlgorithm   AlgorithmIdentifier,
  signatureValue       BIT STRING  }

3082 06eb - SEQUENCE with length 0x06eb

TBSCertificate  ::=  SEQUENCE  {
  version         [0]  EXPLICIT Version DEFAULT v1,
  serialNumber         CertificateSerialNumber,
  signature            AlgorithmIdentifier,
  issuer               Name,
  validity             Validity,
  subject              Name,
  subjectPublicKeyInfo SubjectPublicKeyInfo,
  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
  -- If present, version MUST be v2 or v3
  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
  -- If present, version MUST be v2 or v3
  extensions      [3]  EXPLICIT Extensions OPTIONAL
  -- If present, version MUST be v3
}

3082 05d3 - SEQUENCE with length 0x05d3

a0 03 02 01 02 - version [0] EXPLICIT Version DEFAULT v1

02 08 20 3f 89 1f c8 b6 29 20 - serialNumber CertificateSerialNumber
  ( 02 - INTEGER, 08 - length, integer value: 0x203f891fc8b62920)

signature AlgorithmIdentifier
AlgorithmIdentifier  ::=  SEQUENCE  {
  algorithm               OBJECT IDENTIFIER,
  parameters              ANY DEFINED BY algorithm OPTIONAL
}

30 0d - SEQUENCE with length 0x0d

06 09 2a 86 48 86 f7 0d 01 01 0b - algorithm OBJECT IDENTIFIER
  1.2.840.113549.1.1.11 = {iso(1) member-body(2) us(840)
    rsadsi(113549) pkcs(1) pkcs-1(1) sha256WithRSAEncryption(11)}

    86 48 - 10000110 01001000 -> 000011 01001000 -> 0x0348 = 840
    86 f7 0d - 10000110 11110111 00001101 -> 00001 10111011 10001101 ->
               0x01bb8d = 113549

0500 - parameters ANY DEFINED BY algorithm OPTIONAL - NULL

issuer Name
Name ::= CHOICE { -- only one possibility for now --
     rdnSequence  RDNSequence }
     
RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
        
RelativeDistinguishedName ::=
  SET SIZE (1..MAX) OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
  type     AttributeType,
  value    AttributeValue
}

AttributeType ::= OBJECT IDENTIFIER
                                
AttributeValue ::= ANY -- DEFINED BY AttributeType

DirectoryString ::= CHOICE {
  teletexString           TeletexString (SIZE (1..MAX)),
  printableString         PrintableString (SIZE (1..MAX)),
  universalString         UniversalString (SIZE (1..MAX)),
  utf8String              UTF8String (SIZE (1..MAX)),
  bmpString               BMPString (SIZE (1..MAX))
}

30 49 - SEQUENCE - length 0x49
  rdnSequence  RDNSequence
  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

31 0b - SET - length 0x0b
  RelativeDistinguishedName ::=
    SET SIZE (1..MAX) OF AttributeTypeAndValue

30 09 - SEQUENCE with length 0x09
  AttributeTypeAndValue ::= SEQUENCE {
    type     AttributeType,
    value    AttributeValue
  }

06 03 55 04 06 - type OBJECT IDENTIFIER
  2.5.4.6 = id-at-countryName

13 02 55 53 - value PrintableString "US"

31 13 - SET - length 0x13

30 11 - SEQUENCE with length 0x11

06 03 55 04 0a - type OBJECT IDENTIFIER
  2.5.4.10 = id-at-organizationName

13 0a 47 6f 6f 67 6c 65 20 49 6e 63 - value PrintableString "Google Inc"

31 25 - SET with length 0x25

30 23 - SEQUENCE with length 0x23

06 03 55 04 03 - type OBJECT IDENTIFIER
  2.5.4.3 = id-at-commonName

13 1c 47 6f 6f 67 6c 65 20 49 6e 74 65
72 6e 65 74 20 41 75 74 68 6f 72 69 74 79 20 47
32 - PrintableString "Google Internet Authority G2"

validity             Validity
Validity ::= SEQUENCE {
  notBefore      Time,
  notAfter       Time
}

Time ::= CHOICE {
  utcTime        UTCTime,
  generalTime    GeneralizedTime
}
30 1e - SEQUENCE with length 0x1e

17 0d 31 35 31 30 32 38 31 38 35 32 31 32 5a - UTCTime "151028185212Z"
  2015-10-28 18:52:12 Zulu time

17 0d 31 36 30 31 32 36 30 30 30 30 30 30 5a - UTCTime "160126000000Z"
  2016-01-26 00:00:00 Zulu time

subject              Name
30 66 SEQUENCE with length 0x66

31 0b SET with length 0x0b

30 09 SEQUENCE with length 0x09

06 03 55 04 06 - type OBJECT IDENTIFIER
  2.5.4.6 = id-at-countryName

13 02 55 53 - value PrintableString "US"

31 13 - SET with length 0x13

30 11 - SEQUENCE with length 0x11

06 03 55 04 08 - type OBJECT IDENTIFIER
  2.5.4.8 = id-at-stateOrProvinceName

0c 0a 43 61 6c 69 66 6f 72 6e 69 61 - UTF8String "California"

31 16 - SET with length 0x16

30 14 - SEQUENCE with length 0x14

06 03 55 04 07 - type OBJECT IDENTIFIER
  2.5.4.7 = id-at-localityName

0c 0d 4d6f 756e 7461 696e 2056 6965 77 - UTF8String "Mountain View"

31 13 - SET with length 0x13

30 11 - SEQUENCE with length 0x11

06 03 55 04 0a - type OBJECT IDENTIFIER
  2.5.4.10 = id-at-organizationName

0c 0a 47 6f 6f 67 6c 65 20 49 6e 63 - UTF8String "Google Inc"

31 15 - SET with length 0x15

30 13 - SEQUENCE with length 0x13

06 03 55 04 03 - type OBJECT IDENTIFIER
  2.5.4.3 = id-at-commonName

0c 0c 2a 2e 67 6f 6f 67 6c 65 2e 63 6f 6d - UTF8String "*.google.com"

subjectPublicKeyInfo SubjectPublicKeyInfo
SubjectPublicKeyInfo  ::=  SEQUENCE  {
  algorithm            AlgorithmIdentifier,
  subjectPublicKey     BIT STRING  }
AlgorithmIdentifier  ::=  SEQUENCE  {
  algorithm               OBJECT IDENTIFIER,
  parameters              ANY DEFINED BY algorithm OPTIONAL  }
30 59 - SEQUENCE with length 0x59

algorithm AlgorithmIdentifier
30 13 - SEQUENCE with length 0x13

06 07 2a 86 48 ce 3d 02 01 - algorithm OBJECT IDENTIFIER
  1.2.840.10045.2.1 = {iso(1) member-body(2) us(840)
    ansi-x962(10045) keyType(2) ecPublicKey(1)}

          86 48 - 10000110 01001000 -> 000011 01001000 -> 0x0348 = 840
          ce 3d - 11001110 00111101 -> 10 0111 0011 1101 -> 0x273d = 10045
                             
06 08 2a 86 48 ce 3d 03 01 07 - OBJECT IDENTIFIER
  1.2.840.10045.3.1.7 = {iso(1) member-body(2) us(840)
    ansi-x962(10045) curves(3) prime(1) prime256v1(7)}

      86 48 -> 0x0348 = 840
      ce 3d -> 0x273d = 10045

subjectPublicKey     BIT STRING
03 42 - BIT STRING with length 0x42

Bytes of public key: 00 (padding) + 65 bytes
00 04 da 15 df a8 21 8a 6a dc 69 d9 4d c6
b8 e3 3b 2a 92 26 62 41 94 9a 81 79 fc 9c 3f 3f
65 b0 94 a1 f9 31 b4 0b 79 14 eb ea 95 13 5b d5
b5 26 e5 57 4e ef 89 11 fb 51 0c 2d 23 4e 4e 62
74 9f 5b 79

extensions      [3]  EXPLICIT Extensions OPTIONAL
a3 82 04 83 - explicit tag 3 with length 0x0483 = 1155

30 82 04 7f - SEQUENCE with length 0x047f = 1151

30 1d - SEQUENCE with length 0x1d = 29

06 03 55 1d 25 - OBJECT IDENTIFIER
  2.5.29.37 = {joint-iso-itu-t(2) ds(5) certificateExtension(29)
    extKeyUsage(37)}

04 16 - OCTET STRING with length 0x16 = 22

30 14 = SEQUENCE with length 0x14 = 20

06 08 2b 06 01 05 05 07 03 01 - OBJECT IDENTIFIER
  1.3.6.1.5.5.7.3.1 = {iso(1) identified-organization(3) dod(6)
    internet(1) security(5) mechanisms(5) pkix(7) kp(3) serverAuth(1)}

06 08 2b 06 01 05 05 07 03 02 - OBJECT IDENTIFIER
  1.3.6.1.5.5.7.3.2 = {iso(1) identified-organization(3) dod(6)
    internet(1) security(5) mechanisms(5) pkix(7) kp(3) clientAuth(2)}

30 82 03 42 - SEQUENCE with length 0x342 = 834

06 03 55 1d 11 - OBJECT IDENTIFIER
  2.5.29.17 = {joint-iso-itu-t(2) ds(5) certificateExtension(29) subjectAltName(17)}

SubjectAltName ::= GeneralNames

  GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

  GeneralName ::= CHOICE {
    otherName                       [0]     OtherName,
    rfc822Name                      [1]     IA5String,
    dNSName                         [2]     IA5String,
    x400Address                     [3]     ORAddress,
    directoryName                   [4]     Name,
    ediPartyName                    [5]     EDIPartyName,
    uniformResourceIdentifier       [6]     IA5String,
    iPAddress                       [7]     OCTET STRING,
    registeredID                    [8]     OBJECT IDENTIFIER }

  OtherName ::= SEQUENCE {
    type-id    OBJECT IDENTIFIER,
    value      [0] EXPLICIT ANY DEFINED BY type-id }

  EDIPartyName ::= SEQUENCE {
    nameAssigner            [0]     DirectoryString OPTIONAL,
    partyName               [1]     DirectoryString }
                                                                                                                    

04 82 03 39 - BIT STRING with length 0x0339 = 825

30 82 03 35 - SEQUENCE with length 0x335 = 821

82 0c - context-specific external tag 2 with length 0x0c = 12
  82 - choice [2], dNSName

2a 2e 67 6f 6f 67 6c 65 2e 63 6f 6d - "*.google.com"

82 0d - context-specific external tag 2 with length 0x0d = 13

and so on:
        2a2e 616e  *.an
        00001a0: 6472 6f69 642e 636f 6d82 162a 2e61 7070  droid.com..*.app
        00001b0: 656e 6769 6e65 2e67 6f6f 676c 652e 636f  engine.google.co
        00001c0: 6d82 122a 2e63 6c6f 7564 2e67 6f6f 676c  m..*.cloud.googl
        00001d0: 652e 636f 6d82 162a 2e67 6f6f 676c 652d  e.com..*.google-
        00001e0: 616e 616c 7974 6963 732e 636f 6d82 0b2a  analytics.com..*
        00001f0: 2e67 6f6f 676c 652e 6361 820b 2a2e 676f  .google.ca..*.go
        0000200: 6f67 6c65 2e63 6c82 0e2a 2e67 6f6f 676c  ogle.cl..*.googl
        0000210: 652e 636f 2e69 6e82 0e2a 2e67 6f6f 676c  e.co.in..*.googl
        0000220: 652e 636f 2e6a 7082 0e2a 2e67 6f6f 676c  e.co.jp..*.googl
        0000230: 652e 636f 2e75 6b82 0f2a 2e67 6f6f 676c  e.co.uk..*.googl
        0000240: 652e 636f 6d2e 6172 820f 2a2e 676f 6f67  e.com.ar..*.goog
        0000250: 6c65 2e63 6f6d 2e61 7582 0f2a 2e67 6f6f  le.com.au..*.goo
        0000260: 676c 652e 636f 6d2e 6272 820f 2a2e 676f  gle.com.br..*.go
        0000270: 6f67 6c65 2e63 6f6d 2e63 6f82 0f2a 2e67  ogle.com.co..*.g
        0000280: 6f6f 676c 652e 636f 6d2e 6d78 820f 2a2e  oogle.com.mx..*.
        0000290: 676f 6f67 6c65 2e63 6f6d 2e74 7282 0f2a  google.com.tr..*
        00002a0: 2e67 6f6f 676c 652e 636f 6d2e 766e 820b  .google.com.vn..
        00002b0: 2a2e 676f 6f67 6c65 2e64 6582 0b2a 2e67  *.google.de..*.g
        00002c0: 6f6f 676c 652e 6573 820b 2a2e 676f 6f67  oogle.es..*.goog
        00002d0: 6c65 2e66 7282 0b2a 2e67 6f6f 676c 652e  le.fr..*.google.
        00002e0: 6875 820b 2a2e 676f 6f67 6c65 2e69 7482  hu..*.google.it.
        00002f0: 0b2a 2e67 6f6f 676c 652e 6e6c 820b 2a2e  .*.google.nl..*.
        0000300: 676f 6f67 6c65 2e70 6c82 0b2a 2e67 6f6f  google.pl..*.goo
        0000310: 676c 652e 7074 8212 2a2e 676f 6f67 6c65  gle.pt..*.google
        0000320: 6164 6170 6973 2e63 6f6d 820f 2a2e 676f  adapis.com..*.go
        0000330: 6f67 6c65 6170 6973 2e63 6e82 142a 2e67  ogleapis.cn..*.g
        0000340: 6f6f 676c 6563 6f6d 6d65 7263 652e 636f  ooglecommerce.co
        0000350: 6d82 112a 2e67 6f6f 676c 6576 6964 656f  m..*.googlevideo
        0000360: 2e63 6f6d 820c 2a2e 6773 7461 7469 632e  .com..*.gstatic.
        0000370: 636e 820d 2a2e 6773 7461 7469 632e 636f  cn..*.gstatic.co
        0000380: 6d82 0a2a 2e67 7674 312e 636f 6d82 0a2a  m..*.gvt1.com..*
        0000390: 2e67 7674 322e 636f 6d82 142a 2e6d 6574  .gvt2.com..*.met
        00003a0: 7269 632e 6773 7461 7469 632e 636f 6d82  ric.gstatic.com.
        00003b0: 0c2a 2e75 7263 6869 6e2e 636f 6d82 102a  .*.urchin.com..*
        00003c0: 2e75 726c 2e67 6f6f 676c 652e 636f 6d82  .url.google.com.
        00003d0: 162a 2e79 6f75 7475 6265 2d6e 6f63 6f6f  .*.youtube-nocoo
        00003e0: 6b69 652e 636f 6d82 0d2a 2e79 6f75 7475  kie.com..*.youtu
        00003f0: 6265 2e63 6f6d 8216 2a2e 796f 7574 7562  be.com..*.youtub
        0000400: 6565 6475 6361 7469 6f6e 2e63 6f6d 820b  eeducation.com..
        0000410: 2a2e 7974 696d 672e 636f 6d82 1a61 6e64  *.ytimg.com..and
        0000420: 726f 6964 2e63 6c69 656e 7473 2e67 6f6f  roid.clients.goo
        0000430: 676c 652e 636f 6d82 0b61 6e64 726f 6964  gle.com..android
        0000440: 2e63 6f6d 8204 672e 636f 8206 676f 6f2e  .com..g.co..goo.
        0000450: 676c 8214 676f 6f67 6c65 2d61 6e61 6c79  gl..google-analy
        0000460: 7469 6373 2e63 6f6d 820a 676f 6f67 6c65  tics.com..google
        0000470: 2e63 6f6d 8212 676f 6f67 6c65 636f 6d6d  .com..googlecomm
        0000480: 6572 6365 2e63 6f6d 820a 7572 6368 696e  erce.com..urchin
        0000490: 2e63 6f6d 8208 796f 7574 752e 6265 820b  .com..youtu.be..
        00004a0: 796f 7574 7562 652e 636f 6d82 1479 6f75  youtube.com..you
        00004b0: 7475 6265 6564 7563 6174 696f 6e2e 636f  tubeeducation.co
        00004c0: 6d                                       m

Extension  ::=  SEQUENCE  {
  extnID      OBJECT IDENTIFIER,
  critical    BOOLEAN DEFAULT FALSE,
  extnValue   OCTET STRING
    -- contains the DER encoding of an ASN.1 value
    -- corresponding to the extension type identified
    -- by extnID
}
30 0b - SEQUENCE with length 0x0b = 11

06 03 55 1d 0f - OBJECT IDENTIFIER
  2.5.29.15 = {joint-iso-itu-t(2) ds(5) certificateExtension(29) keyUsage(15)}

critical    BOOLEAN DEFAULT FALSE
  tag for BOOLEAN is 01, so since the next byte is not 01, this is
  not a critical extension

KeyUsage ::= BIT STRING {
  digitalSignature        (0),
  nonRepudiation          (1), -- recent editions of X.509 have
  -- renamed this bit to contentCommitment
  keyEncipherment         (2),
  dataEncipherment        (3),
  keyAgreement            (4),
  keyCertSign             (5),
  cRLSign                 (6),
  encipherOnly            (7),
  decipherOnly            (8) }
04 04 03 02 07 80 - OCTET STRING with length 04
  03 02 - BIT STRING with length 2
    07 - the first byte of BIT STRING means in the rest, 7 bits at the end are
         left unused, so only the first bit is used
    80 = 10000000b - digitalSignature
  

30 68 - SEQUENCE with length 0x68 = 104

06 08 2b 06 01 05 05 07 01 01 - OBJECT IDENTIFIER
  1.3.6.1.5.5.7.1.1 = {iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) pe(1) authorityInfoAccess(1)}

04 5c - OCTET STRING with length 0x5c = 92

30 5a - SEQUENCE with length 0x5a = 90

30 2b - SEQUENCE with length 0x2b = 43

06 08 2b 06 01 05 05 07 30 02 - OBJECT IDENTIFIER
  1.3.6.1.5.5.7.48.2 = {iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) ad(48) caIssuers(2)}

86 1f 68 74 74 70 3a 2f 2f 70 6b 69 2e 67 6f 6f 67 6c 65 2e 63 6f
6d 2f 47 49 41 47 32 2e 63 72 74 - access location 6 with length 0x1f = 31
  "http://pki.google.com/GIAG2.crt"

30 2b - SEQUENCE with length 0x2b = 43

06 08 2b 06 01 05 05 07 30 01 - OBJECT IDENTIFIER
  1.3.6.1.5.5.7.48.1 = {iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) ad(48) ocsp(1)}

86 1f 68 74 74 70 3a 2f 2f
63 6c 69 65 6e 74 73 31 2e 67 6f 6f 67 6c 65 2e
63 6f 6d 2f 6f 63 73 70 - access location 6 with length 0x1f = 31
  "http://clients1.google.com/ocsp"

30 1d - SEQUENCE with length 0x1d = 29

06 03 55 1d 0e - OBJECT IDENTIFIER
  2.5.29.14 = {joint-iso-itu-t(2) ds(5) certificateExtension(29)
    subjectKeyIdentifier(14)}

04 16 - OCTET STRING with length 0x16 = 22

04 14 - OCTET STRING with length 0x14 = 20

Subject Key Identifier:
da 73 61 46 27 a0 b3 de 9b fe 4d d4 89  ....saF'.....M..
1a 19 c1 68 63 30 9e

30 0c - SEQUENCE with length 0x0c = 12

06 03 55 1d 13 - OBJECT IDENTIFIER
  2.5.29.19 = {joint-iso-itu-t(2) ds(5) certificateExtension(29)
    basicConstraints(19)}

critical = 1:
01 01 ff - BOOLEAN 0xff - 01

BasicConstraints ::= SEQUENCE {
  cA                      BOOLEAN DEFAULT FALSE,
  pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
(
BasicConstraintsSyntax ::= SEQUENCE {
  cA                 BOOLEAN DEFAULT FALSE,
  pathLenConstraint  INTEGER(0..MAX) OPTIONAL,
  ...
}
)
(part that is in the "..."):
04 02 30 00 - OCTET STRING with length 2

30 1f - SEQUENCE with length 0x1f = 31

06 03 55 1d 23 - OBJECT IDENTIFIER
  2.5.29.35 = {joint-iso-itu-t(2) ds(5) certificateExtension(29)
    authorityKeyIdentifier(35)}

04 18 - OCTET STRING with length 0x18 = 24

AuthorityKeyIdentifier ::= SEQUENCE {
  keyIdentifier              [0]  KeyIdentifier OPTIONAL,
  authorityCertIssuer        [1]  GeneralNames OPTIONAL,
  authorityCertSerialNumber  [2]  CertificateSerialNumber OPTIONAL,
  ...
}
30 16 - SEQUENCE IDENTIFIER with length 0x16 = 22

KeyIdentifier ::= OCTET STRING
80 14 - implicit tag 0 (keyIdentifier) with length 0x14 = 20
  (keyIdentifier is OCTET STRING)

key identifier:
4a dd 06 16 1b bc f6 68 b5 76 f5 81 b6 bb 62 1a ba 5a 81 2f

30 21 - SEQUENCE with length 0x21 = 33

06 03 55 1d 20 - OBJECT IDENTIFIER
  2.5.29.32 = {joint-iso-itu-t(2) ds(5) certificateExtension(29)
    certificatePolicies(32)}

04 1a - OCTET STRING with length 0x1a = 26

30 18 - SEQUENCE with length 0x18 = 24

30 0c - SEQUENCE with length 0x0c = 12

06 0a 2b 06 01 04 01 d6 79 02 05 01 - OBJECT IDENTIFIER
  1.3.6.1.4.1.11129.2.5.1 = ? (a Google certificate policy OID)

    d6 79 = 1101 0110 0111 1001 -> 101011 01111001 -> 0x2b79
      0x2b79 = 11129

30 08 - SEQUENCE with length 0x08

06 06 67 81 0c 01 02 02 - OBJECT IDENTIFIER
  2.23.140.1.2.2 =
    subject-identity-validated(2) => (2.23.140.1.2.2)
    (Compliant with Baseline Requirements – Entity identity asserted)

    81 0c -> 10000001 00001100 -> 0000001 0001100 -> 000000 10001100 ->
      0x008c = 140

30 30 - SEQUENCE with length 0x30 = 48

30 30 - SEQUENCE with length 0x30 = 48

06 03 55 1d 1f - OBJECT IDENTIFIER
  2.5.29.31 = {joint-iso-itu-t(2) ds(5) certificateExtension(29)
    cRLDistributionPoints(31)}

cRLDistributionPoints EXTENSION ::= {
  SYNTAX         CRLDistPointsSyntax
  IDENTIFIED BY  id-ce-cRLDistributionPoints
}

CRLDistPointsSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

DistributionPoint ::= SEQUENCE {
  distributionPoint  [0]  DistributionPointName OPTIONAL,
  reasons            [1]  ReasonFlags OPTIONAL,
  cRLIssuer          [2]  GeneralNames OPTIONAL,
  ...
}

DistributionPointName ::= CHOICE {
  fullName                 [0]  GeneralNames,
  nameRelativeToCRLIssuer  [1]  RelativeDistinguishedName,
  ...
}

ReasonFlags ::= BIT STRING {
  unused(0), keyCompromise(1), cACompromise(2), affiliationChanged(3),
  superseded(4), cessationOfOperation(5), certificateHold(6),
  privilegeWithdrawn(7), aACompromise(8)}

04 29 - OCTET STRING with length 0x29 = 41

CRLDistPointsSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
30 27 - SEQUENCE with length 0x27 = 39

DistributionPoint ::= SEQUENCE
30 25 - SEQUENCE with length 0x25 = 37

a0 23 - explicit tag 0 with length 0x23 = 35
  distributionPoint  [0]  DistributionPointName OPTIONAL

DistributionPointName ::= CHOICE {
a0 21 - explicit tag 0 with length 0x21 = 33
fullName                 [0]  GeneralNames

GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

GeneralName ::= CHOICE {
  otherName                  [0]  INSTANCE OF OTHER-NAME,
  rfc822Name                 [1]  IA5String,
  dNSName                    [2]  IA5String,
  x400Address                [3]  ORAddress,
  directoryName              [4]  Name,
  ediPartyName               [5]  EDIPartyName,
  uniformResourceIdentifier  [6]  IA5String,
  iPAddress                  [7]  OCTET STRING,
  registeredID               [8]  OBJECT IDENTIFIER,
  ...
}

86 1f 68 74 74 70
3a 2f 2f 70 6b 69 2e 67 6f 6f 67 6c 65 2e 63 6f
6d 2f 47 49 41 47 32 2e 63 72 6c - access location 6 (uniformResource Identifier)
  with length 0x1f = 31
  "http://pki.google.com/GIAG1.crl"

signatureAlgorithm   AlgorithmIdentifier
AlgorithmIdentifier  ::=  SEQUENCE  {
  algorithm               OBJECT IDENTIFIER,
  parameters              ANY DEFINED BY algorithm OPTIONAL
}
30 0d - SEQUENCE with length 0x0d = 13

06 09 2a 86 48 86 f7 0d 01 01 0b - OBJECT IDENTIFIER
  1.2.840.113549.1.1.11 = {iso(1) member-body(2) us(840) rsadsi(113549)
    pkcs(1) pkcs-1(1) sha256WithRSAEncryption(11)}

    86 48 -> 10000110 01001000 -> 000011 01001000 -> 0x0348 = 840
    86f70d -> 10000110 11110111 00001101 -> 0000110 1111011 0001101 ->
      00001 10111101 10001101 -> 0x01bb8d = 113549

parameters
05 00 - NULL

signatureValue       BIT STRING
03 82 01 01 - BIT STRING with length 0x101 = 257

00 09
5c7b 0333 092e 9923 1386 1f6b 337c 44f5  \{.3...#...k3|D.
701d e149 3f66 ad59 24bd 44ae 7b19 c36c  p..I?f.Y$.D.{..l
964e 0da8 e43e e5a2 b502 f22c 428f 0601  .N...>.....,B...
efb0 f75f 2d4c 222e e8e0 bb9e 294b bba8  ..._-L".....)K..
7618 6061 862a 6e5e 45c2 6043 45b4 4729  v.`a.*n^E.`CE.G)
adac e702 2895 c00a 64c9 4b87 b62a 0fb7  ....(...d.K..*..
1498 0d5a 57a0 557c 35d9 57b8 76b8 46dd  ...ZW.U|5.W.v.F.
47cc d084 bf34 f5a7 5211 d258 24e7 cdf8  G....4..R..X$...
889e 4fd8 a2f2 d3a5 296a c9b1 118c c91e  ..O.....)j......
473a c9b3 abdc 2bc6 f7ab 2889 654e a654  G:....+...(.eN.T
22ee 7602 dca1 6b8f 7f4e 42b5 6b5f 7a4e  ".v...k..NB.k_zN
1c1c ed27 e9b7 9fd1 c38d c9d4 cd19 2015  ...'.......... .
0628 e8df e8cb ce44 ecb1 12ca 0e4c 721b  .(.....D.....Lr.
b1e7 b627 13fa dc5e b9dd eff6 a4cb 1326  ...'...^.......&
e449 5aee 4efc 9fa1 ac61 f880 3708 4002  .IZ.N....a..7.@.
2964 a345 b099 f3cc 891e f9eb bec8 75    )d.E..........u
