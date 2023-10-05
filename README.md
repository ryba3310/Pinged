# Pinged


## In case you need to get someone Pinged

Pinged is a simple program which solely transmits payload using only unreliable layer 3 ICMP in case all layer 4 outbound and inbound communication is forbidden.

It requiers binanry ran on target host to listen for incoming ICMP packets.

By default it accepts data in stdin or specifed file path after "-f path/to/file" flag.

Supplied data may be encoded into base64 with "-b" flag before transmission.

It is developed for the sake of breviy, as a learning project and is inspired by Netcat.

Root privileges or CAP_NET_RAW capabilities set are required for usage of SOCK_RAW from socket library to create socket and allow sending and recieving packets.

# Usage

```sh
# To listen on target host
./pinged

# To send payload from a file
./pinged -f file/to/path 1.1.1.1
```

# About

Please keep in mind it's not developed in a malicious puropse therefore any IDS properly configured should detect the trafic and it is not suited for transmission of large payloads becouse of DoS danger.


# TODO

- ✅ Create listener ran without flags that outputs the payload of ICMP to STDOUT

- ✅ ~~Filter IMCP packets based on identifier inside payload~~ Filter ICMP packets based on code filed insied ICMP header

- ✅ Check data integrity and in case of error, request it again from client, based on checksum ICMP field

- ✅ Create client mode which expects IP destination as an argument and by default accepts STDIN as input or file spcifed by "-f" flags

- ⚠️ Parse payload into packeets and avoid IP fragmentation

- ⚠️ Listen for resend requests in client mode, based on echo reply from target

- ✅ Check IPPROTO_ICMP protocol and SOCK_DGRAM type with sysctl 'net.ipv4.ping_group_range allowed' for rootless application

- ⚠️ Add base64 encoding in client mode

- ⚠️  Set listener socket to SOCK_DGRAM type for rootless listening on target host
