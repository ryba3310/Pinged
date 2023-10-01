# Pinged


## In case you need to get someone Pinged

Pinged is a simple program which solely transmits payload using only unreliable layer 3 ICMP in case all layer 4 outbound and inbound communication is forbidden.

It requiers binanry ran on target host to listen for incoming ICMP packets.

By default it accepts data in stdin or specifed file path specifed after "-f path/to/file" flag.

Supplied data may be encoded into base64 with "-b" flag before transmission.

It is developed for the sake of breviy and is inspired by Netcat.

# About

Please keep in mind it's not developed in a malicious puropse therefore any IDS properly configured should detect the trafic and it is not suited for transmission of large payloads becouse of DoS danger.


# TODO

Create listener ran without flags that outputs the payload of ICMP to STDOUT

Filter IMCP packets based on identifier inside payload

Check data integrity and in case of error, request it again from client

Create client mode if there is an argument which indicates IP destination which by default accepts STDIN as input or file spcifed by "-f" flag

Listen for resend requests in client mode
