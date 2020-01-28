# Illumio-Coding-Assignment-2019-2020
This is the repository for the Illumio coding assignment.

## Implementation
Since I aimed to complete this assigment within two hours, I decided to store all given rules in a HashSet to achieve fast lookup. I encode each firewall wall to a Long object, using the first byte for the direction, second byte for the protocol, third and fourth bytes for the port number, and lastly, the last four bytes for the ip address. When a user packet is sent in, its packet inforation would be encoded the same way, and then if the encoding of it is present in the HashSet, accept_packet would return true. If given more time, I would like to modify the way I store the rules, using structures such as TreeMap in java, to achieve a balance between time efficiency and space efficiency. I would also like to redesign the Firewall class in a way that it could accomodate more types of packet input (for example, protocols other than tcp and udp). 

## Testing
JUnit was used for testing. If given more time, I would like to test my Firewall on larger set or rules. 

## Teams
1. 
