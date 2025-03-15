import operator
from functools import reduce

def nmea_checksum(sentence: str):
    """
    This function checks the validity of an NMEA string using it's checksum
    """
    sentence = sentence.strip("$\n")
    nmeadata, checksum = sentence.split("*", 1)
    calculated_checksum = reduce(operator.xor, (ord(s) for s in nmeadata), 0)
    if int(checksum, base=16) == calculated_checksum:
        return '$' + sentence
    else:
        return '$' + nmeadata + '*' + str(hex(calculated_checksum))[2:]

w = open("new_road.nmea", "w")

with open("road.nmea", "r") as file:
    for line in file:
        w.write(nmea_checksum(line) + "\n")

w.close()
