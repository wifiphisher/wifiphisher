
a = 0
name = "wifiphisher/data/wifiphisher-mac-prefixes"
with open(name, "r") as f:
    hand = f.readlines()
    for line in range(len(hand)):
        if not hand[line].startswith("#"):
            # separate vendor and MAC addresses and add it
            # to the dictionary
            separated_line = hand[line].rstrip('\n').split('|')
            mac_identifier = separated_line[0]
            vendor = separated_line[1]
            logo = separated_line[2]
            if vendor == "Juniper Networks" and not logo:
                a += 1
                hand[line] = mac_identifier + "|" + vendor + "|" + "juniper_networks.svg\n"
print a

with open(name, "w") as fi:
    for l in hand:
        fi.write(l)
