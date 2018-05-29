a = 0
my_dic = dict()
name = "wifiphisher/data/wifiphisher-mac-prefixes"
with open(name, "r") as f:
    hand = f.readlines()
    for line in range(len(hand)):
        if not hand[line].startswith("#"):
            separated_line = hand[line].rstrip('\n').split('|')
            mac_identifier = separated_line[0]
            vendor = separated_line[1]
            logo = separated_line[2]
            if not logo:
                a+=1
                try:
                    my_dic[vendor] += 1
                except KeyError:
                    my_dic[vendor] = 1

print sorted(my_dic.items(),key=lambda x:x[1])
print a
