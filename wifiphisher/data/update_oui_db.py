import requests


with open("wifiphisher-mac-prefixes", "w") as file:
    oui = requests.get("https://svn.nmap.org/nmap/nmap-mac-prefixes")
    for line in oui.content.splitlines():
        if line.startswith("# "):
            file.write(line + "\n")
            continue
        new_line = line.split(" ")
        new_line = new_line[0] + "|" + " ".join(new_line[1:]) + "|\n"
        file.write(new_line)