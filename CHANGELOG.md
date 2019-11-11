v1.4 (2018-01-12)
=====

New Features:
-----
* <address></address> dissociation frame to DEAUTH attack 993228c917a2046819cc673b2e35789e4a36f77e
* support wireless card for internet option interface00c1b64ae03a475dbf283ac455bfbb627fd729aa
* kill interfering processes on startup 9127a91f06d245bfbe22cd9fc58ec398aba860fa
* use curses everywhere cfa632aee59624b5caf2703297802f01fe4d5a89
* add captured passphrase validation 3d255e73e44c627380380c6685aa9e82c9b75f52
* add option to deauthenticate based on ESSID 225cd72b4b6e0f0088b592be2a63c2be5f932d29
* add --logging option db4a3f126fbaef3434f9c369f1b708ee34693b58
* add target channel monitoring 2940a94a790121dc0735c1c0990ca430d4e829d4
* add known beacons attack affbc3d911decd6db32813da53025fd28c24bc0a
* add WPS PBC phishing attack 2b1bae7566f113438b78e7972e2249bf61357353
* support only one physical interface e9e7690ad0a1e3f04a2d5ecc721d9e5a3781659c

Bug Fixes:
-----
* RSSI output 4efea79277c0c288d2df6402232556a9d8c35f9a
		
v1.3 (2017-04-15) 
=====

New Features:
-----
* add --quitonsuccess option 557086e86a5d38c71078ad017a63e88032e02d67
* add Lure10 attack 5e77abb5d0893835c629c2d8a53719eba65a8289
* add --internetinterface option de63c2394cf5a4a28ee174663dfaf2a4c9867dc4
* support iOS and Android in network manager template 36ed91960533d64d0c712ce334d5e7a345a538fd
* new target AP selection phase cb7ff03b7e06716693e99348ce86483dc41e73af

Bug Fixes:
-----
* bugs in tornado d19337ad3c0d39a9dcc11a316e2ce6f0f22fdb16
* Remove DNS leases after the script restarts 7970cc10e6a63f245b4ca4a7d5a974cafe35ffe3

v1.2 (2016-12-04)
=====

New Features:
-----
* add "Wi-Fi Connect" template 41f3220d4de53672c577f7758ae1110ee316059d
* allow multiple POST values 24e52210b2dec7f673c4371ec799083f57fdb6b7
* add interactive scenario selection 9163fd2ebbbb2025850b1fc23c8f6eba5510597a
* add --presharedkey option f764075a7deb6c2b7b049e9a84388adfc3c4f911
* add "Browser Plugin Update" scenario b5e1bd744896f8a14840ad55acfa8614330bc018
* add --essid option bc94f90e578037c8e6f9422b3767f8d2c45abe81
* add --nojamming option 4a160467a04a4ee564b98e6dc1a69a7d4fd4e3a8
* add OAuth template 0c8deaea7d42bf69b9727c6f53407824abe45c55
* detect target vendor based on BSSID 7fc1787150182d8ac3ea2b797585ea46d53689e7
* add template engine support 6c7de9164878df9b14946b6192053442be948e5f

Bug Fixes:
-----
* issues on Ubuntu e8929c8673788e0213cf267dc25ee2de5c9169bd
* issues on Arch Linux da54b7580023ec0577fa654b254483049fe23bf9
* start server after DHCP 4b193b5b897974b72daaa3f2b9a4bbc855659e6d
* bugs on HTTP server f6dcce260d482da62de964fc039788679de333b3

v1.1 (2015-07-01)
=====

New Features:
-----
* add support for Pineapple's DD-WRT 03be17e28c6c4bb5ef468b1c84b5593d317b1d53
* add connection-reset template 32cd212911557905ff10ffaafc5619e125ae0917

Bug Fixes:
-----
* chage shebang deafulting to python2 c3cbca2e68c9942e71a86a205496dc7380ccb4b0
* undefined variable use #7 444eb3d3ae0113e3e22ab8f211b39875b23b3859
* string concatenation error 4da046d28fede6249f49da0da419e655e411417b
* empty password redirect 864dab8986a43416ce9aeec6963e14e33a4b5a6c
* exception when port is unavailable a5a3dd9fc607083bf92bdc450123ec175e74a6db
* message output in case hostapd is notinstalled c2270153ae05e7b94d06efff81d0b1693feb1d94
* PEP8 errors 587fd51004ad5a83fe2294ba4f2a936030d2366d
* prohibit internet interface for other usage
