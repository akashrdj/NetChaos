"""OUI (Organizationally Unique Identifier) validation database.

Contains a curated set of the most common OUI prefixes (first 3 bytes of
a MAC address) from major NIC manufacturers. Used by the MAC flood detector
to distinguish real hardware MACs from randomly generated ones.

Randomly generated MACs (e.g., Scapy's RandMAC()) will statistically have
invalid/unknown OUI prefixes, since only ~30k of the ~16.7M possible
3-byte prefixes are actually registered with IEEE.
"""

# Top ~200 most common OUI prefixes covering major manufacturers.
# Format: lowercase hex with colons (e.g., "00:50:56" for VMware).
VALID_OUIS = {
    # VMware
    "00:50:56", "00:0c:29", "00:05:69",
    # Microsoft / Hyper-V
    "00:15:5d", "00:03:ff", "00:12:5a",
    # Intel
    "00:1b:21", "00:1e:67", "00:1f:3c", "00:22:fa", "00:24:d7",
    "00:26:c6", "00:27:10", "3c:97:0e", "40:a3:6b", "48:21:0b",
    "4c:eb:42", "54:ee:75", "68:05:ca", "80:86:f2", "8c:ec:4b",
    "a0:36:9f", "a4:4c:c8", "b4:96:91", "d0:94:66", "f4:8e:38",
    "f8:bc:12",
    # Realtek
    "00:e0:4c", "52:54:00", "00:12:3f", "00:0d:0b",
    # Broadcom
    "00:10:18", "00:24:d2", "d8:fe:e3",
    # Qualcomm / Atheros
    "00:03:7f", "00:0e:6a", "00:13:74", "00:26:cb", "9c:b7:0d",
    # Cisco
    "00:00:0c", "00:01:42", "00:01:64", "00:01:96", "00:01:97",
    "00:01:c7", "00:01:c9", "00:02:3d", "00:02:4a", "00:02:4b",
    "00:02:7d", "00:02:7e", "00:02:b9", "00:02:ba", "00:02:fc",
    "00:02:fd", "00:03:31", "00:03:32", "00:03:6b", "00:03:6c",
    "00:03:9f", "00:03:a0", "00:03:e3", "00:03:e4", "00:03:fd",
    "00:03:fe",
    # Dell
    "00:06:5b", "00:08:74", "00:0b:db", "00:0d:56", "00:0f:1f",
    "00:11:43", "00:13:72", "00:14:22", "00:15:c5",
    "00:18:8b", "00:19:b9", "00:1a:a0", "00:1c:23", "00:1d:09",
    "00:1e:4f", "00:1e:c9", "00:21:70", "00:21:9b", "00:22:19",
    "00:23:ae", "00:24:e8", "00:25:64", "00:26:b9",
    # HP / HPE
    "00:01:e6", "00:01:e7", "00:02:a5", "00:04:ea", "00:08:02",
    "00:0a:57", "00:0b:cd", "00:0d:9d", "00:0e:7f", "00:0f:20",
    "00:0f:61", "00:10:83", "00:10:e3", "00:11:0a", "00:11:85",
    "00:12:79", "00:13:21", "00:14:38", "00:14:c2", "00:15:60",
    "00:16:35", "00:17:08", "00:17:a4", "00:18:71", "00:18:fe",
    "00:19:bb", "00:1a:4b", "00:1b:78", "00:1c:2e", "00:1c:c4",
    "00:1e:0b", "00:1f:28", "00:1f:29", "00:21:5a", "00:21:5b",
    "00:22:64", "00:23:7d", "00:24:81", "00:25:b3",
    # Apple
    "00:03:93", "00:05:02", "00:0a:27", "00:0a:95", "00:0d:93",
    "00:10:fa", "00:11:24", "00:14:51", "00:16:cb", "00:17:f2",
    "00:19:e3", "00:1b:63", "00:1c:b3", "00:1d:4f", "00:1e:52",
    "00:1e:c2", "00:1f:5b", "00:1f:f3", "00:21:e9", "00:22:41",
    "00:23:12", "00:23:32", "00:23:6c", "00:23:df", "00:24:36",
    "00:25:00", "00:25:4b", "00:25:bc", "00:26:08", "00:26:4a",
    "00:26:b0", "00:26:bb",
    # Samsung
    "00:07:ab", "00:12:fb", "00:15:99", "00:15:b9", "00:16:32",
    "00:16:6b", "00:16:6c", "00:17:c9", "00:17:d5", "00:18:af",
    "00:1a:8a", "00:1b:98", "00:1c:43", "00:1d:25", "00:1d:f6",
    "00:1e:e1", "00:1e:e2", "00:1f:cc", "00:1f:cd", "00:21:19",
    "00:21:d1", "00:21:d2", "00:23:39", "00:23:3a", "00:23:99",
    "00:23:d6", "00:23:d7", "00:24:54", "00:24:90", "00:24:91",
    "00:25:66", "00:25:67", "00:26:37",
    # Docker default range (02:42:xx:xx:xx:xx)
    "02:42:ac",
    # QEMU / KVM
    "52:54:00",
    # VirtualBox
    "08:00:27",
    # Juniper Networks
    "00:05:85", "00:10:db", "00:12:1e", "00:14:f6", "00:17:cb",
    "00:19:e2", "00:1d:b5", "00:21:59", "00:22:83", "00:23:9c",
    "00:24:dc", "00:26:88",
    # Amazon / AWS
    "0a:00:27", "02:50:f4",
    # Google Cloud
    "42:01:0a",
    # TP-Link
    "00:27:19", "14:cf:92", "50:fa:84", "60:e3:27", "a4:2b:b0",
    # Netgear
    "00:09:5b", "00:0f:b5", "00:14:6c", "00:18:4d", "00:1b:2f",
    "00:1e:2a", "00:1f:33", "00:22:3f", "00:24:b2", "00:26:f2",
    # Linksys
    "00:04:5a", "00:06:25", "00:0c:41", "00:0f:66", "00:12:17",
    "00:14:bf", "00:16:b6", "00:18:39", "00:18:f8", "00:1a:70",
    "00:1c:10", "00:1d:7e", "00:1e:e5", "00:21:29", "00:22:6b",
    "00:23:69", "00:25:9c",
    # Arista Networks
    "00:1c:73", "28:99:3a",
    # Mellanox / NVIDIA Networking
    "00:02:c9", "00:30:48", "e4:1d:2d",
}


def is_valid_oui(mac_address: str) -> bool:
    """Check if a MAC address has a valid (known) OUI prefix.

    Args:
        mac_address: MAC in colon-separated format
            (e.g., "00:50:56:ab:cd:ef").

    Returns:
        True if the first 3 octets match a known manufacturer OUI.
    """
    prefix = mac_address.lower()[:8]  # "xx:xx:xx"
    return prefix in VALID_OUIS
