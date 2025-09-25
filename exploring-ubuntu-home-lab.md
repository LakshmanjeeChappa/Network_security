

Exploring Ubuntu Home Lab

 1) Find Network Interfaces & IP

Command:

ip a

What i saw:

* Loopback (127.0.0.1).
* Main interface `ens33` with IP `192.168.92.128`.

My note:

when i ran the above command this shows how my VM is connected. The important one is `ens33` with 192.168.92.128, which is my VM’s address. 


https://github.com/user-attachments/assets/5928d6bc-afe9-4111-8ab3-d622d76eb701

2) Check Open Ports

Command:

sudo ss -tuln

What i saw:

* SSH (22) open to everywhere.
* CUPS (631) open only locally.
* Some background UDP services: DNS, DHCP, Avahi.

My note:

 SSH being open makes sense but I’ll want to lock it down. CUPS is just for printing — not useful here, so that’s extra stuff I don’t need running. Everything else looked normal.


https://github.com/user-attachments/assets/6a1c5615-f168-4a24-b282-d6800f0562f0

 3) List Connections with lsof

Command:

sudo lsof -i -P -n
What i saw :
My first run failed (wrong flags). After correcting it, I could see which processes are tied to ports.

https://github.com/user-attachments/assets/ad91c203-3fa7-46e0-96c9-44bc48fa6bba

 4) Nmap Scan (Localhost)

Command:

sudo nmap -sS -O localhost

what i saw:
* Found ports 22 and 631.
* Guessed Linux/Ubuntu.
My note:

Nmap results matched what I saw with ss. The OS guess was low confidence, but that’s fine.

https://github.com/user-attachments/assets/f4b6b64a-3133-41d7-8ad0-5727ea1aa3db

 5) Find Devices on My Network

Command:

sudo nmap -sn 192.168.1.0/24


What I saw:

 Several live hosts: .1 through .9.

My note:

Found my router, my VM, and other devices like phones or smart plugs. A reminder that home networks always have more stuff than you expect.

https://github.com/user-attachments/assets/f3dfcabc-ad9f-423a-9c5c-cd8b94486b49

https://github.com/user-attachments/assets/d927336e-cbf8-416a-90f2-fd6394ecbc17

 6) Check Services and Versions

Command:


sudo nmap -sV localhost

What i saw:

* SSH (OpenSSH 8.9p1).
* CUPS (2.4).
My note:

SSH version was up-to-date. The printing service (CUPS) surprised me — no reason for it on this VM.


https://github.com/user-attachments/assets/d23f2d6f-7a89-4a82-9f0b-128531ce86d8

7) Quick Vulnerability Check

Command:


sudo nmap --script vuln localhost


What i saw:

* Checked Avahi (not vulnerable).
* Some noisy results and script errors.

My note:

Nothing serious flagged, just generic stuff. Shows how vuln scans can be messy.

https://github.com/user-attachments/assets/51934f90-556d-466a-840a-09039ce7dedd

https://github.com/user-attachments/assets/050c271c-1de1-4fc9-8d9b-276d6c3741ee

 8) Watch Network Traffic

Command:

sudo tcpdump -i ens33

What I saw:

* Lots of ARP requests asking “who has the gateway?”.
* DNS lookups returning NXDomain.
* 116 packets captured.
My note:

Looked like normal traffic — my VM chatting with the router. No weird protocols or surprises.

https://github.com/user-attachments/assets/6d05c0b2-1fba-4bb5-9202-7722ba548216
https://github.com/user-attachments/assets/3c5e1d16-4356-49f8-9c0a-bca49293236c

 9) Real-Time Connections

Command:

sudo watch -n 1 ss -tulnp


What i saw:

* SSH open to all addresses.
* CUPS local-only.
* Avahi, DNS, and DHCP running.

My note:

 I liked seeing this update live. Nothing unexpected popped up, so it gave me some peace of mind. Again, SSH is the one to keep an eye on.

https://github.com/user-attachments/assets/3a072c90-c22e-4b56-a94a-cd6267fd85fc

10) Firewall Rules

Command:

sudo ufw status verbose


What I saw:

* Firewall is active.
* Default: deny incoming, allow outgoing.
* Only SSH (22) is allowed in.

My note:

This was good to see — my VM isn’t wide open. SSH is allowed, which I expected. Later, I’d narrow that down so only my laptop/IP can connect.



https://github.com/user-attachments/assets/35bfb693-41a6-441a-8b61-3f7ed60356fe









