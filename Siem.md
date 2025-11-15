**INTRO**

n this lab I deployed a complete lightweight SIEM pipeline using Suricata for intrusion detection, Promtail for log forwarding, Loki for log storage, and LogCLI for querying. The goal was to observe network security events, generate alerts, forward them into a centralized log system, and analyze them. This setup helped demonstrate how SOC teams collect, index, and correlate security logs in real environments.



**PART1
**
1. Update system + install curl, jq, unzip

Command:

sudo apt update && sudo apt upgrade -y
sudo apt install -y curl jq unzip



<img width="875" height="592" alt="1" src="https://github.com/user-attachments/assets/06018b20-1ebd-4792-821f-fdfbb16ad7b4" />

What I saw:
The system updated successfully and installed curl, jq, and unzip without errors.

My note:
These tools are required for downloading files, formatting JSON, and extracting zip files.

2. Install Docker

Command:

curl -fsSL https://get.docker.com | sudo sh

<img width="876" height="777" alt="Screenshot 2025-11-13 221127" src="https://github.com/user-attachments/assets/5b09dfc6-e9fe-496f-a401-8da9f10614d4" />


What I saw:
Docker packages were downloaded and installed. No errors appeared.

My note:
I installed Docker because I need it to run Loki and Promtail containers later.

3. Add user to Docker group

Command:

sudo usermod -aG docker "$USER"
newgrp docker
docker --version

<img width="852" height="129" alt="Screenshot 2025-11-13 221253" src="https://github.com/user-attachments/assets/e3a3f3a9-b3aa-42d2-92a6-f6c92ca2268c" />

What I saw:
Docker version displayed successfully.

My note:
Adding myself to the Docker group lets me run docker commands without sudo.

4. Enable Docker service

Command:

sudo systemctl enable --now docker
docker --version

<img width="865" height="119" alt="Screenshot 2025-11-13 221348" src="https://github.com/user-attachments/assets/97f26247-cc0c-468e-8fe7-2bc4add51ef7" />

What I saw:
Docker service started and enabled. The docker version printed again.




My note:
This makes sure Docker always runs in the background, even after reboot.


**PART-2**

Reading the Suricata vs Snort article

What I learned:
Suricata is a modern IDS/IPS that watches network traffic and alerts on suspicious activity.
It can detect attacks, malware, scans, and strange behavior.
It works faster than Snort because it uses multiple CPU cores.
Suricata also creates JSON logs, which makes it easier to use with SIEM tools like Loki.

Install Suricata + Update Rules

Command:

sudo apt -y install suricata
sudo apt -y install suricata-update
sudo suricata-update



<img width="866" height="548" alt="part2 1" src="https://github.com/user-attachments/assets/2df079cd-0b9d-414e-a754-4738dc9372ae" />

What I saw:
Suricata installed successfully and downloaded a big set of community rules.

My note:
These rules help Suricata detect common threats right away.

Check default rule file

Location checked:
/var/lib/suricata/rules/suricata.rules
<img width="886" height="332" alt="part2 5" src="https://github.com/user-attachments/assets/5d469384-3c82-4719-846d-745e4e397cb4" />

What I saw:
This file contains thousands of existing rules from the community set.

My note:
This is the main rule file Suricata loads during startup.

Find my network interface

Command:

ip -br a | awk '$1!="lo"{print $1, $3}'
<img width="862" height="198" alt="part2 2" src="https://github.com/user-attachments/assets/a7898763-4c3d-424c-aea9-39e00fde5dd5" />


What I saw:
Your interface was: ens33 (based on screenshots).

My note:
Suricata needs the correct interface name to capture traffic.

Create local rules directory

Command:

sudo mkdir -p /etc/suricata/rules
sudo touch /etc/suricata/rules/local.rules

<img width="835" height="62" alt="part2 3" src="https://github.com/user-attachments/assets/532e5930-68e0-4d59-9f10-18dce7bea908" />

What I saw:
The folders and the file were created successfully.

My note:
This file is for my own rules that I will write later.

Edit suricata.yaml

Command:

sudo nano /etc/suricata/suricata.yaml

What I changed:

 Updated default-rule-path to:
/var/lib/suricata/rules

 Added this under rule-files:

- /etc/suricata/rules/local.rules


 Updated af-packet interface to:
<img width="862" height="199" alt="Screenshot 2025-11-13 221749" src="https://github.com/user-attachments/assets/78bc4d28-1976-4506-b7f2-6ed3633b95be" />

interface: ens33


What I saw:
The values updated correctly in the config file.

My note:
This makes Suricata load both the main rules and my custom rules.

Validate Suricata Configuration

Command:

sudo suricata -T -c /etc/suricata/suricata.yaml -v
<img width="886" height="332" alt="part2 5" src="https://github.com/user-attachments/assets/f3304ffc-5c55-4ddb-8ed4-38d06252e410" />


What I saw:
Output showed "Configuration provided was successfully loaded."

My note:
This confirms the YAML file is valid and Suricata can start without errors.

Explain the flags
-T

What I saw:
Runs a test mode — no real traffic, just config validation.

My note:
Used to make sure the config has no mistakes.

-c

What I saw:
Loads the specific config file (suricata.yaml).

My note:
Points Suricata to the right configuration.

-v

What I saw:
More detailed messages printed on screen.

My note:
Shows what Suricata is doing, so I can catch problems.


Command:

sudo tail -f /var/log/suricata/eve.json | jq
<img width="857" height="708" alt="part2 7" src="https://github.com/user-attachments/assets/c9634d44-2090-4608-b876-0ff0e91fe00a" />


What I saw:
The eve.json log started streaming live, and the output was nicely formatted in JSON.
New Suricata alerts and events were appearing as they happened.

My note:
This lets me watch Suricata’s network alerts in real time. jq makes the logs readable instead of a single messy line.

Question 1 Answer:

I only saw the event type:

stats

This is Suricata’s internal reporting about uptime, decoder counts, memory usage, and packet totals.
No flow or alert events appeared in this specific output.


**PART-3**

Command:
sudo mkdir -p /etc/loki /var/lib/loki/{chunks,rules}
<img width="878" height="341" alt="part3 5(main of main)" src="https://github.com/user-attachments/assets/98adc3fb-9135-473b-85ef-258f16427df4" />

What I saw:

The command finished with no errors and created the folders Loki needs.

My note:

These folders hold Loki’s config file and log storage, so creating them is required before starting Loki.

Command:

Created the Loki config file using:

cat <<'EOF' | sudo tee /etc/loki/loki-config.yml
...
EOF
<img width="878" height="341" alt="part3 5(main of main)" src="https://github.com/user-attachments/assets/538784df-c1f3-4005-8575-ba07c7655f61" />

What I saw:

The YAML config file was written successfully.

My note:

This file tells Loki which port to listen on, where to store logs, and how to index them.
It's basically Loki’s instruction manual.

Command:
sudo chown -R 10001:10001 /var/lib/loki
sudo chmod -R u+rwX /var/lib/loki
<img width="878" height="341" alt="part3 5(main of main)" src="https://github.com/user-attachments/assets/d954392c-a978-4595-b062-5f2c7f666e1b" />

What I saw:

No errors, permissions updated.

My note:

Loki runs as user ID 10001 inside the container, so fixing permissions is required or the container will fail to start.

Command (Run Loki):
sudo docker run -d --name loki -p 3100:3100 \
-v /etc/loki:/etc/loki \
-v /var/lib/loki:/var/lib/loki \
grafana/loki:2.9.8 -config.file=/etc/loki/loki-config.yml
<img width="878" height="341" alt="part3 5(main of main)" src="https://github.com/user-attachments/assets/de529079-ced3-4d81-9d24-e5933b6a2677" />

What I saw:

A container ID was returned, meaning Loki started.

Command (Check Loki):
docker ps

What I saw:

The Loki container was running.
Status showed “Up”, and port 3100 was exposed.

Command (Check ready status):
curl -s http://localhost:3100/ready; echo
<img width="878" height="341" alt="part3 5(main of main)" src="https://github.com/user-attachments/assets/176c5165-5c06-4de4-bcab-755f51aab245" />

What I saw:

The first time it said:

Ingester not ready; waiting for 15s after being ready

When I ran it again, it showed:

ready

My note:

This means Loki fully started and is ready to accept logs.

Question2
Answer:

Port: Loki exposes port 3100.

API path for log data: Promtail sends logs to:

/loki/api/v1/push
Port 3100 is where Loki listens, and the /loki/api/v1/push endpoint is the API where Promtail forwards your Suricata logs.


**PART4**
Command:
sudo mkdir -p /etc/promtail /var/lib/promtail
<img width="872" height="507" alt="part4 1" src="https://github.com/user-attachments/assets/e1089ef7-516a-4c55-aacc-b55187d41c7e" />

What I saw:

The command created the required folders with no errors.

My note:

Promtail needs these folders for its config file and for storing its “positions” bookmark.

Command (Create Promtail config file):
sudo nano /etc/promtail/promtail-config.yml
<img width="872" height="507" alt="part4 1" src="https://github.com/user-attachments/assets/00bb73da-3120-4d97-98c8-887923bebe50" />

What I saw:

I created the YAML config file and saved it without issues.

My note:

This config tells Promtail which file to read (Suricata’s eve.json), where to send logs (Loki), and which labels to attach.

Command (Run Promtail):
sudo docker run -d --name promtail -p 9080:9080 \
-v /etc/promtail:/etc/promtail \
-v /var/log/suricata:/var/log/suricata:ro \
-v /var/lib/promtail:/var/lib/promtail \
grafana/promtail:2.9.8 \
-config.file=/etc/promtail/promtail-config.yml
<img width="872" height="507" alt="part4 1" src="https://github.com/user-attachments/assets/46bba4a7-5bbc-492a-905a-55bebee87891" />

What I saw:

The promtail image downloaded successfully.

The container started with no errors.

Running docker ps shows Promtail Up and running on port 9080.

My note:

This means Promtail is now actively watching Suricata’s logs and forwarding them to Loki.

Question 3 Answer:

Promtail is the log collector, and Loki is the log database.

Promtail’s job is to find logs on the system, read them, add labels, and send them to Loki.
Loki’s job is to store the logs and let me search through them later.



Question 4 Answer
Promtail keeps a “position file” to remember how far it has read in eve.json.

This prevents two problems:

It won’t resend old logs each time it restarts. And won’t miss new logs if the container stops and starts again.

**PART5**

Command 
logcli labels --addr=http://localhost:3100
<img width="890" height="483" alt="part5 1" src="https://github.com/user-attachments/assets/36203189-b8d5-487c-be4e-5c6d646d8fcf" />

What I saw:

The command connected to Loki and returned the labels that Loki has collected so far.

My note:

This proves that Promtail is successfully sending Suricata logs into Loki.

Command (Query Suricata logs):
logcli query --addr=http://localhost:3100 --limit=10 '{job="suricata"}'
<img width="881" height="307" alt="part5 2" src="https://github.com/user-attachments/assets/b20d6a14-d619-4d34-b86c-a172dafb0cae" />

What it does:

This command asks Loki for the 10 most recent logs that have the label:

job="suricata"


It’s basically a quick check to confirm Suricata logs are flowing end-to-end through Promtail → Loki → LogCLI.

Question 5 Answer:

Based on LogCLI output:

job="suricata"

filename="/var/log/suricata/eve.json"

host (your machine name)

stream (standard Loki log stream label)

These labels tell Loki where the logs came from and how they should be grouped.

Question 6 Answer:

Labels are small pieces of structured metadata, like job, filename, or host.
Loki uses only these labels to index logs.

Full-text indexes index every word in every log line, which uses a lot more storage and CPU.

**PART6**
Part 6 – Generate Alerts and Analyze
Command:
echo 'alert http any any -> any any (msg:"LAB UA hit"; http.user_agent; content:"CPS-NETSEC-LAB"; sid:9900001; rev:1;)' | sudo tee -a /etc/suricata/rules/local.rules

What I saw:

The rule was successfully appended to local.rules.

My note:

This rule tells Suricata to trigger an alert whenever an HTTP request contains the User-Agent string "CPS-NETSEC-LAB".
The signature ID 9900001 makes this rule unique.

Command:
sudo systemctl restart suricata
sudo suricata -T -c /etc/suricata/suricata.yaml -v

What I saw:

Suricata restarted without errors, and the config test showed “OK”, meaning my rule was loaded correctly.

My note:

Restarting Suricata is required so the new rule becomes active.

Command (Query alerts in Loki):
logcli query --addr=http://localhost:3100 --limit=50 '{job="suricata"} |= "event_type\":\"alert\"" | json | line_format "{{.alert.signature}}"'
<img width="877" height="401" alt="part6" src="https://github.com/user-attachments/assets/a19e7de0-305a-4a96-964a-0f8e7ff6b8db" />

What I saw:

The query returned:

LAB UA hit

My note:

This confirms the entire SIEM pipeline works:
Suricata → Promtail → Loki → LogCLI.

The alert signature "LAB UA hit" appeared exactly as my custom rule defined it.

Question 7 Answer:

The command connected to Loki and searched through all Suricata logs, but only kept the lines that were actual alerts. Then it parsed the alert JSON and printed just the alert signature.


Question 8 Answe:

The alert message that showed up was:

LAB UA hit

**Part 7 **
– Correlation & Aggregation (SIEM Analysis)
Command:
logcli query --addr=http://localhost:3100 --limit=1000 --since=5m \
 '{job="suricata"} |= "event_type\":\"alert\"" | json | line_format "{{.src_ip}} "' \
 | sort | uniq -c | sort -nr | head

What I saw:

The command pulled all Suricata alerts from the last 5 minutes.
It printed only the source IP addresses, then sorted and counted how many times each IP appeared.
The output showed the IPs with the highest alert count at the top.

My note (what the command is doing):

This command basically takes a big pile of raw logs and turns it into a small list of “top talkers.”
Instead of reading every alert, I can instantly see:

Which IP triggered the most alerts

How many times each IP appeared

Which IPs might be attacking or misbehaving

This is real SIEM behavior — taking raw logs and turning them into meaningful signals.

Question 9 Answer:

It shows that a SIEM can group and count related events automatically.
Even if there are hundreds of alerts, the SIEM can correlate them by IP and show patterns.
This reduces noise and makes it obvious when one IP is causing most of the security events.

Question 10 answer:

A SOC analyst can use this to spot potential attackers fast.
If one IP keeps showing up at the top of the list, it’s likely scanning, brute-forcing, or doing something suspicious.
They could:

Block that IP

Check firewall logs

Look for related alerts

Start an incident investigation

It helps the SOC go from “lots of alerts” to “here’s the real threat.”

**PART8**

Part 8 – Create and Test My Own Custom Rule
My custom rule:

I created a new Suricata rule to detect any HTTP request going to a “bad host.”
Here is the rule I added:

alert http any any -> any any (msg:"Custom Bad Host Test"; content:"badtest.com"; http_host; sid:9901234; rev:1;)

What the rule detects:

It looks for HTTP requests where the Host header contains badtest.com.
If I visit or curl a URL with that domain, Suricata should trigger an alert.

How I tested it:
Command I ran:
curl -A "CPS-NETSEC-LAB" http://badtest.com/
<img width="873" height="697" alt="part8" src="https://github.com/user-attachments/assets/8cb5e4c4-1595-45e8-b276-a980a4cbf584" />

What I saw:

In the screenshot, I saw Suricata generate an alert with the message:

"Custom Bad Host Test"

The alert appeared in:

/var/log/suricata/eve.json
Loki 
 LogCLI searches

My note:

Seeing the alert message and the matching domain confirmed that the rule fired correctly.

Question 1: What condition did my rule detect?

My answer:
It detected any HTTP request where the Host header contained badtest.com.
Basically, if my machine tried to reach that domain, Suricata generated an alert.

Question 2: How did I confirm it triggered?

My answer:
I ran a curl request to http://badtest.com and then used:

sudo tail -n 30 /var/log/suricata/eve.json | grep -i "Custom Bad Host Test"


The alert showed up immediately, proving the rule worked.

Question 3: How could I make the rule more specific?

My answer:
I could tighten the detection by adding:

A specific URL path (e.g., /login)

A required user-agent

A specific source IP

A specific destination IP

Flow direction (e.g., only outbound traffic)

Application-layer content (e.g., look for keywords)

Example of a more specific rule:

alert http any any -> any any (msg:"Custom Bad Host Test"; content:"badtest.com"; http_host; content:"/admin"; http_uri; sid:9901234; rev:2;)


This version reduces false positives by requiring two conditions, not just one.

Question 4: Why is fine-tuning rules important?

My answer:
If rules are too broad, they trigger constantly and flood the logs.
That causes:

Alert fatigue

Missed real attacks

Wasted time investigating harmless traffic

Fine-tuned rules help a SOC focus on real threats, not noise.

**PART9**

Command:
sudo docker stop promtail loki
<img width="875" height="776" alt="part9" src="https://github.com/user-attachments/assets/7ec1a077-213e-4d80-9999-31121348f120" />


What I saw:
Both Promtail and Loki containers stopped successfully.

My note:
I shut down the log shipper (Promtail) and the log database (Loki) so I could remove them cleanly.

Command:
sudo docker rm promtail loki
<img width="875" height="776" alt="part9" src="https://github.com/user-attachments/assets/cef66d26-4bd1-429c-95cf-efc89c069e00" />


What I saw:
Docker removed both containers.

My note:
Removing the containers frees up space and makes sure they don’t restart again.

Command:
sudo apt purge -y suricata

<img width="875" height="776" alt="part9" src="https://github.com/user-attachments/assets/3999115a-2bca-4949-addb-5ca6f020cd3f" />

What I saw:
Suricata was fully removed.
There were warnings saying /var/log/suricata and /etc/suricata/rules were not empty, so they were not deleted.

My note:
Purging removes the Suricata package and its config files, but leftover folders remain because they still contain logs and rules.

Command:
sudo docker system prune -a -f

<img width="875" height="776" alt="part9" src="https://github.com/user-attachments/assets/9bed9cdf-2e94-4459-a302-79921667db1a" />

What I saw:
Docker deleted unused images, networks, and cache layers.
About 100MB of space was reclaimed.

My note:
This cleanup removed all the old Loki and Promtail images and cleared unused Docker data to free up disk space.



**SUMMARY**
This lab walked through deploying a functional SIEM pipeline and testing it end-to-end. I installed Suricata to detect traffic, used Promtail to ship logs, stored and indexed them in Loki, and analyzed them through LogCLI. I created and triggered custom alerts, verified they reached the SIEM, and performed correlation queries. The lab demonstrated how detection, forwarding, storage, and analysis fit together in real security operations.

