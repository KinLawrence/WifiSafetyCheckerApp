import tkinter as tk
from tkinter import scrolledtext
import subprocess

def scan_wifi():
    result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                            capture_output=True, text=True)
    return result.stdout

def analyze():
    output.delete(1.0, tk.END)
    data = scan_wifi()

    networks = []
    current = {}

    for line in data.split("\n"):
        line = line.strip()

        if line.startswith("SSID"):
            if current:
                networks.append(current)
                current = {}
            current["SSID"] = line.split(":")[1].strip()

        elif "Authentication" in line:
            current["Auth"] = line.split(":")[1].strip()

    if current:
        networks.append(current)

    for net in networks:
        score = 100
        ssid = net.get("SSID", "")
        auth = net.get("Auth", "")

        if "Open" in auth:
            score -= 50

        if "WEP" in auth:
            score -= 40

        if any(x in ssid.lower() for x in ["free", "guest", "wifi"]):
            score -= 10

        duplicates = [n for n in networks if n["SSID"] == ssid]
        if len(duplicates) > 1:
            score -= 30

        output.insert(tk.END, f"{ssid} → Security Score: {score}/100\n")

root = tk.Tk()
root.title("WiFi Safety Checker")

btn = tk.Button(root, text="Scan Networks", command=analyze)
btn.pack(pady=10)

output = scrolledtext.ScrolledText(root, width=60, height=20)
output.pack()

root.mainloop()