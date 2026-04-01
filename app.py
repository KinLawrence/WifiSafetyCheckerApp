import tkinter as tk
from tkinter import scrolledtext
import subprocess

def scan_wifi():
    """
    Scans for available WiFi networks using the Windows netsh command.
    Returns the raw output from the command.
    """
    # Execute the netsh command to show available wireless networks
    result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                            capture_output=True, text=True)
    return result.stdout

def analyze(output_widget):
    """
    Parses the WiFi scan data, calculates a safety score for each network,
    and displays the results in the provided text widget.
    """
    # Clear previous results from the output window
    output_widget.delete(1.0, tk.END)
    
    # Get raw data from the wifi scan
    data = scan_wifi()

    networks = []
    current = {}

    # Parse the raw text output to extract SSID and Authentication types
    for line in data.split("\n"):
        line = line.strip()

        # Identify the start of a network block (SSID)
        if line.startswith("SSID"):
            if current:
                networks.append(current)
                current = {}
            # Extract and clean the SSID name
            parts = line.split(":", 1)
            if len(parts) > 1:
                current["SSID"] = parts[1].strip()

        # Identify the authentication/security type
        elif "Authentication" in line:
            parts = line.split(":", 1)
            if len(parts) > 1:
                current["Auth"] = parts[1].strip()

    # Append the last network found in the loop
    if current:
        networks.append(current)

    # Analyze each network and calculate a safety score
    for net in networks:
        score = 100  # Start with a perfect score
        ssid = net.get("SSID", "Unknown SSID")
        auth = net.get("Auth", "Unknown")

        # Penalty for 'Open' networks (No password requirement)
        if "Open" in auth:
            score -= 50

        # Penalty for 'WEP' protocol (Known to be insecure)
        if "WEP" in auth:
            score -= 40

        # Penalty for generic names often used by phishing hotspots
        if any(x in ssid.lower() for x in ["free", "guest", "wifi"]):
            score -= 10

        # Penalty if multiple networks share the same name (Potential Evil Twin attack)
        duplicates = [n for n in networks if n.get("SSID") == ssid]
        if len(duplicates) > 1:
            score -= 30

        # Display the result to the user
        output_widget.insert(tk.END, f"{ssid} → Security Score: {score}/100\n")

def main():
    """
    Main entry point for the WiFi Safety Checker application.
    Initializes the GUI and handles the main event loop.
    """
    # Initialize the main window
    root = tk.Tk()
    root.title("WiFi Safety Checker")

    # Create a layout container for the UI elements
    # Create the text output area first so it can be passed to the analyze command
    output_display = scrolledtext.ScrolledText(root, width=60, height=20)
    
    # Create the trigger button
    # Using a lambda to pass the output_display widget to the analyze function
    btn = tk.Button(root, text="Scan Networks", command=lambda: analyze(output_display))
    btn.pack(pady=10)

    # Pack the output display into the window
    output_display.pack(padx=10, pady=10)

    # Start the Tkinter event loop
    root.mainloop()

# Execute the main function if the script is run directly
if __name__ == "__main__":
    main()