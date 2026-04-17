import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import subprocess
import datetime
import csv
import re

def scan_wifi():
    """
    Scans for available WiFi networks using the Windows netsh command.
    Returns the raw output from the command.
    """
    # Execute the netsh command to show available wireless networks
    result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                            capture_output=True, text=True)
    return result.stdout

def get_current_connection():
    """
    Retrieves the currently connected WiFi SSID and its local IP address.
    """
    ssid = ""
    ip = ""
    interface_name = ""
    
    # Get current interface info to find SSID and Interface Name
    try:
        if_result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
        for line in if_result.stdout.split("\n"):
            if "Name" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    interface_name = parts[1].strip()
            elif "SSID" in line and "BSSID" not in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    ssid = parts[1].strip()
        
        # If we have an interface name, get its IP specifically
        if interface_name:
            cfg_result = subprocess.run(["netsh", "interface", "ip", "show", "config", f"name={interface_name}"], 
                                         capture_output=True, text=True)
            for line in cfg_result.stdout.split("\n"):
                if "IP Address" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        break
    except Exception:
        pass
        
    return ssid, ip

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

    # Get the current connection info for reference
    current_ssid, current_ip = get_current_connection()

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
        display_name = ssid
        if ssid == current_ssid and current_ip:
            display_name = f"{ssid} ({current_ip})"
            
        output_widget.insert(tk.END, f"{display_name} → Security Score: {score}/100\n")

def export_results(output_widget):
    """
    Exports the content of the output widget to a .txt or .csv file.
    """
    content = output_widget.get(1.0, tk.END).strip()
    if not content:
        messagebox.showwarning("Export Warning", "No scan results to export. Please run a scan first.")
        return

    # Open file dialog to choose save location and format
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")],
        initialfile=f"wifi_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
        title="Save Scan Results"
    )

    if file_path:
        try:
            if file_path.lower().endswith(".csv"):
                # Export as CSV
                with open(file_path, "w", encoding="utf-8", newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["SSID", "Security Score", "Scale"])
                    
                    # Parse the content from the widget: "SSID → Security Score: SCORE/100"
                    lines = content.split('\n')
                    for line in lines:
                        if "→ Security Score:" in line:
                            # Using regex to capture SSID and Score
                            match = re.search(r"^(.*?) → Security Score: (\d+)/100", line)
                            if match:
                                ssid = match.group(1).strip()
                                score = match.group(2).strip()
                                writer.writerow([ssid, score, "100"])
            else:
                # Export as TXT
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(f"WiFi Safety Scan Results\n")
                    file.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    file.write("-" * 30 + "\n")
                    file.write(content)
            
            messagebox.showinfo("Export Successful", f"Results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save file: {e}")

def main():
    """
    Main entry point for the WiFi Safety Checker application.
    Initializes the GUI and handles the main event loop.
    """
    # Initialize the main window
    root = tk.Tk()
    root.title("WiFi Safety Checker")

    # Enlarge the GUI to 1/4 of the screen (1/2 width and 1/2 height)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    width = screen_width // 2
    height = screen_height // 2
    
    # Calculate position to center the window
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    
    root.geometry(f"{width}x{height}+{x}+{y}")

    # Ensure the window "pops out" (brings it to front and focuses)
    root.lift()
    root.attributes('-topmost', True)
    root.after(100, lambda: root.attributes('-topmost', False))
    root.focus_force()

    # Real-time clock display (Top Left)
    time_label = tk.Label(root, font=("Helvetica", 10, "italic"), fg="#7f8c8d")
    time_label.pack(side=tk.TOP, anchor="nw", padx=15, pady=(10, 0))

    def refresh_clock():
        """Updates the real-time clock label every second."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        time_label.config(text=f"System Time: {now}")
        root.after(1000, refresh_clock)

    refresh_clock()

    # Create the trigger buttons container first and pack at bottom
    btn_frame = tk.Frame(root)
    btn_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=20)

    # Create the text output area
    output_display = scrolledtext.ScrolledText(root, font=("Consolas", 11))
    # Pack it to fill the remaining space
    output_display.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)

    # Define a larger, more visible font for the buttons
    btn_font = ("Helvetica", 14, "bold")

    # Scan button - High visibility styling
    scan_btn = tk.Button(btn_frame, 
                         text="Scan Networks", 
                         font=btn_font, 
                         bg="#2ecc71", 
                         fg="white",
                         padx=30, 
                         pady=15,
                         command=lambda: analyze(output_display))
    scan_btn.pack(side=tk.LEFT, expand=True, padx=20)

    # Export button - High visibility styling
    export_btn = tk.Button(btn_frame, 
                           text="Export Results...", 
                           font=btn_font, 
                           bg="#3498db", 
                           fg="white",
                           padx=30, 
                           pady=15,
                           command=lambda: export_results(output_display))
    export_btn.pack(side=tk.LEFT, expand=True, padx=20)

    # Start the Tkinter event loop
    root.mainloop()

# Execute the main function if the script is run directly
if __name__ == "__main__":
    main()