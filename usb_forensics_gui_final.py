#USB FORENSICS TOOL V4 WITH UNAUTHORIZED USB BLOCKING
import tkinter as tk
from tkinter import scrolledtext, messagebox, font
import subprocess
import re
import os
from datetime import datetime

# Define the log file path and patterns
LOG_FILE_PATH = "/var/log/syslog"
USB_EVENT_PATTERN = r".*kernel: usb (\d+-\d+): (.*)"
REPORT_FILENAME = '/home/shourya-kakkar/usb_forensics_tool/usb_forensics_report.txt'

# Example whitelist of authorized USB devices
WHITELIST = [
    # Add authorized devices here...
    {"idVendor": "1d6b", "idProduct": "0002", "name": "Linux Foundation 2.0 root hub"},
    {"idVendor": "1d6b", "idProduct": "0003", "name": "Linux Foundation 3.0 root hub"},
    {"idVendor": "13d3", "idProduct": "3594", "name": "IMC Networks Wireless_Device"},
    {"idVendor": "0bda", "idProduct": "8179", "name": "Realtek Semiconductor Corp. RTL8188EUS 802.11n Wireless Network Adapter"}
]

class USBForensicsGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("USB Forensics Tool")
        self.geometry("1000x600")
        self.configure(bg="#f0f0f0")
        self.create_widgets()

    def create_widgets(self):
        # Define custom font
        custom_font = font.Font(family="Helvetica", size=12)

        # Title Label
        title_label = tk.Label(self, text="USB Forensics Tool", font=("Helvetica", 18, "bold"), bg="#f0f0f0")
        title_label.pack(pady=10)

        # Buttons with improved styling
        button_frame = tk.Frame(self, bg="#f0f0f0")
        button_frame.pack(fill=tk.X, pady=10, padx=10)

        button_style = {'bg': '#4CAF50', 'fg': '#ffffff', 'font': custom_font, 'bd': 2, 'relief': tk.RAISED}
        tk.Button(button_frame, text="Display USB Events", command=self.display_usb_events, **button_style).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(button_frame, text="List USB Devices", command=self.list_usb_devices, **button_style).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(button_frame, text="Generate Report", command=self.generate_report, **button_style).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(button_frame, text="Monitor USB Activity", command=self.monitor_usb_activity, **button_style).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(button_frame, text="Check Unauthorized USB's", command=self.check_unauthorized_usb, **button_style).pack(side=tk.LEFT, padx=5, pady=5)

        # Text area for output
        self.output_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=custom_font, bg="#ffffff", fg="#000000")
        self.output_area.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w', bg="#d3d3d3")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self, message):
        self.status_var.set(message)
        self.update_idletasks()

    def display_usb_events(self):
        self.output_area.delete('1.0', tk.END)
        events = self.parse_usb_events()
        if events:
            for event in events:
                self.output_area.insert(tk.END, f"Time: {event['time']}, USB Bus: {event['usb_bus']}, Event Info: {event['event_info']}\n")
        else:
            self.output_area.insert(tk.END, "No USB events found.\n")

    def list_usb_devices(self):
        self.output_area.delete('1.0', tk.END)
        result = subprocess.run(['lsusb'], stdout=subprocess.PIPE)
        self.output_area.insert(tk.END, result.stdout.decode('utf-8'))

    def generate_report(self):
        self.output_area.delete('1.0', tk.END)
        events = self.parse_usb_events()
        if events:
            try:
                self.create_report(events)
                self.output_area.insert(tk.END, f"USB Forensics Report saved as {REPORT_FILENAME}.\n")
            except Exception as e:
                self.output_area.insert(tk.END, f"Failed to create report: {e}\n")
        else:
            self.output_area.insert(tk.END, "No USB events found to generate a report.\n")

    def monitor_usb_activity(self):
        self.output_area.delete('1.0', tk.END)
        self.output_area.insert(tk.END, "Monitoring USB activity in real-time...\n")
        self.update_status("Monitoring USB activity...")
        self.update_usb_activity()

    def check_unauthorized_usb(self):
        self.output_area.delete('1.0', tk.END)
        result = subprocess.run(['lsusb'], stdout=subprocess.PIPE)
        devices = result.stdout.decode('utf-8').splitlines()
        unauthorized_devices = []

        for device in devices:
            match = re.search(r"ID (\w+):(\w+)", device)
            if match:
                idVendor = match.group(1)
                idProduct = match.group(2)
                # Check if device is not in the whitelist
                if not any(device for device in WHITELIST if device['idVendor'] == idVendor and device['idProduct'] == idProduct):
                    # Capture the product name from the lsusb output
                    product_name_match = re.search(r"ID \w+:\w+ (.+)", device)
                    product_name = product_name_match.group(1).strip() if product_name_match else "Unknown Device"
                    unauthorized_devices.append((idVendor, idProduct, product_name))

        if unauthorized_devices:
            for vendor_id, product_id, product_name in unauthorized_devices:
                self.alert_unauthorized_device(vendor_id, product_id, product_name)
        else:
            self.output_area.insert(tk.END, "All connected USB devices are authorized.\n")

    def alert_unauthorized_device(self, vendor_id, product_id, product_name):
        message = f"Unauthorized USB device detected!\nVendor ID: {vendor_id}\nProduct ID: {product_id}\nProduct Name: {product_name}\n"
        self.output_area.insert(tk.END, message + "\n")
        self.update_status("Unauthorized USB device detected!")
        messagebox.showwarning("Alert", message)

        # Ask user if they want to add the device to the whitelist
        add_to_whitelist = messagebox.askyesno("Add to Whitelist", "Do you want to add this device to the whitelist?")
        if add_to_whitelist:
            self.add_to_whitelist(vendor_id, product_id, product_name)

        # Block the USB device (using usbguard or similar tool)
        self.block_usb_device(vendor_id, product_id)

    def add_to_whitelist(self, vendor_id, product_id, product_name):
        # Add the device to the whitelist
        new_device = {"idVendor": vendor_id, "idProduct": product_id, "product_name": product_name}
        WHITELIST.append(new_device)
        self.output_area.insert(tk.END, f"Device {product_name} (Vendor ID: {vendor_id}, Product ID: {product_id}) added to whitelist.\n")

    def block_usb_device(self, vendor_id, product_id):
        try:
            # Example command to block the USB device using usbguard
            # This command blocks the device with the given vendor and product ID
            device_id = f"{vendor_id}:{product_id}"
            subprocess.run(['usbguard', 'block-device', device_id], check=True)
            self.output_area.insert(tk.END, f"Access to USB device (Vendor ID: {vendor_id}, Product ID: {product_id}) has been blocked.\n")
        except subprocess.CalledProcessError as e:
            self.output_area.insert(tk.END, f"Failed to block USB device: {e}\n")
        except Exception as e:
            self.output_area.insert(tk.END, f"Unexpected error: {e}\n")


    def reauthorize_usb_device(self, vendor_id, product_id):
        try:
            # Example command to reauthorize the USB device using usbguard
            device_id = f"{vendor_id}:{product_id}"
            subprocess.run(['usbguard', 'allow-device', device_id], check=True)
            self.output_area.insert(tk.END, f"USB device (Vendor ID: {vendor_id}, Product ID: {product_id}) has been reauthorized.\n")
        except subprocess.CalledProcessError as e:
            self.output_area.insert(tk.END, f"Failed to reauthorize USB device: {e}\n")
        except Exception as e:
            self.output_area.insert(tk.END, f"Unexpected error: {e}\n")


    def parse_usb_events(self):
        events = []
        if os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, 'r') as log_file:
                for line in log_file:
                    match = re.match(USB_EVENT_PATTERN, line)
                    if match:
                        event_time = datetime.now()
                        usb_bus = match.group(1)
                        event_info = match.group(2)

                        event = {
                            "time": event_time,
                            "usb_bus": usb_bus,
                            "event_info": event_info,
                        }
                        events.append(event)
        else:
            print(f"Log file not found: {LOG_FILE_PATH}")
        return events

    def create_report(self, events):
        if not events:
            print("No events to write to the report.")
        try:
            with open(REPORT_FILENAME, 'w') as report_file:
                report_file.write("USB Forensics Report\n")
                report_file.write("=" * 40 + "\n")
                for event in events:
                    report_file.write(f"Time: {event['time']}\n")
                    report_file.write(f"USB Bus: {event['usb_bus']}\n")
                    report_file.write(f"Event Info: {event['event_info']}\n")
                    report_file.write("-" * 40 + "\n")
                report_file.write(f"Total USB Events: {len(events)}\n")
        except Exception as e:
            raise Exception(f"Failed to write report file: {e}")

    def update_usb_activity(self):
        def monitor():
            process = subprocess.Popen(['udevadm', 'monitor', '--udev', '--subsystem-match=usb'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                while True:
                    output = process.stdout.readline().decode('utf-8').strip()
                    if output:
                        self.output_area.insert(tk.END, f"USB Event: {output}\n")
                        self.output_area.yview(tk.END)
                        self.update_idletasks()
            except KeyboardInterrupt:
                process.terminate()
                self.output_area.insert(tk.END, "Monitoring stopped.\n")
                self.update_status("Ready")
        
        # Run the monitor in a separate thread to avoid blocking the GUI
        import threading
        thread = threading.Thread(target=monitor)
        thread.daemon = True
        thread.start()

# Run the GUI application
if __name__ == "__main__":
    app = USBForensicsGUI()
    app.mainloop()
