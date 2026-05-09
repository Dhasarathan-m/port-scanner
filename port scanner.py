import socket
import threading
import time
from tkinter import *
from tkinter import ttk
from queue import Queue

# ---------------- GUI ----------------
root = Tk()
root.title("Port Scanner")
root.geometry("650x550")

queue = Queue()
results_list = []

# ---------------- FUNCTIONS ----------------

def scan(port, target_ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        if s.connect_ex((target_ip, port)) == 0:

            # Risk detection
            common_ports = {
                21: "⚠️ FTP",
                22: "🔐 SSH",
                23: "⚠️ Telnet",
                80: "🌐 HTTP",
                443: "🔒 HTTPS",
                445: "⚠️ SMB",
                3389: "⚠️ RDP"
            }
            risk = common_ports.get(port, "")

            # Service
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"

            # Banner grabbing
            try:
                if port == 80:
                    s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                else:
                    s.send(b"\r\n")

                banner = s.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "No banner"

            # Add result safely to UI
            root.after(0, lambda: insert_result(port, service, banner, risk))

        s.close()
    except:
        pass


def insert_result(port, service, banner, risk):
    tag = "risk" if risk else "safe"
    table.insert("", END, values=(port, service, banner, risk), tags=(tag,))
    results_list.append((port, service, banner, risk))


def worker(target_ip):
    while not queue.empty():
        port = queue.get()
        scan(port, target_ip)

        # update progress safely
        root.after(0, lambda: progress.step(1))

        queue.task_done()


def start_scan():
    # clear old data
    output.delete(1.0, END)
    results_list.clear()
    for row in table.get_children():
        table.delete(row)

    output.insert(END, "Port Scanner Started...\n\n")

    target = target_entry.get()

    try:
        start_port = int(start_entry.get())
        end_port = int(end_entry.get())
    except:
        output.insert(END, "Invalid port range\n")
        return

    try:
        target_ip = socket.gethostbyname(target)
    except:
        output.insert(END, "Invalid target\n")
        return

    total_ports = end_port - start_port + 1
    progress["maximum"] = total_ports
    progress["value"] = 0

    status_label.config(text="Status: Scanning...")
    start_time = time.time()

    for port in range(start_port, end_port + 1):
        queue.put(port)

    # start threads
    for _ in range(50):
        threading.Thread(target=worker, args=(target_ip,), daemon=True).start()

    def finish():
        queue.join()
        end_time = time.time()
        root.after(0, lambda: status_label.config(
            text=f"Scan complete in {round(end_time - start_time, 2)} sec"
        ))

    threading.Thread(target=finish, daemon=True).start()


def save_results():
    with open("gui_results.csv", "w", encoding="utf-8") as f:
        f.write("Port,Service,Banner,Risk\n")
        for row in results_list:
            f.write(",".join(map(str, row)) + "\n")

    output.insert(END, "\nResults saved to gui_results.csv\n")


# ---------------- UI ----------------

Label(root, text="Target IP / Domain").pack()
target_entry = Entry(root, width=40)
target_entry.pack()

Label(root, text="Start Port").pack()
start_entry = Entry(root, width=20)
start_entry.pack()

Label(root, text="End Port").pack()
end_entry = Entry(root, width=20)
end_entry.pack()

# Buttons
Button(root, text="Start Scan", command=start_scan).pack(pady=5)
Button(root, text="Save Results", command=save_results).pack(pady=5)

# Output box
output = Text(root, height=8, width=75)
output.pack(pady=5)
output.tag_config("safe", foreground="green")
output.tag_config("risk", foreground="red")

# Table
columns = ("Port", "Service", "Banner", "Risk")
table = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    table.heading(col, text=col)
    table.column(col, anchor="center", width=140)

table.tag_configure("risk", background="lightcoral")
table.tag_configure("safe", background="lightgreen")

# Scrollbar
scrollbar = Scrollbar(root, orient=VERTICAL, command=table.yview)
table.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side=RIGHT, fill=Y)
table.pack(fill=BOTH, expand=True, pady=5)

# Progress bar
progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress.pack(pady=5)

# Status label
status_label = Label(root, text="Status: Idle")
status_label.pack()

# ---------------- RUN ----------------
root.mainloop()