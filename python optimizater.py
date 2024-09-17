import os
import time
import tempfile
import psutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Function to delete selected large files
def delete_selected_files(file_list, listbox):
    selected_indices = listbox.curselection()  # Get selected indices
    if not selected_indices:
        messagebox.showwarning("No Selection", "Please select files to delete.")
        return

    deleted_files = []
    for index in selected_indices:
        file_to_delete = file_list[index]
        try:
            os.remove(file_to_delete)
            deleted_files.append(file_to_delete)
        except Exception as e:
            messagebox.showerror("Error", f"Error deleting {file_to_delete}: {e}")

    if deleted_files:
        result = "\n".join(deleted_files)
        messagebox.showinfo("Success", f"Deleted files:\n{result}")
        for index in sorted(selected_indices, reverse=True):
            listbox.delete(index)
        for file in deleted_files:
            file_list.remove(file)

# Function to clean cache (temporary files)
def clean_cache(result_box=None):
    temp_dir = tempfile.gettempdir()
    files_deleted = 0

    result_box.delete(1.0, tk.END)  # Clear the result box before starting

    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                os.remove(file_path)
                result_box.insert(tk.END, f"Deleted: {file_path}\n")
                result_box.yview(tk.END)  # Auto-scroll to the end
                files_deleted += 1
            except Exception as e:
                result_box.insert(tk.END, f"Error deleting {file_path}: {e}\n")
                result_box.yview(tk.END)

    messagebox.showinfo("Cache Cleaned", f"Deleted {files_deleted} temporary files.")

# Storage Cleaner with live progress and option to delete selected files
def clean_storage(threshold_mb=100, progress=None, result_box=None, file_list=None, listbox=None):
    home_dir = filedialog.askdirectory(title="Select Directory to Scan") or os.path.expanduser("~")
    if not home_dir:
        return
    large_files = []
    total_files = sum([len(files) for r, d, files in os.walk(home_dir)])
    file_count = 0

    result_box.delete(1.0, tk.END)
    listbox.delete(0, tk.END)

    for root, dirs, files in os.walk(home_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                if file_size_mb > threshold_mb:
                    large_files.append(file_path)
                    result_box.insert(tk.END, f"Large file: {file_path} ({file_size_mb:.2f} MB)\n")
                    result_box.yview(tk.END)
                    listbox.insert(tk.END, file_path)
            except Exception as e:
                result_box.insert(tk.END, f"Error accessing {file_path}: {e}\n")
                result_box.yview(tk.END)
            file_count += 1
            if progress:
                progress['value'] = (file_count / total_files) * 100
                result_box.update()

    file_list.extend(large_files)
    if large_files:
        messagebox.showinfo("Scan Complete", f"Found {len(large_files)} large files.")
    else:
        messagebox.showinfo("Scan Complete", "No large files found.")

# Virus Scan with live progress and estimated wait time
def virus_scan(progress=None, result_box=None, time_box=None):
    suspicious_patterns = ['virus', 'malware', 'ransomware', 'spyware']
    drive = filedialog.askdirectory(title="Select Drive to Scan") or "C:/"
    if not drive:
        return
    suspicious_files = []
    total_files = sum([len(files) for r, d, files in os.walk(drive)])
    file_count = 0

    result_box.delete(1.0, tk.END)
    time_box.delete(1.0, tk.END)  # Clear the time box before starting

    start_time = time.time()
    for root, dirs, files in os.walk(drive):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if 'Windows' in root or 'Program Files' in root or 'AppData' in root:
                    continue
                if any(pattern in file.lower() for pattern in suspicious_patterns):
                    suspicious_files.append(file_path)
                    result_box.insert(tk.END, f"Suspicious file: {file_path}\n")
                    result_box.yview(tk.END)
            except PermissionError:
                result_box.insert(tk.END, f"Permission Denied: {file_path}\n")
                result_box.yview(tk.END)
            except Exception as e:
                result_box.insert(tk.END, f"Error scanning {file_path}: {e}\n")
                result_box.yview(tk.END)

            file_count += 1
            if progress:
                progress['value'] = (file_count / total_files) * 100
                result_box.update()

            # Update estimated time every 100 files
            if file_count % 100 == 0:
                elapsed_time = time.time() - start_time
                estimated_total_time = (elapsed_time / file_count) * total_files
                estimated_remaining_time = estimated_total_time - elapsed_time
                time_box.delete(1.0, tk.END)
                time_box.insert(tk.END, f"Estimated remaining time: {estimated_remaining_time:.2f} seconds\n")
                time_box.yview(tk.END)

    if suspicious_files:
        result = "\n".join(suspicious_files)
        user_response = messagebox.askyesno("Suspicious Files Found", f"Found suspicious files:\n{result}\n\nDo you want to delete these files?")
        if user_response:
            for file in suspicious_files:
                try:
                    os.remove(file)
                except Exception as e:
                    result_box.insert(tk.END, f"Error deleting {file}: {e}\n")
            messagebox.showinfo("Deletion Complete", "Suspicious files have been deleted.")
    else:
        messagebox.showinfo("Scan Complete", "No suspicious files found.")

# Function to run long tasks in a separate thread
def run_in_thread(target, *args):
    def wrapper():
        try:
            target(*args)
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            enable_buttons()

    thread = threading.Thread(target=wrapper)
    thread.start()

# Disable buttons while processing
def disable_buttons():
    for button in buttons:
        button.config(state=tk.DISABLED)

# Enable buttons after processing
def enable_buttons():
    for button in buttons:
        button.config(state=tk.NORMAL)

# Scrollable frame for buttons
def create_scrollable_frame(parent):
    canvas = tk.Canvas(parent)
    scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    return scrollable_frame

# GUI Code with scrollable frame for buttons and a separate time box
def create_gui():
    global buttons
    window = tk.Tk()
    window.title("PC Optimization Software")
    window.geometry("900x600")

    # Style configuration
    style = ttk.Style()
    style.configure("TButton", padding=6, relief="flat", background="#ccc")

    # Frame for result and time boxes
    main_frame = tk.Frame(window)
    main_frame.pack(fill="both", expand=True)

    # Text box for live result updates with scrollbars
    result_frame = tk.Frame(main_frame)
    result_frame.pack(side="left", padx=10, pady=10, fill="both", expand=True)

    result_box = tk.Text(result_frame, wrap="none", height=15, width=60, relief="sunken", borderwidth=2)
    result_box.pack(side="left", fill="both", expand=True)

    result_scrollbar_v = ttk.Scrollbar(result_frame, orient="vertical", command=result_box.yview)
    result_scrollbar_v.pack(side="right", fill="y")
    result_box.config(yscrollcommand=result_scrollbar_v.set)

    result_scrollbar_h = ttk.Scrollbar(result_frame, orient="horizontal", command=result_box.xview)
    result_scrollbar_h.pack(side="bottom", fill="x")
    result_box.config(xscrollcommand=result_scrollbar_h.set)

    # Frame for estimated time
    time_frame = tk.Frame(main_frame)
    time_frame.pack(side="right", padx=10, pady=10, fill="both", expand=False)

    time_box = tk.Text(time_frame, wrap="none", height=15, width=40, relief="sunken", borderwidth=2)
    time_box.pack(side="left", fill="both", expand=True)

    time_scrollbar_v = ttk.Scrollbar(time_frame, orient="vertical", command=time_box.yview)
    time_scrollbar_v.pack(side="right", fill="y")
    time_box.config(yscrollcommand=time_scrollbar_v.set)

    time_scrollbar_h = ttk.Scrollbar(time_frame, orient="horizontal", command=time_box.xview)
    time_scrollbar_h.pack(side="bottom", fill="x")
    time_box.config(xscrollcommand=time_scrollbar_h.set)

    # Progress Bar
    progress = ttk.Progressbar(window, orient="horizontal", length=800, mode="determinate")
    progress.pack(pady=10)

    # Listbox for displaying large files
    file_list = []
    listbox = tk.Listbox(window, selectmode=tk.MULTIPLE, height=6, width=80)
    listbox.pack(pady=10)

    # Scrollable frame for buttons
    scrollable_frame = create_scrollable_frame(window)

    # Buttons inside the scrollable frame
    buttons = []

    clean_cache_button = tk.Button(scrollable_frame, text="Clean Cache", command=lambda: run_in_thread(clean_cache, result_box), width=25)
    clean_cache_button.pack(pady=10)
    buttons.append(clean_cache_button)

    clean_storage_button = tk.Button(scrollable_frame, text="Clean Storage", command=lambda: run_in_thread(clean_storage, 100, progress, result_box, file_list, listbox), width=25)
    clean_storage_button.pack(pady=10)
    buttons.append(clean_storage_button)

    delete_files_button = tk.Button(scrollable_frame, text="Delete Selected Files", command=lambda: delete_selected_files(file_list, listbox), width=25)
    delete_files_button.pack(pady=10)
    buttons.append(delete_files_button)

    virus_scan_button = tk.Button(scrollable_frame, text="Virus Scan", command=lambda: run_in_thread(virus_scan, progress, result_box, time_box), width=25)
    virus_scan_button.pack(pady=10)
    buttons.append(virus_scan_button)

    optimize_os_button = tk.Button(scrollable_frame, text="Optimize OS", command=lambda: messagebox.showinfo("Optimization", "Optimization not implemented yet"), width=25)
    optimize_os_button.pack(pady=10)
    buttons.append(optimize_os_button)

    exit_button = tk.Button(scrollable_frame, text="Exit", command=window.quit, width=25)
    exit_button.pack(pady=10)
    buttons.append(exit_button)

    window.mainloop()

# Main function to call all optimizations
if __name__ == "__main__":
    create_gui()
