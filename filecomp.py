
import os
import pyzipper
from tkinter import Tk, filedialog, messagebox, Button, Label, Frame, Listbox, Scrollbar, VERTICAL, RIGHT, Y, END, BOTH, simpledialog

# Function to compress files with password
def compress_files(file_paths, output_zip, password):
    total_original_size = 0
    total_compressed_size = 0
    output_details = []
    with pyzipper.AESZipFile(output_zip, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zipf:
        zipf.pwd = password.encode()
        for file in file_paths:
            zipf.write(file, os.path.basename(file))
            original_size = os.path.getsize(file)
            compressed_size = zipf.getinfo(os.path.basename(file)).compress_size
            compression_ratio = (compressed_size / original_size) * 100

            output_details.append(f"{os.path.basename(file)} - Original Size: {original_size} bytes, Compressed Size: {compressed_size} bytes, Compression Ratio: {compression_ratio:.2f}%")

            total_original_size += original_size
            total_compressed_size += compressed_size

    overall_ratio = (total_compressed_size / total_original_size) * 100 if total_original_size else 0
    output_details.append(f"\nTotal Original Size: {total_original_size} bytes, Total Compressed Size: {total_compressed_size} bytes, Overall Compression Ratio: {overall_ratio:.2f}%")

    show_output("\n".join(output_details))
    messagebox.showinfo("Success", f"Files compressed into {output_zip}")

# Function to decompress files with password
# Function to decompress files with password
def decompress_file(zip_path, extract_to, password):
    try:
        with pyzipper.AESZipFile(zip_path, 'r', encryption=pyzipper.WZ_AES) as zipf:
            zipf.pwd = password.encode()
            zipf.extractall(extract_to)
        messagebox.showinfo("Success", f"Files extracted to {extract_to}")
    except RuntimeError as e:
        # Handle incorrect password or other decryption issues
        messagebox.showerror("Error", "Incorrect password or corrupted file. Please try again.")
    except Exception as e:
        # Handle other exceptions (e.g., file not found, permission error)
        messagebox.showerror("Error", f"An error occurred: {e}")


# Function to select files for compression
def select_files_for_compression():
    files = filedialog.askopenfilenames(title="Select files for compression")
    if files:
        output_zip = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("Zip files", "*.zip")])
        if output_zip:
            password = simpledialog.askstring("Password", "Enter password:", show='*')
            if password:
                compress_files(files, output_zip, password)

# Function to select a zip file for decompression
def select_zip_for_decompression():
    zip_path = filedialog.askopenfilename(title="Select a zip file", filetypes=[("Zip files", "*.zip")])
    if zip_path:
        extract_to = filedialog.askdirectory(title="Select extraction directory")
        if extract_to:
            password = simpledialog.askstring("Password", "Enter password:", show='*')
            if password:
                decompress_file(zip_path, extract_to, password)

# Function to show output details in a text box
def show_output(details):
    output_window = Tk()
    output_window.title("Compression Details")

    frame = Frame(output_window)
    frame.pack(fill=BOTH, expand=True)

    scrollbar = Scrollbar(frame, orient=VERTICAL)
    output_listbox = Listbox(frame, yscrollcommand=scrollbar.set, font=("Courier", 12))
    scrollbar.config(command=output_listbox.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    output_listbox.pack(fill=BOTH, expand=True)

    for line in details.split("\n"):
        output_listbox.insert(END, line)

    output_window.mainloop()

# Main function to create the user interface
def main():
    root = Tk()
    root.title("File Zipper")

    # Create the main frame
    main_frame = Frame(root)
    main_frame.pack(pady=20, padx=20, fill=BOTH, expand=True)

    # Add buttons to the main frame
    compress_button = Button(main_frame, text="Compress Files", command=select_files_for_compression, height=4, width=20)
    compress_button.pack(pady=10)

    decompress_button = Button(main_frame, text="Decompress File", command=select_zip_for_decompression, height=4, width=20)
    decompress_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()

