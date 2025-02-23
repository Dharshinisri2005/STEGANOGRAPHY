import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from stegano_utils import encrypt_message, decrypt_message, encode_image, decode_image

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 AES-256 Steganography")
        self.root.geometry("500x450")

        self.img_path = ""

        tk.Label(root, text="🔒 Secure Image Steganography", font=("Arial", 16)).pack(pady=10)
        tk.Button(root, text="Select Image", command=self.select_image).pack(pady=5)

        tk.Label(root, text="Secret Message:").pack()
        self.msg_entry = tk.Entry(root, width=50)
        self.msg_entry.pack(pady=5)

        tk.Label(root, text="🔑 Password:").pack()
        self.password_entry = tk.Entry(root, width=50, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(root, text="Hide Message", command=self.hide_message).pack(pady=5)
        tk.Button(root, text="Extract Message", command=self.extract_message).pack(pady=5)

        self.output_label = tk.Label(root, text="")
        self.output_label.pack(pady=10)

    def select_image(self):
        self.img_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if self.img_path:
            img = Image.open(self.img_path)
            img.thumbnail((150, 150))
            img = ImageTk.PhotoImage(img)
            self.img_label = tk.Label(self.root, image=img)
            self.img_label.image = img
            self.img_label.pack()

    def hide_message(self):
        if not self.img_path:
            messagebox.showerror("Error", "Please select an image first!")
            return

        message = self.msg_entry.get()
        password = self.password_entry.get()

        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return

        encrypted_msg = encrypt_message(message, password)
        encoded_img_path = encode_image(self.img_path, encrypted_msg)
        messagebox.showinfo("Success", f"Message hidden in {encoded_img_path}")

    def extract_message(self):
        if not self.img_path:
            messagebox.showerror("Error", "Please select an image first!")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return

        extracted_msg = decode_image(self.img_path)
        decrypted_msg = decrypt_message(extracted_msg, password)

        self.output_label.config(text=f"Extracted Message: {decrypted_msg}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
