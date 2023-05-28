import tkinter as tk
from tkinter import messagebox
from PIL import ImageTk, Image
import base64


def encode(key, text):
    enc = []
    for i in range(len(text)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(text[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, text):
    dec = []
    text = base64.urlsafe_b64decode(text).decode()
    for i in range(len(text)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(text[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


##### User Interface #####
# window
window = tk.Tk()
window.title("Secret Notes")
window.minsize(450, 810)
window.config(pady=20)
# logo
img = ImageTk.PhotoImage(Image.open("logo.png"))
img_label = tk.Label(window, image=img)
img_label.pack()
# Title
title = tk.Label(text="Enter Your Title", font=("Bahnschrift", 13, "bold"))
title.pack()
title_entry = tk.Entry(width=40, font=("Bahnschrift", 11, "normal"), justify="center")
title_entry.focus()
title_entry.pack()
# secret
secret = tk.Label(text="Enter Your Secret", font=("Bahnschrift", 13, "bold"))
secret.pack()
secret_text = tk.Text(width=40, height=20, font=("Bahnschrift", 11, "normal"))
secret_text.pack()
# master key
master_key = tk.Label(text="Enter Master Key", font=("Bahnschrift", 13, "bold"))
master_key.pack()
master_entry = tk.Entry(width=25, font=("Bahnschrift", 11, "bold"),
                        bd=6, justify="center", show="*")
# show password
cbox_state = tk.IntVar()


def show_hide():
    cbox_value = cbox_state.get()
    if cbox_value == 1:
        master_entry.config(show="")
    else:
        master_entry.config(show="*")


show_pass = tk.Checkbutton(text="Show Password", variable=cbox_state, command=show_hide)
master_entry.pack()
show_pass.pack()


# save
def encrpyt_and_write():
    user_secret = secret_text.get("1.0", "end")
    user_key = master_entry.get()

    if title_entry.get() == "" or secret_text.get("1.0", "end") == "" or master_entry.get() == "":
        messagebox.showwarning(title="Warning!", message="Fill in the blanks !")
    else:
        encoded_msg = encode(user_key, user_secret)
        with open("key.txt", "a") as txt:
            txt.write(f"{title_entry.get()}\n{encoded_msg}\n")

        secret_text.delete("1.0", "end")
        master_entry.delete(0, "end")
        title_entry.delete(0, "end")


save_button = tk.Button(text="Save & Encrypt", width=12, font=("Bahnschrift", 9, "normal"),
                        command=encrpyt_and_write)
save_button.pack()


# decrpyt
def decrypt_and_write():
    if secret_text.get("1.0", "end") == "" or master_entry.get() == "":
        messagebox.showwarning(title="Warning!", message="Fill in the blanks !")
    else:
        try:
            decoded_msg = decode(master_entry.get(), secret_text.get("1.0", "end"))
            secret_text.delete("1.0", "end")
            secret_text.insert("1.0", decoded_msg)
            title_entry.insert(0, "↓↓↓ The decrypted version is below ↓↓↓")
        except:
            messagebox.showwarning(title="Warning!", message="Do not try to decrypt decrypted secrets")




decrpyt_button = tk.Button(text="Decrypt", width=7, font=("Bahnschrift", 9, "normal"),
                           command=decrypt_and_write)
decrpyt_button.pack()

tk.mainloop()
