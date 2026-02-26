import tkinter as tk
import tkinterdnd2 as tkdnd
from tkinter import filedialog
from functions import encrypt_message, decrypt_without_key, decrypt_with_key

current_decrypt_image = ""
current_mode = "encrypt"

BG = "#f6f1e7"
SURFACE = "#ffffff"
BORDER = "#e4d7c8"
TEXT = "#2b2117"
MUTED = "#6f5b49"
PRIMARY = "#b7791f"
PRIMARY_HOVER = "#975a16"
BUTTON_BG = "#efe6d8"
ENTRY_BG = "#fffaf2"
ENTRY_FG = TEXT

FONT_H1 = ("Segoe UI", 20, "bold")
FONT_H2 = ("Segoe UI", 14, "bold")
FONT_BODY = ("Segoe UI", 11)


def center_popup(win, parent):
    win.update_idletasks()
    parent.update_idletasks()

    pw = parent.winfo_width()
    ph = parent.winfo_height()
    px = parent.winfo_rootx()
    py = parent.winfo_rooty()

    ww = win.winfo_width()
    wh = win.winfo_height()

    x = px + max((pw - ww) // 2, 0)
    y = py + max((ph - wh) // 2, 0)
    win.geometry(f"{ww}x{wh}+{x}+{y}")


def prepare_popup(win):
    win.transient(root)
    win.lift()
    win.grab_set()
    center_popup(win, root)


def show_popup(title, message, *, kind="info"):
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.geometry("520x240")
    dialog.configure(bg=BG)
    dialog.resizable(False, False)
    prepare_popup(dialog)

    header = tk.Frame(dialog, bg=BG)
    header.pack(fill=tk.X, padx=18, pady=(18, 8))

    icon_map = {
        "info": "i",
        "success": "✓",
        "error": "!",
    }
    icon = icon_map.get(kind, "i")
    accent = PRIMARY if kind != "error" else "#b42318"

    icon_label = tk.Label(
        header,
        text=icon,
        font=(FONT_H1[0], 18, "bold"),
        fg="#ffffff",
        bg=accent,
        width=2,
        height=1,
    )
    icon_label.pack(side=tk.LEFT)
    make_label(header, text=title, font=FONT_H2, bg=BG).pack(side=tk.LEFT, padx=12)

    body = make_text(dialog, wrap=tk.WORD, width=60, height=6)
    body.insert(tk.END, message)
    body.config(state=tk.DISABLED)
    body.pack(padx=18, pady=(0, 12), fill=tk.BOTH, expand=True)

    def close():
        dialog.destroy()

    make_button(dialog, "OK", close, kind="primary", width=10).pack(pady=(0, 16))
    dialog.bind("<Return>", lambda e: close())
    dialog.bind("<Escape>", lambda e: close())


def style_root():
    root.configure(bg=BG)
    root.minsize(620, 460)
    root.resizable(True, True)


def make_label(parent, text, *, font=FONT_BODY, fg=TEXT, bg=None, **kwargs):
    return tk.Label(parent, text=text, font=font, fg=fg, bg=(BG if bg is None else bg), **kwargs)


def make_button(parent, text, command, *, kind="primary", width=18, **kwargs):
    if kind == "primary":
        bg = PRIMARY
        active = PRIMARY_HOVER
        fg = "#ffffff"
    elif kind == "ghost":
        bg = BG
        active = SURFACE
        fg = TEXT
    elif kind == "back":
        bg = BG
        active = BUTTON_BG
        fg = PRIMARY_HOVER
    else:
        bg = BUTTON_BG
        active = SURFACE
        fg = TEXT

    return tk.Button(
        parent,
        text=text,
        command=command,
        width=width,
        bg=bg,
        activebackground=active,
        fg=fg,
        activeforeground=fg,
        relief=tk.FLAT,
        bd=0,
        highlightthickness=0,
        font=FONT_BODY,
        padx=12,
        pady=8,
        cursor="hand2",
        **kwargs,
    )


def make_back_button(parent, command):
    btn = make_button(parent, "←", command, kind="back", width=3)
    btn.config(
        font=(FONT_BODY[0], FONT_BODY[1], "bold"),
        padx=10,
        pady=6,
        bg=BG,
        activebackground=BUTTON_BG,
        fg=PRIMARY_HOVER,
        activeforeground=PRIMARY_HOVER,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=BORDER,
        bd=0,
    )
    return btn


def make_breadcrumb(parent, current_title, back_command):
    bar = tk.Frame(parent, bg=BG)
    bar.pack(fill=tk.X, padx=18, pady=(14, 8))

    make_back_button(bar, back_command).pack(side=tk.LEFT)
    make_label(bar, text=f"{current_title}", font=FONT_H2, fg=TEXT, bg=BG).pack(side=tk.LEFT, padx=12)
    return bar


def make_entry(parent, *, width=24, **kwargs):
    return tk.Entry(
        parent,
        width=width,
        bg=ENTRY_BG,
        fg=ENTRY_FG,
        insertbackground=ENTRY_FG,
        relief=tk.FLAT,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=PRIMARY,
        font=FONT_BODY,
        **kwargs,
    )


def make_text(parent, *, width=40, height=6, **kwargs):
    return tk.Text(
        parent,
        width=width,
        height=height,
        bg=ENTRY_BG,
        fg=ENTRY_FG,
        insertbackground=ENTRY_FG,
        relief=tk.FLAT,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=PRIMARY,
        font=FONT_BODY,
        **kwargs,
    )


def clear_screen():
    for widget in root.winfo_children():
        widget.destroy()


def show_main_menu():
    global current_mode
    current_mode = "encrypt"
    clear_screen()
    style_root()
    make_label(root, text="Image Encrypter-Decrypter", font=FONT_H1).pack(pady=(28, 8))
    root.title("Image Encrypter-Decrypter")
    make_label(root, text="Securely store and retrieve messages inside images.", fg=MUTED).pack(pady=(0, 18))

    card = tk.Frame(root, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
    card.pack(padx=28, pady=10, fill=tk.X)

    inner = tk.Frame(card, bg=SURFACE)
    inner.pack(padx=18, pady=18, fill=tk.X)

    make_button(inner, "Encrypt", show_encrypt_ui, kind="primary", width=22).pack(pady=(0, 10))
    make_button(inner, "Decrypt", show_decrypt_ui, kind="secondary", width=22).pack()


def show_encrypt_ui():
    global current_mode
    current_mode = "encrypt"
    clear_screen()
    style_root()
    make_breadcrumb(root, "Encrypt", show_main_menu)

    root.title("Encrypting Image")
    # Drop Image Section with button
    drop_frame = tk.Frame(root, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
    drop_frame.pack(pady=18, padx=20, fill=tk.BOTH, expand=True)

    make_label(drop_frame, text="Drag an image here", font=FONT_H2, bg=SURFACE).place(relx=0.5, rely=0.45, anchor=tk.CENTER)
    make_label(drop_frame, text="or select a file below", fg=MUTED, bg=SURFACE).place(relx=0.5, rely=0.58, anchor=tk.CENTER)

    # Adding drag drop functionalities
    drop_frame.drop_target_register(tkdnd.DND_FILES)
    drop_frame.dnd_bind('<<Drop>>', handle_drop)

    # Select file button with functionality
    select_button = make_button(root, "Select Image File", select_file, kind="primary", width=22)
    select_button.config(pady=10)
    select_button.pack(pady=(0, 18))

    root.bind("<Escape>", lambda e: show_main_menu())


def show_encrypt_dialog(image_path):
    # Create dialog window
    dialog = tk.Toplevel(root)
    dialog.title("Enter Encryption Details")
    dialog.geometry("520x440")
    dialog.configure(bg=BG)
    dialog.resizable(True, True)
    prepare_popup(dialog)

    # Message label and entry
    make_label(dialog, text="Message", font=FONT_H2).pack(pady=(16, 6))
    message_entry = make_text(dialog, height=12, width=60, wrap=tk.WORD)
    message_entry.pack(pady=(0, 12), padx=16, fill=tk.BOTH, expand=True)

    # Shift number label and entry
    make_label(dialog, text="Shift (0-25)", font=FONT_H2).pack(pady=(0, 6))
    shift_entry = make_entry(dialog, width=22)
    shift_entry.pack(pady=(0, 16))

    # Encrypt button
    def encrypt_btn_click():
        message = message_entry.get("1.0", tk.END).strip()
        shift = int(shift_entry.get())

        # Ask for output location
        output_path = filedialog.asksaveasfilename(
            title="Save Encrypted Image",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )

        if output_path:
            try:
                encrypt_message(image_path, message, shift, output_path)
            except Exception as e:
                show_popup("Error", str(e), kind="error")
                return

            show_popup("Success", "Image encrypted successfully!", kind="success")
            dialog.destroy()

    encrypt_button = make_button(dialog, "Encrypt", encrypt_btn_click, kind="primary", width=18)
    encrypt_button.config(pady=10)
    encrypt_button.pack(pady=(0, 18))


def show_decrypt_ui():
    global current_mode
    current_mode = "decrypt"
    clear_screen()
    style_root()
    make_breadcrumb(root, "Decrypt", show_main_menu)

    root.title("Decrypting Image")

    # Drop Image Section with button
    drop_frame = tk.Frame(root, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
    drop_frame.pack(pady=18, padx=20, fill=tk.BOTH, expand=True)
    make_label(drop_frame, text="Drag an image here", font=FONT_H2, bg=SURFACE).place(relx=0.5, rely=0.45, anchor=tk.CENTER)
    make_label(drop_frame, text="or select a file below", fg=MUTED, bg=SURFACE).place(relx=0.5, rely=0.58, anchor=tk.CENTER)

    # Adding drag drop functionalities
    drop_frame.drop_target_register(tkdnd.DND_FILES)
    drop_frame.dnd_bind('<<Drop>>', handle_drop)

    # Select file button with functionality
    select_button = make_button(root, "Select Image File", select_file, kind="primary", width=22)
    select_button.config(pady=10)
    select_button.pack(pady=(0, 18))


def show_decrypt_options():
    dialog = tk.Toplevel(root)
    dialog.title("Choose Decryption Method")
    dialog.geometry("420x260")
    dialog.configure(bg=BG)
    dialog.resizable(False, False)
    prepare_popup(dialog)

    make_label(dialog, text="Decryption Method", font=FONT_H2).pack(pady=(18, 12))
    make_button(dialog, "I know the shift key", command=lambda: [dialog.destroy(), show_decrypt_with_key(current_decrypt_image)],
                kind="primary", width=22).pack(pady=(0, 10))
    make_button(dialog, "I don't know the key", command=lambda: [dialog.destroy(), show_decrypt_without_key(current_decrypt_image)],
                kind="secondary", width=22).pack()


def show_decrypt_with_key(image_path):
    dialog = tk.Toplevel(root)
    dialog.title("Decrypt with Known Key")
    dialog.geometry("680x460")
    dialog.configure(bg=BG)
    dialog.resizable(True, True)
    prepare_popup(dialog)

    make_label(dialog, text="Shift (0-25)", font=FONT_H2).pack(pady=(18, 6))
    shift_entry = make_entry(dialog, width=22)
    shift_entry.pack(pady=(0, 10))

    output_frame = tk.Frame(dialog, bg=BG)
    output_frame.pack(pady=(8, 10), padx=16, fill=tk.BOTH, expand=True)

    result_text = make_text(output_frame, wrap=tk.WORD, width=60, height=10)
    scrollbar = tk.Scrollbar(output_frame, command=result_text.yview)
    result_text.config(yscrollcommand=scrollbar.set)
    result_text.config(state=tk.DISABLED)

    result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def decrypt_btn_click():
        shift = int(shift_entry.get())
        if not image_path:
            output = "No image selected! Please drop/select an image first."
        else:
            message = decrypt_with_key(image_path, shift)
            if message is None:
                output = "No valid hidden message found!"
            else:
                output = f"Decrypted Message:\n\n{message}"

        result_text.config(state=tk.NORMAL)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, output)
        result_text.config(state=tk.DISABLED)

    make_button(dialog, "Decrypt", decrypt_btn_click, kind="primary", width=18).pack(pady=(0, 18))


def show_decrypt_without_key(image_path):
    messages = decrypt_without_key(image_path)

    dialog = tk.Toplevel(root)
    dialog.title("Decrypted Message")
    dialog.geometry("700x520")
    dialog.configure(bg=BG)
    dialog.resizable(True, True)
    prepare_popup(dialog)

    if not messages:
        make_label(dialog, text="No valid hidden message found.", font=FONT_H2).pack(pady=(18, 6))
        make_label(dialog, text="Make sure you're using an image created by this app (PNG recommended).", fg=MUTED).pack(
            pady=(0, 18), padx=18)
    else:
        make_label(dialog, text="Brute forced Combinations", font=FONT_H2).pack(pady=(18, 10))
        text_widget = make_text(dialog, wrap=tk.WORD, width=70, height=18)
        scrollbar = tk.Scrollbar(dialog, command=text_widget.yview)
        text_widget.config(yscrollcommand=scrollbar.set)

        for msg in messages:
            text_widget.insert(tk.END, f"Shift {msg['shift']}:\n{msg['message']}\n{'-' * 50}\n")

        text_widget.config(state=tk.DISABLED)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


def handle_drop(event):
    global current_decrypt_image
    file_path = event.data
    if file_path.startswith("{") and file_path.endswith("}"):
        file_path = file_path[1:-1]
    if current_mode == "encrypt":
        show_encrypt_dialog(file_path)
    else:  # decrypt mode
        current_decrypt_image = file_path
        show_decrypt_options()


def select_file():
    global current_decrypt_image
    file_path = filedialog.askopenfilename(
        title="Select Image File",
        filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp")]
    )
    if file_path:
        if current_mode == "encrypt":
            show_encrypt_dialog(file_path)
        else:  # decrypt mode
            current_decrypt_image = file_path
            show_decrypt_options()


root = tkdnd.Tk()
root.geometry("620x460")
style_root()
show_main_menu()
root.mainloop()