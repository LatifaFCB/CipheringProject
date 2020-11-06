import tkinter as tk
from cryptography.fernet import Fernet
from tkinter import filedialog
from tkinter import *
import os
from PIL import Image

def file_open():
    filename = filedialog.askopenfilename(initialdir="C:/",title="Select File",filetypes=(("Text File", "*.txt"),("Images","*.png")))
    with open(filename, 'r') as f:
        pathlabel.insert(0, f.read() or Image.open(f))


'''def write_key(): #when encrypt first time uncomment this
    key = Fernet.generate_key()
    print('key: {0}, type: {1}'.format(key, type(key)))
    with open("key.key", "wb") as key_file:
        key_file.write(key)'''

def load_key():
    return open("key.key", "rb").read()

#write_key() #when encrypt first time uncomment this
key = load_key()

def encrypt(pathlabel, key):
    f = Fernet(key)
    file1 = pathlabel.get()
    plaintext1 = f.encrypt(file1.encode('utf-8'))
    ciphertext.insert(0, plaintext1)


def decrypt(ciphertext, key):
    f = Fernet(key)
    file1 = ciphertext.get()
    ciphertext1 = f.decrypt(file1.encode('utf-8'))
    plaintext.insert(0, ciphertext1)

def clear_text():
    pathlabel.delete(0,'end')
    ciphertext.delete(0, 'end')
    plaintext.delete(0,'end')


#GUI
m=tk.Tk()
tnb = tk.Menu(m)
m.config(menu=tnb)
m.title('File Encryption and decryption')
m.geometry("600x200")


#Menu
tnb_file = tk.Menu(tnb, tearoff=0)
tnb.add_cascade(label="Options", menu=tnb_file)
tnb_file.add_command(label="Open", command=lambda: file_open())
tnb_file.add_command(label="Exit", command=m.destroy)
tnb_file.add_separator()


#Buttons
button = tk.Button(m, text='Encrypt File', width=25, bg ="red", fg ="white", command= lambda: encrypt(pathlabel,key))
button.grid(row = 13, column = 2)

button2 = tk.Button(m, text='Decrypt File', bg ="green", fg ="white",  width=25, command= lambda: decrypt(ciphertext,key))
button2.grid(row = 13, column = 11)

button3 = tk.Button(m, text='Clear', bg ="yellow", fg ="black",  width=25, command= lambda: clear_text())
button3.grid(row = 14, column = 11, padx=6,pady=11,ipady=3)

#Labels
label1 = Label(m, text ='Plain text:')
label1.grid(row = 10, column = 1)

label2 = Label(m, text ='Encrypted text:')
label2.grid(row = 11, column = 1)

label3 = Label(m, text ="Decrypted text:")
label3.grid(row = 11, column = 10)

#Entries
pathlabel = Entry(m)
pathlabel.grid(row = 10, column = 2, padx=5,pady=10,ipady=3)

ciphertext = Entry(m)
ciphertext.grid(row = 11, column = 2, padx=5,pady=10,ipady=3)

plaintext = Entry(m)
plaintext.grid(row = 11, column = 11, padx=5,pady=10,ipady=3)

m.mainloop()