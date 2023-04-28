import binascii
import secrets
import mysql.connector
from mysql.connector import Error, connect
import string
import hashlib
import base64
import bcrypt
from tkinter import * 
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
mydb = mysql.connector.connect(host ="localhost", db ="passwordmanager", user="applogin", password="applogin")
mycursor = mydb.cursor()
#CREATE USER 'applogin' IDENTIFIED BY 'applogin';
#GRANT ALL ON `passwordmanager`.* TO 'applogin';
#potentially add a description per password, allows user to remember pass
#CREATE TABLE IF NOT EXISTS `passwordmanager`.`passwords` (
# 'password_id' INT NOT NULL AUTO_INCREMENT, 
# `user_id` INT NOT NULL,
#  `password` VARCHAR(255) NULL,
#  PRIMARY KEY (`password_id));
#CREATE TABLE IF NOT EXISTS `passwordmanager`.`users` (
#  `user_id` INT NOT NULL AUTO_INCREMENT,
#  `username` VARCHAR(255) NULL,
#  `password` VARCHAR(255) NULL,
#  PRIMARY KEY (`user_id`));
global tk 
tk = Tk()
def UI():
    tk.title("Password Manager")
    tk.eval('tk::PlaceWindow . center')
    tk.geometry("400x100")
    l1 = Label(tk, text="Enter Username:")
    l3 = Label(tk, text="Enter Master Password:")
    username_entry = Entry(tk, fg="black", bg="white", width=50)
    masterpass_entry = Entry(tk, fg="black", bg="white", width=50, show="*")
    button = Button(tk, text="Login", command= lambda: login(username_entry, masterpass_entry))
    button2 = Button(tk, text="Create Account", command=createaccount)
    l1.grid(row=0,column=0,sticky=W,pady=2)
    l3.grid(row=1, column=0, sticky=W, pady=2)
    username_entry.grid(row=0, column=1, pady=2)
    masterpass_entry.grid(row=1, column=1,pady=2)
    button.grid(row=2, column=1, pady=1)
    button2.grid(row=2, column=0, sticky=W, pady=2)
def createaccount():
    top = Toplevel()
    top.title('Create Account')
    top.grab_set()
    l1 = Label(top, text="Enter Username:")
    l4 = Label(top, text="Master Password(MUST BE EXACTLY 16 CHARACTERS):")
    l5 = Label(top, text="Confirm Master Password:")
    username = Entry(top, fg="black", bg="white", width=50)
    masterpass = Entry(top, fg="black", bg="white", width=50, show="*")
    confirmmasterpass = Entry(top, fg="black", bg="white", width=50, show="*")
    submit = Button(top, text="Create Account", command= lambda: storenewacc(top, username, masterpass, confirmmasterpass))
    l1.grid(row=0,column=0,sticky=W, pady=2)
    l4.grid(row=1, column=0, sticky=W, pady=2)
    l5.grid(row=2, column=0, sticky=W, pady=2)
    username.grid(row=0, column=1, pady=2)
    masterpass.grid(row=1, column=1, pady=2)
    confirmmasterpass.grid(row=2, column=1, pady=2)
    submit.grid(row=3, column=1, pady=1)

def storenewacc(top, usernamewidget, masterpasswidget, confirmmasterpasswidget):
    username = usernamewidget.get()
    masterpass = masterpasswidget.get()
    confirmmasterpass = confirmmasterpasswidget.get()
    error = Label(top, text="Master passwords don't match!")
    if masterpass != confirmmasterpass:
        error.grid(row=4, column=1, pady=1)
    elif len(masterpass) != 16:
        error.grid(row=4, column=1, pady=1)
    else:
        masterpass = masterpass.encode("utf-8")
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(masterpass, salt)
        sql1 = "SELECT * FROM users WHERE username = %s;"
        val = (username, )
        mycursor.execute(sql1, val)
        data = mycursor.fetchall()
        if len(data) > 0:
            error = Label(top, text="Account already exists!")
            error.grid(row=4, column=1, pady=1)
        else:
            masterpass = masterpass.decode("utf-8")
            key = get_random_bytes(16)
            encrypted_key = master_encrypt(key, masterpass)
            encrypted_password = master_encrypt(hashed, masterpass)
            sql = "INSERT INTO users(username, pass_keys, masterpass) VALUES(%s, %s, %s)"
            val = (username, encrypted_key, encrypted_password)
            mycursor.execute(sql, val)
            mydb.commit()
            top.destroy()

def createnew(user_id, masterpass):
    top = Toplevel(tk)
    top.title('Generate Password')
    top.grab_set()
    options = [
        "Alphabetic Password",
        "Alphanumeric Password",
        "Special Character Password (suggested)"
    ]
    dropdown = StringVar(top)
    dropdown.set(options[0])
    select_option = OptionMenu(top, dropdown, *options)
    select_option.grid(row=0, column=0, sticky=W, pady=2)
    label1 = Label(top, text="Please input desired length of password")
    entry = Entry(top, fg="black", bg="white", width=50)
    create = Button(top, text="Create", command= lambda: create_password(top, dropdown, entry, options, user_id, masterpass))
    label1.grid(row=1, column=0, sticky=W,pady=2)
    entry.grid(row=2, column=0, sticky=W, pady=2)
    create.grid(row=4, column=0, sticky=W, pady=2)
def create_password(top, dropdown, entry, options, user_id, masterpass):
        #this function generates a password and allows the user
        #to save it to the database using the save button
        #user can also copy directly to clipboard
        try:
            int_entry = int(entry.get())
            selection = dropdown.get()
            if selection == options[0]:
                letters = string.ascii_letters
                generated_password = ''.join(secrets.choice(letters)for i in range(int_entry))
            elif selection == options[1]:
                letters = string.ascii_letters + string.digits
                generated_password = ''.join(secrets.choice(letters)for i in range(int_entry))
            elif selection == options[2]:
                letters = string.ascii_letters + string.digits + string.punctuation
                generated_password = ''.join(secrets.choice(letters)for i in range(int_entry))
            copy = Button(top, text="Copy", command= lambda: copytoclip(generated_password, top))
            copy.grid(row=1, column=1, pady=1)
            savepass = Button(top, text="Save Password", command = lambda: savepassword(generated_password, user_id, masterpass))
            savepass.grid(row=2,column=1, pady=1)
            display_pass = Label(top, text="Your generated password is " + generated_password)
            #make it so that if the button is clicked again, the label
            #gets reset so drop and grid it
            display_pass.grid(row=0, column=1, pady=1)
        except ValueError:
            error = Label(top, text="Please input an integer")
            if (error.winfo_exists()) == 1:
                error.grid(row=3, column=0, sticky=W, pady=2)

def copytoclip(password, top):
     top.withdraw
     top.clipboard_clear()
     top.clipboard_append(password)
     top.update() 
def savepassword(generated_password, user_id, masterpass):
    #saves the password to the database
    encrypted = encrypt(generated_password, user_id, masterpass)
    #print(encrypted)
    sql = "INSERT INTO passwords(user_id, password) VALUES(%s, %s);"
    #currently doesn't work as primary key is needed 
    #in passwords table
    var = (user_id, encrypted)
    mycursor.execute(sql, var)
    mydb.commit()

def showall(user_id, masterpass):
    #this will generate all passwords
    top = Toplevel()
    top.title("Passwords")
    top.grab_set()
    l1 = Label(top, text="Your stored passwords:")
    l1.grid(row=0, column=0, sticky=W, pady=2)
    sql = "SELECT password_id FROM passwords WHERE user_id = %s;"
    var = (user_id, )
    mycursor.execute(sql, var)
    data = mycursor.fetchall()
    decrypted = decrypt(user_id, masterpass)
    for x in data:
        loop = 1
        for i in data:
            text = decrypted[loop]
            label = Label(top, text=text)
            number = Label(top, text=loop)
            number.grid(row=loop, column=0,sticky=W, pady=1)
            label.grid(row=loop, column=1, sticky=W, pady=1)
            copy = Button(top, text="Copy", command= lambda: copytoclip(text, top))
            copy.grid(row=loop, column=2, pady=1)
            loop += 1
#this doesn't work just yet!
def homepage(user_id, masterpass):
    top = Toplevel(tk)
    top.title('Home Page')
    top.grab_set()
    home = Label(top, text="Welcome to your password manager!")
    create_password = Button(top, text="Create a new password", command= lambda: createnew(user_id, masterpass))
    see_passwords = Button(top, text="See existing passwords", command= lambda: showall(user_id, masterpass))
    strengthofpassword = Button(top, text="Check password strength", command= password_checker)
    passworduploader = Button(top, text = "Upload a password", command=lambda: upload_password(user_id, masterpass))
    home.pack()
    create_password.pack()
    passworduploader.pack()
    strengthofpassword.pack()
    see_passwords.pack()
def password_checker():
    top = Toplevel(tk)
    top.title('Password Checker')
    top.grab_set()
    entry = Entry(top, fg="black", bg="white", width=50, show="*")
    label = Label(top, text= "Enter Password:")
    button = Button(top, text = "Check Password Strength", command= lambda: check_password(top, entry))
    entry.grid(row=0, column=1, pady=1)
    label.grid(row=0, column=0, sticky=W, pady=2)
    button.grid(row=1, column=1, pady=1)
def check_password(top, entry):
    password = entry.get()
    strength = 0
    if len(password) >= 12:
        strength += 1
    for char in list(password):
        if char in string.ascii_lowercase:
            strength += 1
        elif char in string.ascii_uppercase:
            strength += 1
        elif char in string.digits:
            strength += 1
        else:
            strength += 1
    sql = "SELECT common_text FROM common WHERE common_text = %s"
    var = (password, )
    mycursor.execute(sql, var)
    data = mycursor.fetchall()
    warning = Label(top, text="Your password is extremely common and \n therefore insecure!")
    if len(data) == 0:
        warning.grid_forget()
        strength += 1
    elif len(data) > 0:
        warning.grid(row=3, column=1, pady=1)
    strength = strength // 5
    label = Label(top, text="Your password strength is " + str(strength) + "/7")
    label.grid(row=2, column=1, pady=1)
def upload_password(user_id, masterpass):
    top = Toplevel(tk)
    top.title('Upload Password')
    top.grab_set()
    entry = Entry(top, fg="black", bg="white", width=50, show="*")
    label = Label(top, text= "Enter Password:")
    button = Button(top, text = "Submit", command= lambda: password_upload(top, entry, user_id, masterpass))
    entry.grid(row=0, column=1, pady=1)
    label.grid(row=0, column=0, sticky=W, pady=2)
    button.grid(row=1, column=1, pady=1)
def password_upload(top, entry, user_id, masterpass):
    password = entry.get()
    encrypted = encrypt(password, user_id, masterpass)
    sql = "INSERT INTO passwords(user_id, password) VALUES(%s, %s);"
    #currently doesn't work as primary key is needed 
    #in passwords table
    var = (user_id, encrypted)
    mycursor.execute(sql, var)
    mydb.commit()
    label = Label(top, text="Password Uploaded!")
    label.grid(row=2, column=1, pady=1)
def encrypt(data, user_id, masterpass):
    sql1 = "SELECT pass_keys FROM users where user_id = %s"
    var = (user_id, )
    mycursor.execute(sql1, var)
    for x in mycursor.fetchall():
        key = bytes(x[0])
        key = master_decrypt(key, masterpass)
    cipher = AES.new(key, AES.MODE_EAX)
    #here the data is being encoded
    data = data.encode("utf-8")
    #here the data is being decoded
    #data = data.decode("utf-8")
    #this is being fucked up somewhere
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    stored_text = nonce + tag + ciphertext
    return stored_text
    #this encrypts data, need to replace variable data
#
#
#       FINAL CORE MODULE THAT NEEDS TO BE FIXED!!!!
#
#
def decrypt(user_id, masterpass):
    sql = "SELECT pass_keys FROM users WHERE user_id = %s"
    val = (user_id, )
    mycursor.execute(sql, val)
    for row in mycursor.fetchall():
        key = bytes(row[0])
        key = master_decrypt(key, masterpass)
    sql2 = "SELECT password FROM passwords WHERE user_id = %s"
    val2 = (user_id, )
    mycursor.execute(sql2, val2)
    list_of_passwords = [""]
    for row in mycursor.fetchall():
        encrypted_password = bytes(row[0])
        nonce = encrypted_password[:16]
        tag = encrypted_password[16:32]
        ciphertext = encrypted_password[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
        list_of_passwords.append(decrypted_password)
    return list_of_passwords

    
def login(username_entry, masterpass_entry):
    username = username_entry.get()
    masterpass = masterpass_entry.get()
    correct_pass = 0
    sql = "SELECT * FROM users WHERE username = %s;"
    val = (username, )
    mycursor.execute(sql, val)
    data = mycursor.fetchall()
    error = Label(text="Wrong username or password")
    if len(data) != 0:
        for x in data:
            loop = 0
            for i in x:
                if loop == 0:
                    user_id = i
                elif loop == 2:
                    encrypted_hash = bytes(i)
                    try:
                        decrypted_hash = master_decrypt(encrypted_hash, masterpass)
                        masterpass = masterpass.encode("utf-8")
                        if bcrypt.hashpw(masterpass, decrypted_hash) == decrypted_hash:
                            correct_pass = 1
                        else:
                            correct_pass = 0
                    except ValueError:
                        error.grid(row=5,column=1,pady=1)
                loop += 1
        if correct_pass == 1:
                masterpass = masterpass.decode("utf-8")
                error.grid_forget()
                homepage(user_id, masterpass)
        else:
            error.grid(row=5,column=1,pady=1)
    if len(data) == 0:
        error = Label(text="Wrong username or password")
        error.grid_forget()
        presence_check = error.winfo_exists()
        if presence_check == 1:
            error.grid(row=3,column=1,pady=1) 
def master_encrypt(data, masterpass):
    key = masterpass.encode("utf-8")
    cipher = AES.new(key, AES.MODE_EAX)
    #here the data is being encoded
    if type(data) is bytes:
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        stored_text = nonce + tag + ciphertext
        return stored_text
    else:
        data = data.encode("utf-8")
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        stored_text = nonce + tag + ciphertext
        return stored_text
    #here the data is being decoded
    #data = data.decode("utf-8")
    #this is being fucked up somewhere
def master_decrypt(data, masterpass):
    key = masterpass.encode("utf-8")
    encrypted_password = bytes(data)
    nonce = encrypted_password[:16]
    tag = encrypted_password[16:32]
    ciphertext = encrypted_password[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_password

UI()

tk.mainloop()
mydb.close()