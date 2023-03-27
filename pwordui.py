import pwordbackend as pw
import tkinter as tk
import os

window = tk.Tk()
window.geometry('600x400+50+50')
window.title("Password Manager")
alert = tk.Label(text="Incorrect password")
choiceFrame = tk.Frame()
accountbutton = tk.Button(master=choiceFrame, text="accounts")
cardbutton = tk.Button(master=choiceFrame, text="bank cards")
def afterlogin():
    submitbutton.destroy()
    password.destroy()
    choiceFrame.pack(side=tk.TOP, anchor=tk.NW)
    accountbutton.pack()
    cardbutton.pack()
def login():
    global password, submitbutton, alert
    bullet = "\u2022" #specifies bullet character
    password = tk.Entry(width=50)#shows the character bullet
    password.insert(tk.END, "Enter password")
    def some_callback(event):
       
        if password.get() == "Enter password":
            password.delete(0, "end")
        password.config(show = bullet)
        return None
    
    password.bind("<FocusIn>", some_callback)
    password.pack()
    
    def submit():
        global alert
        name = password.get()
        if not name:
            return
        if not os.path.isfile("passwordmanager/key.key"):
            pw.createAccount(name)
            afterlogin()
        else:
            
            if pw.login(name):
                alert.destroy()
                afterlogin()
            else:
                alert.pack()
    submitbutton = tk.Button(window, text="Submit", width=10, command= submit)
    submitbutton.pack()

window.after_idle(login)


window.mainloop()    