# Import the required libraries
from tkinter import *
from tkinter import ttk

# Create an instance of tkinter frame
win = Tk()

# Set the size of the tkinter window
win.geometry("700x350")

# Define the style for combobox widget
style = ttk.Style()
style.theme_use('xpnative')

# Define a function to show/hide widget
def show_widget():
   label.pack()
def hide_widget():
   label.pack_forget()
   b1.configure(text="Show", command=show_widget)

# Add a label widget
label = ttk.Label(win, text="Eat, Sleep, Code and Repeat", font=('Aerial 11'))
label.pack(pady=30)

# Add a Button widget
b1 = ttk.Button(win, text="Hide", command=hide_widget)
b1.pack(pady=20)

win.mainloop()