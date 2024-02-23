import tkinter as tk
from tkinter import ttk

def agregar_datos():
    SKU = "123"
    Packtype = "Box"
    Tipodepaquete = "Small"
    Cantidad = 5
    Largo = 10
    Ancho = 5
    Alto = 3
    Peso = 2.5
    fecha = "2024-02-22"

    # Insertar datos en el Treeview
    item_id = tree.insert('', 'end', values=(SKU, Packtype, Tipodepaquete, Cantidad, Largo, Ancho, Alto, Peso, fecha))

    # Aplicar la etiqueta de fondo verde a la fila recién insertada
    tree.tag_configure('verde', background='green')
    tree.item(item_id, tags=('verde',))

# Crear la ventana principal
root = tk.Tk()
root.title("Ejemplo Treeview con fondo verde")

# Crear el Treeview
tree = ttk.Treeview(root, columns=("SKU", "Packtype", "Tipodepaquete", "Cantidad", "Largo", "Ancho", "Alto", "Peso", "Fecha"), show="headings")

# Configurar encabezados
for col in ("SKU", "Packtype", "Tipodepaquete", "Cantidad", "Largo", "Ancho", "Alto", "Peso", "Fecha"):
    tree.heading(col, text=col)
    tree.column(col, width=100)

# Crear botón para agregar datos
agregar_datos_button = tk.Button(root, text="Agregar Datos", command=agregar_datos)
agregar_datos_button.pack(pady=10)

# Mostrar el Treeview
tree.pack()

# Iniciar el bucle principal
root.mainloop()
