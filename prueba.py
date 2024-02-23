import tkinter as tk

class ParpadeoBotonApp:
    def __init__(self, root):
        self.root = root
        self.boton_detener = tk.Button(root, text="Detener", command=self.detener_proceso, state="normal", background="#FF7474")
        self.boton_detener.pack()
        self.color_actual = "#FF7474"  # Color inicial del botón
        self.iniciar_parpadeo()

    def detener_proceso(self):
        # Detiene el parpadeo
        self.root.after_cancel(self.parpadeo_id)
        self.boton_detener.configure(background="#FF7474")  # Restaura el color original
        self.root.update_idletasks()  # Actualiza la interfaz gráfica

    def cambiar_color(self):
        # Alterna entre dos colores
        self.color_actual = "#D3D3D3" if self.color_actual == "#FF7474" else "#FF7474"
        self.boton_detener.configure(background=self.color_actual)
        self.parpadeo_id = self.root.after(500, self.cambiar_color)

    def iniciar_parpadeo(self):
        self.parpadeo_id = self.root.after(0, self.cambiar_color)

if __name__ == "__main__":
    root = tk.Tk()
    app = ParpadeoBotonApp(root)
    root.mainloop()
