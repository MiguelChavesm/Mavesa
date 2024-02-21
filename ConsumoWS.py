import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import os
from requests.auth import HTTPBasicAuth
import requests
from datetime import datetime
from threading import Thread
import time

class ProcesadorArchivos:
    def __init__(self, root):
        self.root = root
        root.iconbitmap("logo-montra.ico")
        self.root.title("MONTRA")
        self.contraseña = "MONTRA"
        self.contraseña_verificada = False
        self.configuracion_bloqueada = False  # Nuevo: Estado de bloqueo de configuración

        # Contadores para envío exitoso y fallido
        self.envio_exitoso = 0
        self.envio_fallido = 0

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)
        self.medicion_tab = ttk.Frame(self.notebook)
        self.configuracion_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.medicion_tab, text="WebService", state="normal")
        self.notebook.add(self.configuracion_tab, text="Configuración", state="disabled")

        self.create_medicion_tab()
        self.create_configuracion_tab()

        # Configurar evento para abrir la pestaña de configuración
        self.notebook.bind("<<NotebookTabChanged>>", self.abrir_pestana_configuracion)

        # URL del servicio de acceso a tokens
        self.token_url = "https://mingle-sso.inforcloudsuite.com:443/NUGH6DGWYB5E8AMU_TST/as/token.oauth2"

        # Información de autenticación
        self.api_url = "https://mingle-ionapi.inforcloudsuite.com/NUGH6DGWYB5E8AMU_TST/WM/wmwebservice_rest/NUGH6DGWYB5E8AMU_TST_ENTERPRISE/packs"
        self.client_id = "NUGH6DGWYB5E8AMU_TST~_tOirRI-jy9pzu4Xun2ESJvNqMVTHg_jJntMDzFtgV0"
        self.client_secret = "ptQu3maUMRAlScq_xe2-mZLsJkPtT_fkrDWTOGEVJreUHyPqavPhncXtX1cRCVE8uNSQei4CQO0xqssZvwgU9A"
        self.username = "NUGH6DGWYB5E8AMU_TST#ktzJTSlcIfY9X5sH9tUacghKkC7n7TLZXCgx51jQyHjPXJvxzarlQsufPAusg4XgDa6GbLvXKcKvjwN7ljHBlg"
        self.password = "jxy5rCtcwN_jf0b8R1Cbe2FxkBQ-paCjmDwspfGqu7E1Mwj0SsDneZKBF41g4alWZ-lTUWCRl0p7M8tJ0yVknA"

        # Ruta de la carpeta donde se encuentran los archivos txt
        self.carpeta_archivos = "C:/Users/montr/Downloads/Prueba Mavesa/"

        # Ruta de la carpeta "procesados"
        self.carpeta_procesados = "Procesados/"

        # Variable para controlar la ejecución del programa
        self.ejecutar = True

        # Enlazar evento de teclado para detectar la combinación de teclas
        self.root.bind("<KeyPress>", self.verificar_combinacion_teclas)

    def verificar_combinacion_teclas(self, event):
        if event.keysym == "Insert" and event.state & 4 != 0 and event.state & 1 != 0 and event.state & 8 != 0:
            # Verificar si la pestaña actual es la de configuración y la contraseña no ha sido verificada
            if self.notebook.index("current") == 1 and not self.contraseña_verificada:
                self.ingresar_sin_contraseña()

    def ingresar_sin_contraseña(self):
        # Verificar si la pestaña actual es la de configuración y la contraseña no ha sido verificada
        if self.notebook.index("current") == 1 and not self.contraseña_verificada:
            # Habilitar la pestaña de configuración
            self.notebook.tab(1, state="normal")
            # Habilitar los campos de configuración
            for child in self.configuracion_tab.winfo_children():
                if isinstance(child, ttk.Entry):
                    child.config(state="normal")
            # Marcar la contraseña como verificada
            self.contraseña_verificada = True

    def abrir_pestana_configuracion(self, event):
        if self.notebook.index("current") == 1 and self.contraseña_verificada:
            self.notebook.select(self.configuracion_tab)

    def abrir_pestana_configuraciones(self):
        if not self.contraseña_verificada:
            # Establecer la pestaña actual en la de configuración
            self.notebook.select(self.configuracion_tab)
            self.dialogo_contraseña = tk.Toplevel()
            self.dialogo_contraseña.title("Verificación de acceso")
            self.dialogo_contraseña.geometry("300x100")
            self.dialogo_contraseña.resizable(False, False)

            etiqueta_contraseña = ttk.Label(self.dialogo_contraseña, text="Ingrese la contraseña:")
            etiqueta_contraseña.pack(pady=5)

            self.entrada_contraseña = ttk.Entry(self.dialogo_contraseña, show="*")
            self.entrada_contraseña.pack(pady=5)
            self.entrada_contraseña.bind("<Return>", lambda event: self.verificar_contraseña())

            boton_verificar = ttk.Button(self.dialogo_contraseña, text="Verificar", command=self.verificar_contraseña)
            boton_verificar.pack(pady=5)

            # Configurar una acción cuando se cierra la ventana de verificación
            self.dialogo_contraseña.protocol("WM_DELETE_WINDOW", self.restablecer_campos_configuracion)

            # Bloquear campos de configuración hasta que se verifique la contraseña
            for child in self.configuracion_tab.winfo_children():
                if isinstance(child, ttk.Entry):
                    child.config(state="disabled")

    def restablecer_campos_configuracion(self):
        # Restablecer solo si se cierra la ventana emergente de verificación con la "X"
        if self.dialogo_contraseña:
            self.dialogo_contraseña.destroy()
            if self.notebook.index("current") == 1:  # Verifica si la pestaña actual es la de configuración
                self.notebook.select(0)  # Cambia a la pestaña de medición
                self.notebook.tab(1, state="disabled")  # Deshabilita la pestaña de configuración
                # Limpiar y desbloquear los campos de configuración
                self.entrada_contraseña.delete(0, tk.END)
                for child in self.configuracion_tab.winfo_children():
                    if isinstance(child, ttk.Entry):
                        child.config(state="normal")
                self.configuracion_bloqueada = True  # Bloquear la configuración nuevamente
            else:
                self.configuracion_bloqueada = False  # Si se cierra la ventana de configuración desde la pestaña de medición

    def verificar_contraseña(self):
        # Verifica si la contraseña ingresada es correcta
        contraseña_ingresada = self.entrada_contraseña.get()
        if contraseña_ingresada == self.contraseña:
            self.notebook.tab(1, state="normal")  # Habilita la pestaña de configuración
            self.dialogo_contraseña.destroy()
            # Habilitar los campos de configuración
            for child in self.configuracion_tab.winfo_children():
                if isinstance(child, ttk.Entry):
                    child.config(state="normal")
            self.contraseña_verificada = True
        else:
            messagebox.showerror("Error", "Contraseña incorrecta")
            # Limpiar el campo de contraseña
            self.entrada_contraseña.delete(0, tk.END)

    def create_medicion_tab(self):
        # Agregar la pestaña de medición al notebook
        self.notebook.add(self.medicion_tab, text="WebService", state="normal")

        # Tamaño deseado para las imágenes
        img_width, img_height = 100, 100

        # Imagen 1
        imagen1 = Image.open("imagen_1.png")
        imagen1 = imagen1.resize((img_width, img_height), Image.BICUBIC)
        imagen1_tk = ImageTk.PhotoImage(imagen1)
        self.label_imagen1 = tk.Label(self.medicion_tab, image=imagen1_tk)
        self.label_imagen1.image = imagen1_tk
        self.label_imagen1.grid(row=0, column=0, padx=(7, 2), pady=(10, 0))

        # Imagen 2
        imagen2 = Image.open("imagen_2.png")
        imagen2 = imagen2.resize((img_width, img_height), Image.BICUBIC)
        imagen2_tk = ImageTk.PhotoImage(imagen2)
        self.label_imagen2 = tk.Label(self.medicion_tab, image=imagen2_tk)
        self.label_imagen2.image = imagen2_tk
        self.label_imagen2.grid(row=0, column=1, padx=(2, 7), pady=(10, 0))

         # Botones "Iniciar" y "Detener"
        button_frame = tk.Frame(self.medicion_tab)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)

        # Configuración del botón "Iniciar"
        self.boton_iniciar = tk.Button(button_frame, text="Iniciar", command=self.iniciar_proceso, relief="groove", padx=10, pady=5, borderwidth=2)
        self.boton_iniciar.grid(row=0, column=0, padx=(100, 30), pady=5)

        # Configuración del botón "Detener"
        self.boton_detener = tk.Button(button_frame, text="Detener", command=self.detener_proceso, relief="groove", padx=10, pady=5, borderwidth=2)
        self.boton_detener.grid(row=0, column=1, padx=(30, 100), pady=5)

        # Botón "Configuraciones"
        configuraciones_image = Image.open("configuraciones.png")
        configuraciones_image = configuraciones_image.resize((20, 20))
        configuraciones_icon = ImageTk.PhotoImage(configuraciones_image)
        boton_configuraciones = ttk.Button(self.medicion_tab, image=configuraciones_icon, command=self.abrir_pestana_configuraciones)
        boton_configuraciones.image = configuraciones_icon
        boton_configuraciones.grid(row=2, column=1, padx=10, pady=(0, 10), sticky="se")

        # Contadores de envío
        frame_contadores = ttk.Frame(self.medicion_tab)
        frame_contadores.grid(row=4, column=1, padx=(80, 30), pady=(0, 10), sticky="w")

        self.label_envio_exitoso = ttk.Label(frame_contadores, text="Envío Exitoso: 0", foreground="green")
        self.label_envio_exitoso.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        self.label_envio_fallido = ttk.Label(frame_contadores, text="Envío Fallido: 0", foreground="red")
        self.label_envio_fallido.grid(row=0, column=4, padx=5, pady=5, sticky="w")

    def create_configuracion_tab(self):
        ttk.Label(self.configuracion_tab, text="URL del Web Service:").grid(row=1, column=1, pady=5, sticky="w")
        url_entry = ttk.Entry(self.configuracion_tab, width=27)
        url_entry.grid(row=1, column=2, pady=5, sticky="w")

        ttk.Label(self.configuracion_tab, text="Client ID:").grid(row=2, column=1, pady=5, sticky="w")
        client_id_entry = ttk.Entry(self.configuracion_tab)
        client_id_entry.grid(row=2, column=2, pady=5, sticky="w")

        ttk.Label(self.configuracion_tab, text="Client Secret:").grid(row=3, column=1, pady=5, sticky="w")
        client_secret_entry = ttk.Entry(self.configuracion_tab)
        client_secret_entry.grid(row=3, column=2, pady=5, sticky="w")

        ttk.Label(self.configuracion_tab, text="Usuario:").grid(row=4, column=1, pady=5, sticky="w")
        username_entry = ttk.Entry(self.configuracion_tab)
        username_entry.grid(row=4, column=2, pady=5, sticky="w")

        ttk.Label(self.configuracion_tab, text="Contraseña:").grid(row=5, column=1, pady=5, sticky="w")
        password_entry = ttk.Entry(self.configuracion_tab)
        password_entry.grid(row=5, column=2, pady=5, sticky="w")

        ttk.Label(self.configuracion_tab, text="URL del token:").grid(row=6, column=1, pady=5, sticky="w")
        token_url_entry = ttk.Entry(self.configuracion_tab, width=27)
        token_url_entry.grid(row=6, column=2, pady=5, sticky="w")

        ttk.Label(self.configuracion_tab, text="PROCESAMIENTO DE DATOS", font=("Helvetica", 13)).grid(row=7, column=1, columnspan=3, pady=(20, 5), sticky="w")
        ttk.Label(self.configuracion_tab, text="Carpeta Origen Data:").grid(row=8, column=1, pady=5, sticky="w")

        # Mostrar la imagen "folder.png" al lado del campo "Carpeta Origen"
        folder_image = Image.open("folder.png")
        folder_image = folder_image.resize((20, 20))  # Redimensiona la imagen
        folder_icon = ImageTk.PhotoImage(folder_image)

        # Asignar la función seleccionar_carpeta al evento de clic del botón
        def seleccionar_carpeta():
            selected_folder = filedialog.askdirectory()
            if selected_folder:
                carpeta_origen_entry.delete(0, tk.END)  # Borrar el contenido actual del Entry
                carpeta_origen_entry.insert(0, selected_folder)  # Insertar la nueva ruta seleccionada

        folder_label = ttk.Button(self.configuracion_tab, image=folder_icon, command=seleccionar_carpeta)
        folder_label.image = folder_icon
        folder_label.grid(row=8, column=4, padx=(5, 0), pady=5, sticky="w")

        carpeta_origen_entry = ttk.Entry(self.configuracion_tab, width=40)
        carpeta_origen_entry.grid(row=8, column=2, columnspan=2, pady=5, sticky="w")

        ttk.Label(self.configuracion_tab, text="Carpeta Origen Imagen:").grid(row=9, column=1, pady=5, sticky="w")

        # Mostrar la imagen "folder.png" al lado del campo "Carpeta Origen Imagen"
        folder_image = Image.open("folder.png")
        folder_image = folder_image.resize((20, 20))  # Redimensiona la imagen
        folder_icon = ImageTk.PhotoImage(folder_image)

        # Asignar la función seleccionar_carpeta_imagen al evento de clic del botón
        def seleccionar_carpeta_imagen():
            selected_folder = filedialog.askdirectory()
            if selected_folder:
                carpeta_origen_imagen_entry.delete(0, tk.END)  # Borrar el contenido actual del Entry
                carpeta_origen_imagen_entry.insert(0, selected_folder)  # Insertar la nueva ruta seleccionada

        folder_label_imagen = ttk.Button(self.configuracion_tab, image=folder_icon, command=seleccionar_carpeta_imagen)
        folder_label_imagen.image = folder_icon
        folder_label_imagen.grid(row=9, column=4, padx=(5, 0), pady=5, sticky="w")

        carpeta_origen_imagen_entry = ttk.Entry(self.configuracion_tab, width=40)
        carpeta_origen_imagen_entry.grid(row=9, column=2, columnspan=2, pady=5, sticky="w")

    def enviar_data(self, data):
        # Cuerpo del JSON

        # Obtener token de acceso
        token_response = requests.post(
            self.token_url,
            auth=HTTPBasicAuth(self.client_id, self.client_secret),
            data={
                "grant_type": "password",
                "username": self.username,
                "password": self.password
            }
        )

        if token_response.status_code == 200:
            access_token = token_response.json().get("access_token")
            # print(access_token)

            # Si se obtiene el token, realizar la solicitud POST con el cuerpo JSON
            if access_token:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }

                response = requests.post(self.api_url, json=data, headers=headers)

                if response.status_code == 200:
                    print("Solicitud exitosa:", response.json())
                    # Incrementar el contador de envíos exitosos
                    self.envio_exitoso += 1
                    # Actualizar el valor del contador en la interfaz
                    self.label_envio_exitoso.config(text=f"Envío Exitoso: {self.envio_exitoso}")
                else:
                    print("Error en la solicitud:", response.text)
                    # Incrementar el contador de envíos fallidos
                    self.envio_fallido += 1
                    # Actualizar el valor del contador en la interfaz
                    self.label_envio_fallido.config(text=f"Envío Fallido: {self.envio_fallido}")

    def procesar_archivos(self):
        while self.ejecutar:
            # Obtener lista de archivos en la carpeta de origen
            archivos = os.listdir(self.carpeta_archivos)

            if archivos:
                for archivo in archivos:
                    if archivo.endswith(".txt"):
                        ruta_completa = os.path.join(self.carpeta_archivos, archivo)

                        with open(ruta_completa, "r") as file:
                            # Leer el contenido del archivo
                            contenido = file.read()

                            # Simular un proceso de envío de datos
                            data = {
                                "nombre_archivo": archivo,
                                "contenido": contenido,
                                "fecha_envio": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                            # Llamar a la función para enviar los datos
                            self.enviar_data(data)

                            # Mover el archivo a la carpeta de "procesados"
                            os.rename(ruta_completa, os.path.join(self.carpeta_procesados, archivo))
            # Agregar un pequeño retraso antes de revisar nuevamente la carpeta
            time.sleep(2)

    def iniciar_proceso(self):
        # Iniciar un hilo para el procesamiento de archivos
        self.proceso_archivos_thread = Thread(target=self.procesar_archivos)
        self.proceso_archivos_thread.start()

    def detener_proceso(self):
        # Detener el hilo de procesamiento de archivos
        self.ejecutar = False

        # Mostrar un mensaje de confirmación
        messagebox.showinfo("Información", "El proceso ha sido detenido con éxito.")


if __name__ == "__main__":
    root = tk.Tk()
    root.resizable(False,False)
    app = ProcesadorArchivos(root)
    root.mainloop()



#comentario prueba
"""
# Crear una instancia de la clase y ejecutar la interfaz
procesador = ProcesadorArchivos()
procesador.ejecutar_interfaz()
"""
