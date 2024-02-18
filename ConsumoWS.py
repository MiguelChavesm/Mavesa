import requests
from requests.auth import HTTPBasicAuth
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import *
import tkinter as tk
from tkinter import messagebox
from threading import Thread
import time

class ProcesadorArchivos:
    def __init__(self,root):
            
        self.root = root
        self.root.title("MONTRA")
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)
        self.medicion_tab = ttk.Frame(self.notebook)
        self.configuracion_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.medicion_tab, text="WebService", state="normal")  # Inicialmente deshabilitada
        self.notebook.add(self.configuracion_tab, text="Configuración", state="normal")  # Inicialmente deshabilitada
        
        self.create_medicion_tab()
        self.create_configuracion_tab()
        
        
        
        # URL del servicio de acceso a tokens
        self.token_url = "https://mingle-sso.inforcloudsuite.com:443/NUGH6DGWYB5E8AMU_TST/as/token.oauth2"

        # Información de autenticación
        self.api_url = "https://mingle-ionapi.inforcloudsuite.com/NUGH6DGWYB5E8AMU_TST/WM/wmwebservice_rest/NUGH6DGWYB5E8AMU_TST_ENTERPRISE/packs"
        self.client_id = "NUGH6DGWYB5E8AMU_TST~_tOirRI-jy9pzu4Xun2ESJvNqMVTHg_jJntMDzFtgV0"
        self.client_secret = "ptQu3maUMRAlScq_xe2-mZLsJkPtT_fkrDWTOGEVJreUHyPqavPhncXtX1cRCVE8uNSQei4CQO0xqssZvwgU9A"
        self.username = "NUGH6DGWYB5E8AMU_TST#ktzJTSlcIfY9X5sH9tUacghKkC7n7TLZXCgx51jQyHjPXJvxzarlQsufPAusg4XgDa6GbLvXKcKvjwN7ljHBlg"
        self.password = "jxy5rCtcwN_jf0b8R1Cbe2FxkBQ-paCjmDwspfGqu7E1Mwj0SsDneZKBF41g4alWZ-lTUWCRl0p7M8tJ0yVknA"

        # Ruta de la carpeta donde se encuentran los archivos txt
        #self.carpeta_archivos = "Data_mavesa/"
        self.carpeta_archivos="C:/Users/montr/Downloads/Prueba Mavesa/"
        
        # Ruta de la carpeta "procesados"
        self.carpeta_procesados = "Procesados/"

        # Variable para controlar la ejecución del programa
        self.ejecutar = True



    def create_medicion_tab(self):
        # Botón "Iniciar"
        self.boton_iniciar = tk.Button(self.medicion_tab, text="Iniciar", command=self.iniciar_proceso)
        self.boton_iniciar.pack(pady=10)

        # Botón "Detener"
        self.boton_detener = tk.Button(self.medicion_tab, text="Detener", command=self.detener_proceso)
        self.boton_detener.pack(pady=10)

    def create_configuracion_tab(self):
        
        self.token_url=tk.StringVar()
        self.api_url = tk.StringVar()
        self.client_id = tk.StringVar()
        self.client_secret = tk.StringVar()
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.carpeta_archivos = tk.StringVar()
        self.carpeta_procesados = tk.StringVar()

        
        ttk.Label(self.configuracion_tab, text="URL del Web Service:").grid(row=1, column=1, pady=5, sticky="w")
        url_entry = ttk.Entry(self.configuracion_tab, textvariable=self.api_url, width=27)
        url_entry.grid(row=1, column=2, pady=5, sticky="w")
        
        ttk.Label(self.configuracion_tab, text="Client ID:").grid(row=2, column=1, pady=5, sticky="w")
        client_id_entry = ttk.Entry(self.configuracion_tab, textvariable=self.client_id)
        client_id_entry.grid(row=2, column=2, pady=5, sticky="w")

        ttk.Label(self.configuracion_tab, text="Client Secret:").grid(row=3, column=1, pady=5, sticky="w")
        client_secret_entry = ttk.Entry(self.configuracion_tab, textvariable=self.client_secret)
        client_secret_entry.grid(row=3, column=2, pady=5, sticky="w")
        
        ttk.Label(self.configuracion_tab, text="Usuario:").grid(row=4, column=1, pady=5, sticky="w")
        username_entry = ttk.Entry(self.configuracion_tab, textvariable=self.username)
        username_entry.grid(row=4, column=2, pady=5, sticky="w")
        
        ttk.Label(self.configuracion_tab, text="Contraseña:").grid(row=5, column=1,  pady=5, sticky="w")
        password_entry = ttk.Entry(self.configuracion_tab, textvariable=self.password)
        password_entry.grid(row=5, column=2, pady=5, sticky="w")
        
        ttk.Label(self.configuracion_tab, text="URL del token:").grid(row=6, column=1, pady=5, sticky="w")
        token_url_entry = ttk.Entry(self.configuracion_tab, textvariable=self.token_url, width=27)
        token_url_entry.grid(row=6, column=2, pady=5, sticky="w")

        ttk.Label(self.configuracion_tab, text="PROCESAMIENTO DE DATOS",font=("Helvetica", 13)).grid(row=7, column=1, columnspan=3, pady=(20,5), sticky="w")
        ttk.Label(self.configuracion_tab, text="Carpeta Origen:").grid(row=8, column=1, pady=5, sticky="w")
        
        carpeta_origen_entry = ttk.Entry(self.configuracion_tab, textvariable=self.carpeta_archivos, width=40)
        carpeta_origen_entry.grid(row=8, column=2, columnspan=2, pady=5, sticky="w")
        
        
        
        ttk.Label(self.configuracion_tab, text="Hola")

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
                else:
                    print("Error en la solicitud:", response.text)
            else:
                print("No se pudo obtener el token de acceso.")
        else:
            print("Error al obtener el token de acceso:", token_response.text)

    def procesar_archivo(self, archivo):
        try:
            with open(archivo, "r") as f:
                line = f.readline().strip()
                datos = line.split("|")

                SKU, Packtype, Tipodepaquete, Cantidad, Largo, Ancho, Alto, Peso, Descripcion = datos

                # Convertir los valores a números (Largo, Ancho, Alto y Peso)
                Largo = float(Largo)
                Ancho = float(Ancho)
                Alto = float(Alto)
                Peso = float(Peso)


                # Puedes imprimir los datos procesados
                print(f"SKU: {SKU}")
                print(f"Packtype: {Packtype}")
                print(f"Tipodepaquete: {Tipodepaquete}")
                print(f"Cantidad: {Cantidad}")
                print(f"Largo: {Largo}")
                print(f"Ancho: {Ancho}")
                print(f"Alto: {Alto}")
                print(f"Peso: {Peso}")
                print(f"Descripcion: {Descripcion}")

                if Packtype == "Unidad-UOM3":
                    data = {
                        "packkey": f"{SKU}_{Cantidad}",
                        "packdescr": Descripcion,
                        "packuom1": "CJ",
                        "packuom3": Tipodepaquete,
                        "casecnt": Cantidad,
                        "qty": 1,
                        "widthuom3": Ancho,
                        "lengthuom3": Largo,
                        "heightuom3": Alto,
                        "weightuom3": Peso,
                        "widthuom1": Ancho,
                        "lengthuom1": Largo,
                        "heightuom1": Alto,
                        "weightuom1": Peso,
                        "pallethi": 1,
                        "palletti": 1,
                        "ext_udf_str1": SKU,
                        "ext_udf_str2": Tipodepaquete
                    }
                    print(data)
                    self.enviar_data(data)
                elif Packtype == "Caja-UOM1" or Packtype == "Caja2-UOM1" or Packtype == "Caja3-UOM1":
                    data = {
                        "packkey": f"{SKU}_{Cantidad}",
                        "packdescr": Descripcion,
                        "packuom1": Tipodepaquete,
                        "casecnt": Cantidad,
                        "qty": 1,
                        "widthuom1": Ancho,
                        "lengthuom1": Largo,
                        "heightuom1": Alto,
                        "weightuom1": Peso,
                        "pallethi": 1,
                        "palletti": 1,
                        "ext_udf_str1": SKU,
                        "ext_udf_str2": Tipodepaquete
                    }
                    print(data)
                    self.enviar_data(data)


                # Mueve el archivo procesado a la carpeta "procesados"
                nuevo_nombre = os.path.join(self.carpeta_procesados, os.path.basename(archivo))
                # Cerrar el archivo antes de intentar moverlo
                f.close()
                os.rename(archivo, nuevo_nombre)

                print(f"Archivo procesado: {archivo}")

        except Exception as e:
            print(f"Error al procesar el archivo {archivo}: {str(e)}")

    def obtener_archivo_mas_antiguo(self, carpeta):
        archivos = [f for f in os.listdir(carpeta) if f.endswith(".txt")]
        if not archivos:
            return None
        archivos.sort(key=lambda x: datetime.strptime(x.split("_")[1].replace('.txt', ''), "%Y%m%d%H%M%S"))
        return os.path.join(carpeta, archivos[0])

    def procesar_archivos_continuamente(self):
        while self.ejecutar:
            archivo = self.obtener_archivo_mas_antiguo(self.carpeta_archivos)
            if archivo:
                self.procesar_archivo(archivo)


    def iniciar_proceso(self):
        # Inicia un hilo para ejecutar el procesamiento en segundo plano
        self.ejecutar=True
        Thread(target=self.procesar_archivos_continuamente).start()

    def detener_proceso(self):
        try:
            # Detiene el hilo de procesamiento
            self.ejecutar = False
            messagebox.showinfo("Proceso detenido", "El proceso ha sido detenido exitosamente.")
        except Exception as e:
            messagebox.showerror("Error al detener el proceso", f"Error: {str(e)}")

    def ejecutar_interfaz(self):
        # Ejecutar la interfaz gráfica
        root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    root.resizable(False,False)
    app = ProcesadorArchivos(root)
    app.ejecutar_interfaz()
#comentario prueba
"""
# Crear una instancia de la clase y ejecutar la interfaz
procesador = ProcesadorArchivos()
procesador.ejecutar_interfaz()
"""