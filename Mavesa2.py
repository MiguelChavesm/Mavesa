import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import *
from threading import Thread
import base64
import xml.etree.ElementTree as ET
import time


class ProcesadorArchivos:
    def __init__(self, root):
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
        
        
        self.root.protocol("WM_DELETE_WINDOW", self.cerrar_aplicacion)
        
        self.token_url = "https://mingle-sso.inforcloudsuite.com:443/NUGH6DGWYB5E8AMU_TST/as/token.oauth2"
        # Información de autenticación
        self.api_url = "https://mingle-ionapi.inforcloudsuite.com/NUGH6DGWYB5E8AMU_TST/WM/wmwebservice_rest/NUGH6DGWYB5E8AMU_TST_ENTERPRISE/packs"
        self.url_api_image = "https://mingle-ionapi.inforcloudsuite.com/NUGH6DGWYB5E8AMU_TST/IDM/api/bc?$checkout=true&$language=en"
        
        self.client_id = "NUGH6DGWYB5E8AMU_TST~_tOirRI-jy9pzu4Xun2ESJvNqMVTHg_jJntMDzFtgV0"
        self.client_secret = "ptQu3maUMRAlScq_xe2-mZLsJkPtT_fkrDWTOGEVJreUHyPqavPhncXtX1cRCVE8uNSQei4CQO0xqssZvwgU9A"
        self.username = "NUGH6DGWYB5E8AMU_TST#ktzJTSlcIfY9X5sH9tUacghKkC7n7TLZXCgx51jQyHjPXJvxzarlQsufPAusg4XgDa6GbLvXKcKvjwN7ljHBlg"
        self.password = "jxy5rCtcwN_jf0b8R1Cbe2FxkBQ-paCjmDwspfGqu7E1Mwj0SsDneZKBF41g4alWZ-lTUWCRl0p7M8tJ0yVknA"

        # Ruta de la carpeta donde se encuentran los archivos txt
        #self.carpeta_archivos = "Data_mavesa/"
        self.carpeta_archivos="C:/CubiScan/QbitDB/Data/Texto"
        self.carpeta_imagenes="C:/CubiScan/QbitDB/Data/Images"
        # Ruta de la carpeta "procesados"
        self.carpeta_procesados_data = "Procesados/Data"
        self.carpeta_procesados_data_e = "Procesados/Data/Errores/"
        
        self.carpeta_procesados_img = "Procesados/Images"
        self.carpeta_procesados_img_e = "Procesados/Images/Errores/"

        self.carpeta_procesados
        # Variable para controlar la ejecución del programa
        self.ejecutar = True
        
        self.error=False

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

    def enviar_data(self, data, url, archivo, es_imagen=False):
            # Verificar conexión a Internet
            
        try:
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

                if access_token:
                    headers = {
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json"
                    }

                    response = requests.post(url, json=data, headers=headers)

                    if response.status_code == 200:
                        try:
                            self.error=False
                            json_response = response.json()
                            #print("Solicitud exitosa (JSON):", json_response)
                            print("El dato se envió correctamente al WS")
                        except requests.exceptions.JSONDecodeError:
                            try:
                                self.error=False
                                # Intenta analizar la respuesta como XML
                                xml_response = ET.fromstring(response.text)
                                # print("Solicitud exitosa (XML):", ET.dump(xml_response))
                                print("La imagen se envió correctamente al WS")
                            except ET.ParseError:
                                messagebox.showerror("La respuesta no es ni JSON ni XML válido. Contenido de la respuesta:", response.text)
                    else:
                        messagebox.showerror("Error en la solicitud:", response.text)
                        # Mover el archivo a la carpeta de errores
                        if es_imagen:
                            self.mover_a_carpeta_errores(archivo, es_imagen=True)
                        else: 
                            self.mover_a_carpeta_errores(archivo, es_imagen=False)
                else:
                    self.error=True
                    messagebox.showerror(f"No se pudo obtener el token de acceso")
                    # Mover el archivo a la carpeta de errores
                    if es_imagen:
                        self.mover_a_carpeta_errores(archivo, es_imagen=True)
                    else: 
                        self.mover_a_carpeta_errores(archivo, es_imagen=False)
            else:
                self.error=True
                messagebox.showerror(f"Error al obtener el token de acceso:", token_response.text)
                # Mover el archivo a la carpeta de errores
                if es_imagen:
                    self.mover_a_carpeta_errores(archivo, es_imagen=True)
                else: 
                    self.mover_a_carpeta_errores(archivo, es_imagen=False)
                
        except ConnectionError:
            self.error=True
            messagebox.showerror("Error de conexión", "No se pudo establecer conexión con el servidor.")
            # Mover el archivo a la carpeta de errores
            if es_imagen:
                self.mover_a_carpeta_errores(archivo, es_imagen=True)
            else: 
                self.mover_a_carpeta_errores(archivo, es_imagen=False)

    def verificar_conexion(self):
        try:
            # Intentar hacer una solicitud a un sitio web conocido
            requests.get("http://www.google.com", timeout=1)
            return True
        except requests.ConnectionError:
            return False

    def mover_a_carpeta_errores(self, archivo, es_imagen=False):
        carpeta_errores = self.carpeta_procesados_data_e if not es_imagen else self.carpeta_procesados_img_e
        carpeta_errores = os.path.join(carpeta_errores)

        if not os.path.exists(carpeta_errores):
            os.makedirs(carpeta_errores)

        archivo_con_error = os.path.join(carpeta_errores, os.path.basename(archivo))

        if os.path.exists(archivo_con_error):
            os.remove(archivo_con_error)
        try:
            os.rename(archivo, archivo_con_error)
        except: pass

    def procesar_archivo(self, archivo):

        if not self.verificar_conexion():
            messagebox.showerror("Error de conexión", "No hay conexión a Internet.")
            return

        try:
            carpeta_procesados_data = os.path.join(self.carpeta_procesados_data)
            if not os.path.exists(carpeta_procesados_data):
                os.makedirs(carpeta_procesados_data)

            nuevo_nombre = os.path.join(carpeta_procesados_data, os.path.basename(archivo))
            # Verificar si el archivo de destino ya existe y eliminarlo
            if os.path.exists(nuevo_nombre):
                os.remove(nuevo_nombre)
            
            with open(archivo, "r") as f:
                line = f.readline().strip()
                datos = line.split("|")

                if len(datos) != 9:
                    raise ValueError("La estructura del archivo no es válida")


                SKU, Packtype, Tipodepaquete, Cantidad, Largo, Ancho, Alto, Peso, Descripcion = datos

                # Convertir los valores a números (Largo, Ancho, Alto y Peso)
                Largo = float(Largo)
                Ancho = float(Ancho)
                Alto = float(Alto)
                Peso = float(Peso)


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
                    #print(data)
                    f.close()
                    self.enviar_data(data, self.api_url, archivo, es_imagen=False)
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
                    #print(data)
                    f.close()
                    self.enviar_data(data, self.api_url, archivo, es_imagen=False)
            
                if not self.error:
                    carpeta_procesados_data = os.path.join(self.carpeta_procesados_data)
                    if not os.path.exists(carpeta_procesados_data):
                        os.makedirs(carpeta_procesados_data)
                    
                    # Mueve el archivo procesado a la carpeta "procesados"
                    nuevo_nombre = os.path.join(self.carpeta_procesados_data, os.path.basename(archivo))
                    # Cerrar el archivo antes de intentar moverlo
                    os.rename(archivo, nuevo_nombre)

                print(f"Archivo procesado: {archivo}")


        except ValueError as ve:
            # Manejar el error si la estructura del archivo no es válida
            messagebox.showerror("Error", f"Error al procesar el archivo {archivo}: {str(ve)}")
            
            carpeta_procesados_data_e = os.path.join(self.carpeta_procesados_data_e)
            if not os.path.exists(carpeta_procesados_data_e):
                os.makedirs(carpeta_procesados_data_e)

            # Mueve el archivo con error a la carpeta de errores
            nuevo_nombre_error = os.path.join(carpeta_procesados_data_e, os.path.basename(archivo))
            f.close()
            
            if os.path.exists(nuevo_nombre_error):
                os.remove(nuevo_nombre_error)
            
            os.rename(archivo, nuevo_nombre_error)

    def procesar_imagen(self, ruta_imagen):
        try:
            
            carpeta_procesados_img = os.path.join(self.carpeta_procesados_img)
            if not os.path.exists(carpeta_procesados_img):
                os.makedirs(carpeta_procesados_img)

            nuevo_nombre = os.path.join(carpeta_procesados_img, os.path.basename(ruta_imagen))

            # Verificar si el archivo de destino ya existe y eliminarlo
            if os.path.exists(nuevo_nombre):
                os.remove(nuevo_nombre)

            with open(ruta_imagen, "rb") as img_file:
                # Leer la imagen en bytes
                img_bytes = img_file.read()

                # Codificar la imagen en base64
                img_base64 = base64.b64encode(img_bytes).decode('utf-8')
                # Construir el JSON de la imagen
                json_imagen = {
                    "item": {
                        "attrs": {
                            "attr": [
                                {"name": "storer", "value": "LLP"},
                                {"name": "sku", "value": os.path.basename(ruta_imagen).split('_')[0]},  # Obtener el "CODIGO" del nombre de la imagen
                                {"name": "uom", "value": os.path.basename(ruta_imagen).split('_')[1].split('.')[0]}  # Obtener el "UN" del nombre de la imagen
                            ]
                        },
                        "resrs": {
                            "res": [
                                {
                                    "filename": os.path.basename(ruta_imagen),
                                    "base64": img_base64
                                }
                            ]
                        },
                        "acl": {
                            "name": "Public"
                        },
                        "entityName": "SCE_Product_Image"
                    }
                }
                # Puedes imprimir el JSON antes de enviarlo
                # Enviar el JSON al servicio de imágenes
                #if not self.error:
                img_file.close()
                self.enviar_data(json_imagen, self.url_api_image, ruta_imagen, es_imagen=True)
                
                carpeta_procesados_img = os.path.join(self.carpeta_procesados_img)
                if not os.path.exists(carpeta_procesados_img):
                    os.makedirs(carpeta_procesados_img)
                
                nuevo_nombre = os.path.join(carpeta_procesados_img, os.path.basename(ruta_imagen))
                # Cerrar el archivo antes de intentar moverlo
                try: 
                    os.rename(ruta_imagen, nuevo_nombre)
                except:
                    print("Ya se ha movido el archivo")
                print(f"Imagen procesada: {ruta_imagen}")

        except Exception as e:
            messagebox.showerror("Error", f"Error al procesar la imagen:", f"Error: {str(e)}")

    def obtener_archivo_mas_antiguo(self, carpeta, extension=None, es_imagen=False):
        time.sleep(1)
        archivos = [f for f in os.listdir(carpeta) if f.endswith(extension)] if extension else os.listdir(carpeta)
        if not archivos:
            return None
        try:
            for archivo in archivos:
                if extension == ".jpg" and es_imagen:
                    datetime.strptime(archivo.split("_")[2].replace('.jpg', ''), "%Y%m%d%H%M%S")
                elif extension == ".txt" and not es_imagen:
                    datetime.strptime(archivo.split("_")[1].replace('.txt', ''), "%Y%m%d%H%M%S")
        except Exception as e:
            # Manejar el error individualmente para cada archivo
            messagebox.showerror("Error", f"El archivo ({archivo}): no cumple con la estructura definida {str(e)}")
            carpeta_errores = self.carpeta_procesados_data_e if not es_imagen else self.carpeta_procesados_img_e
            carpeta_errores = os.path.join(carpeta_errores)

            if not os.path.exists(carpeta_errores):
                os.makedirs(carpeta_errores)

            # Mueve el archivo con error a la carpeta de errores
            archivo_con_error = os.path.join(carpeta_errores, archivo)
            
            if os.path.exists(archivo_con_error):
                os.remove(archivo_con_error)

            try:
                os.rename(os.path.join(carpeta, archivo), archivo_con_error)
            except: pass   
            time.sleep(2)

            return None

        # Ordenar archivos después de asegurarse de que todos cumplen con el formato
        archivos.sort(key=lambda x: datetime.strptime(x.split("_")[2].replace('.jpg', ''), "%Y%m%d%H%M%S")) if extension == ".jpg" and es_imagen else archivos.sort(key=lambda x: datetime.strptime(x.split("_")[1].replace('.txt', ''), "%Y%m%d%H%M%S"))
        
        if archivos:
            # Si no hubo error, devolver el archivo más antiguo
            return os.path.join(carpeta, archivos[0])
        else:
            return None

    def procesar_archivos_continuamente(self):
        while self.ejecutar:
            archivo_txt = self.obtener_archivo_mas_antiguo(self.carpeta_archivos, ".txt", es_imagen=False)
            archivo_img = self.obtener_archivo_mas_antiguo(self.carpeta_imagenes, ".jpg", es_imagen=True)  # Ajustar la extensión
        

            if archivo_txt:
                self.error=True
                self.procesar_archivo(archivo_txt)
            elif archivo_img:
                self.error=True
                self.procesar_imagen(archivo_img)

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
        
    def cerrar_aplicacion(self):
        # Detener el hilo de procesamiento
        self.ejecutar = False
        # Cerrar la interfaz gráfica
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.resizable(False,False)
    app = ProcesadorArchivos(root)
    app.ejecutar_interfaz()