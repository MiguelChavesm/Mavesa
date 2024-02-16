import requests
from requests.auth import HTTPBasicAuth
import os
from datetime import datetime

# URL del servicio de acceso a tokens
token_url = "https://mingle-sso.inforcloudsuite.com:443/NUGH6DGWYB5E8AMU_TST/as/token.oauth2"

# Información de autenticación
client_id = "NUGH6DGWYB5E8AMU_TST~_tOirRI-jy9pzu4Xun2ESJvNqMVTHg_jJntMDzFtgV0"
client_secret = "ptQu3maUMRAlScq_xe2-mZLsJkPtT_fkrDWTOGEVJreUHyPqavPhncXtX1cRCVE8uNSQei4CQO0xqssZvwgU9A"
username = "NUGH6DGWYB5E8AMU_TST#ktzJTSlcIfY9X5sH9tUacghKkC7n7TLZXCgx51jQyHjPXJvxzarlQsufPAusg4XgDa6GbLvXKcKvjwN7ljHBlg"
password = "jxy5rCtcwN_jf0b8R1Cbe2FxkBQ-paCjmDwspfGqu7E1Mwj0SsDneZKBF41g4alWZ-lTUWCRl0p7M8tJ0yVknA"

# Ruta de la carpeta donde se encuentran los archivos txt
carpeta_archivos = "Data_mavesa/"

# Ruta de la carpeta "procesados"
carpeta_procesados = "Procesados/"

def enviar_data(data): 
# Cuerpo del JSON

    # Obtener token de acceso
    token_response = requests.post(
        token_url,
        auth=HTTPBasicAuth(client_id, client_secret),
        data={
            "grant_type": "password",
            "username": username,
            "password": password
        }
    )

    if token_response.status_code == 200:
        access_token = token_response.json().get("access_token")
        #print(access_token)

        
        # Si se obtiene el token, realizar la solicitud POST con el cuerpo JSON
        if access_token:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            api_url = "https://mingle-ionapi.inforcloudsuite.com/NUGH6DGWYB5E8AMU_TST/WM/wmwebservice_rest/NUGH6DGWYB5E8AMU_TST_ENTERPRISE/packs"

            response = requests.post(api_url, json=data, headers=headers)

            if response.status_code == 200:
                print("Solicitud exitosa:", response.json())
            else:
                print("Error en la solicitud:", response.text)
        else:
            print("No se pudo obtener el token de acceso.")
    else:
        print("Error al obtener el token de acceso:", token_response.text)

def procesar_archivo(archivo):
    try:
        with open(archivo, "r") as f:
            line = f.readline().strip()
            datos = line.split("|")

            SKU, Packtype, Tipodepaquete, Cantidad ,Largo, Ancho, Alto, Peso, Descripcion = datos

            # Convertir los valores a números (Largo, Ancho, Alto y Peso)
            Largo = float(Largo)
            Ancho = float(Ancho)
            Alto = float(Alto)
            Peso = float(Peso)

            # Realizar cálculos o lógica de procesamiento aquí

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

            if Packtype=="Unidad-UOM3":
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
                    "widthuom1":  Ancho,
                    "lengthuom1": Largo,
                    "heightuom1": Alto,
                    "weightuom1": Peso,
                    "pallethi": 1,
	                "palletti": 1,
                 	"ext_udf_str1": SKU,
	                "ext_udf_str2": Tipodepaquete
                }
                print (data)
                enviar_data(data)
            elif Packtype=="Caja-UOM1":
                data = {
                    "packkey": f"{SKU}_{Cantidad}",
                    "packdescr": Descripcion,
                    "packuom1": Tipodepaquete,
                    "casecnt": Cantidad,
                    "qty": 1,
                    "widthuom1":  Ancho,
                    "lengthuom1": Largo,
                    "heightuom1": Alto,
                    "weightuom1": Peso,
                    "pallethi": 1,
	                "palletti": 1,
                 	"ext_udf_str1": SKU,
	                "ext_udf_str2": Tipodepaquete
                }
                print (data)
                enviar_data(data)
        
        
            # Mueve el archivo procesado a la carpeta "procesados"

            print(f"Archivo procesado: {archivo}")

    except Exception as e:
        print(f"Error al procesar el archivo {archivo}: {str(e)}")

def obtener_archivo_mas_antiguo(carpeta):
    archivos = [f for f in os.listdir(carpeta) if f.endswith(".txt")]
    if not archivos:
        return None

    archivos.sort(key=lambda x: datetime.strptime(x.split("_")[1].replace('.txt', ''), "%Y%m%d%H%M%S"))
    return os.path.join(carpeta, archivos[0])

while True:
    archivo = obtener_archivo_mas_antiguo(carpeta_archivos)
    if archivo:
        procesar_archivo(archivo)
        
        # Verifica si el archivo todavía existe antes de intentar moverlo
        if os.path.exists(archivo):
            nuevo_nombre = os.path.join(carpeta_procesados, os.path.basename(archivo))
            os.rename(archivo, nuevo_nombre)
        else:
            print(f"El archivo {archivo} ya no existe. No se puede mover.")
    else:
        print("No hay más archivos por procesar.")
        break


