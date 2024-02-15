import os
from datetime import datetime

# Ruta de la carpeta donde se encuentran los archivos txt
carpeta_archivos = "Data_mavesa/"

# Ruta de la carpeta "procesados"
carpeta_procesados = "Procesados/"

def procesar_archivo(archivo):
    try:
        with open(archivo, "r") as f:
            line = f.readline().strip()
            datos = line.split("|")

            SKU, Packtype, Niveldepaquete, Largo, Ancho, Alto, Peso, ImageFile = datos

            # Convertir los valores a números (Largo, Ancho, Alto y Peso)
            Largo = float(Largo)
            Ancho = float(Ancho)
            Alto = float(Alto)
            Peso = float(Peso)

            # Realizar cálculos o lógica de procesamiento aquí
            # Por ejemplo, calcular el volumen
            Niveldepaqueteint=Niveldepaquete*1
            Volumen = Largo * Ancho * Alto

            # Puedes imprimir los datos procesados
            print(f"SKU: {SKU}")
            print(f"Packtype: {Packtype}")
            print(f"Niveldepaquete: {Niveldepaquete}")
            print(f"Largo: {Largo}")
            print(f"Ancho: {Ancho}")
            print(f"Alto: {Alto}")
            print(f"Peso: {Peso}")
            print(f"Volumen: {Volumen}")
            print(f"ImageFile: {ImageFile}")
            print(Niveldepaqueteint)
            if Packtype=="UNIDAD" and Niveldepaquete=="1":
                data = {
                    "packkey": SKU,
                    "packdescr": "Packtest",
                    "packuom1": "CS",
                    "packuom2": "EA",
                    "packuom3": "PL",
                    "casecnt": 1,
                    "qty": 1,
                    "widthuom3": Ancho,
                    "lengthuom3": Largo,
                    "heightuom3": Alto,
                    "weightuom3": Peso,
                    "widthuom2": "",
                    "lengthuom2":  "",
                    "heightuom2":  "",
                    "weightuom2":  "",
                    "widthuom1":  "",
                    "lengthuom1":  "",
                    "heightuom1":  "",
                    "weightuom1":  ""
                }
            elif Packtype=="UNIDAD" and Niveldepaquete=="2":
                largouom3=Largo
                anchouom3=Ancho
                altouom3=Alto
                pesouom3=Peso
            elif Packtype=="SUBCAJA" and Niveldepaquete=="2":
                data = {
                    "packkey": SKU,
                    "packdescr": "Packtest",
                    "packuom1": "CS",
                    "packuom2": "EA",
                    "packuom3": "PL",
                    "casecnt": 1,
                    "qty": 1,
                    "widthuom3": anchouom3,
                    "lengthuom3": largouom3,
                    "heightuom3": altouom3,
                    "weightuom3": pesouom3,
                    "widthuom2": Ancho,
                    "lengthuom2":  Largo,
                    "heightuom2":  Alto,
                    "weightuom2":  Peso,
                    "widthuom1":  "",
                    "lengthuom1":  "",
                    "heightuom1":  "",
                    "weightuom1":  ""
                }
                
                print (data)
        
        
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