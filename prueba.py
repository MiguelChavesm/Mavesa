import requests
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET

# URL del servicio de acceso a tokens
token_url = "https://mingle-sso.inforcloudsuite.com:443/NUGH6DGWYB5E8AMU_TST/as/token.oauth2"

# Información de autenticación
client_id = "NUGH6DGWYB5E8AMU_TST~_tOirRI-jy9pzu4Xun2ESJvNqMVTHg_jJntMDzFtgV0"
client_secret = "ptQu3maUMRAlScq_xe2-mZLsJkPtT_fkrDWTOGEVJreUHyPqavPhncXtX1cRCVE8uNSQei4CQO0xqssZvwgU9A"
username = "NUGH6DGWYB5E8AMU_TST#ktzJTSlcIfY9X5sH9tUacghKkC7n7TLZXCgx51jQyHjPXJvxzarlQsufPAusg4XgDa6GbLvXKcKvjwN7ljHBlg"
password = "jxy5rCtcwN_jf0b8R1Cbe2FxkBQ-paCjmDwspfGqu7E1Mwj0SsDneZKBF41g4alWZ-lTUWCRl0p7M8tJ0yVknA"

# Cuerpo del JSON
data = {
	"item": {
		"attrs": {
			"attr": [
				{
					"name": "storer",
					"value": "LLP"
				},
				{
					"name": "sku",
					"value": "1234565"
				},
				{
					"name": "uom",
					"value": "UN"
				}
			]
		},
		"resrs": {
			"res": [
				{
					"filename": "prueba.jpg",
					"base64": "img_base64"
				}
			]
		},
		"acl": {
			"name": "Public"
		},
		"entityName": "SCE_Product_Image"
	}
}

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
    
    # Si se obtiene el token, realizar la solicitud POST con el cuerpo JSON
    if access_token:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        #api_url = "https://mingle-ionapi.inforcloudsuite.com/NUGH6DGWYB5E8AMU_TST/WM/wmwebservice_rest/NUGH6DGWYB5E8AMU_TST_ENTERPRISE/packs"
        api_url = "https://mingle-ionapi.inforcloudsuite.com/NUGH6DGWYB5E8AMU_TST/IDM/api/bc?$checkout=true&$language=en"

        response = requests.post(api_url, json=data, headers=headers)

        if response.status_code == 200:
            try:
                json_response = response.json()
                print("Solicitud exitosa (JSON):", json_response)
            except requests.exceptions.JSONDecodeError:
                try:
                    # Intenta analizar la respuesta como XML
                    xml_response = ET.fromstring(response.text)
                    print("Solicitud exitosa (XML):", ET.dump(xml_response))
                except ET.ParseError:
                    print("La respuesta no es ni JSON ni XML válido. Contenido de la respuesta:", response.text)

        else:
            print("Error en la solicitud:", response.text)
            print(f"Estado de la respuesta: {response.status_code}")
            print(f"Contenido de la respuesta: {response.text}")
    else:
        print("No se pudo obtener el token de acceso.")
else:
    print("Error al obtener el token de acceso:", token_response.text)
