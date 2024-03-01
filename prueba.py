import uuid

mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
formatted_mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
formatted_mac=formatted_mac.upper()
formatted_mac = formatted_mac.replace(":", "-")
print(formatted_mac)