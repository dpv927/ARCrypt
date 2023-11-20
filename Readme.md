# kayberc

## Dependencias de Compilación
Si quieres compilar el programa, deberas instalar los siguientes paquetes:
- gcc
- make
- libssl-dev
- libgtk-3-0
- libgtk-3-doc
- build-essential
- pkg-config

## Clonar y utilizar

Para probar el programa, primero clona el repositorio donde quieras, y despues ejecuta make en el mismo repositorio:

```bash
# Clona el repositorio
git clone https://github.com/dpv927/kayberc.git

# Instala las librerias de kyber
cd kayberc 
sudo cp -r libs/*.so /usr/lib/
sudo cp -r libs/kyber_api.h /usr/include/

# Prueba a compilar
make
```
