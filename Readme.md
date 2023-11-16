# kayberc

## Dependencias
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

## Contenidos
### Modulos
- <a href="https://github.com/dpv927/kayberc/tree/main/openSSL">Modulo de encriptacion con OpenSSL</a>
- <a href="https://github.com/dpv927/kayberc/tree/main/gtk">Modulo de interfaz grafica (GUI)</a>

## Referencias
**Algoritmo AES**
- <a href="https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf"> Especificaciones de AES por el NIST</a>
- <a href="https://es.wikipedia.org/wiki/Advanced_Encryption_Standard">AES en Wikipedia</a>
- <a href="https://www.geeksforgeeks.org/advanced-encryption-standard-aes/">AES en GeeksforGeeks</a>
- <a href="https://www.youtube.com/watch?v=NHuibtoL_qk">Video de funcionamiento interno AES</a>
- <a href="https://www.youtube.com/watch?v=w4aWIVhcUyo&t=1918s">Video expansion de claves AES</a>
- <a href="https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf">Pruebas para AES128</a>

**Kyber**
- <a href="https://pq-crystals.org/kyber/">Pagina oficial de Kyber</a>
- <a href="https://github.com/pq-crystals/kyber">Github de Kyber</a>
- <a href="https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf">Especificaciones de Kyber</a>
- <a href="https://cryptopedia.dev/posts/kyber/">Funcionamiento basico de Kayber</a>
- <a href="https://en.wikipedia.org/wiki/Kyber">Kyber en Wikipedia</a>

**Otros**
- <a href="https://www.crypto101.io/">Curso de criptografia (Crypto 101)</a>
