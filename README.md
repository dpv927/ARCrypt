# Biblioteca &lt;kex.h&gt;

## Introduccion
La bilioteca *kex* recibe su nombre por *key exchange*, debido a que implementa diferentes funciones que permiten la comunicacion e intercambio de claves entre dos partes de una comunicacion privadas.

Esta biblioteca hace referencia en sus notaciones a los nombres 'Alice' y 'Bob' como las dos partes que se quieren comunicar entre si, siendo Alice la que empieza el protocolo y Bob como el receptor de esa peticion. Esto es necesario tenerlo en cuenta debido a que algunas funciones incluyen las iniciales de estos nombres a varibles, parametros y funciones.

## Funciones

**Unilaterales**

| Nombre |	Devuelve | 	Parmetros |	Descripcion |
| --- | --- | --- | --- |
kex_uake_initA 	| void | 	u8* send, u8* tk, u8* sk, const u8* pkb |	Alice comienza el protocolo UAKE |
kex_uake_sharedB |	void |	u8* send, u8* k, const u8* recv, const u8* skb | 	Bob envia sus datos |
kex_uake_sharedA |	void | 	u8* k, const u8* recv, const u8* tk, const u8* sk |	Alice comparte sus datos |

**Bilaterales**
