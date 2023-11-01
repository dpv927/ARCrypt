#pragma once

/* @brief Devuelve la ruta elegida del archivo elegido 
 * que se va a encriptar. */
char* get_enc_selected_file(void);

/* @brief Devuelve la ruta elegida del archivo elegido 
 * que se va a desencriptar. */
char* get_dec_selected_file(void);

/* @brief Devuelve la ruta elegida del archivo que contiene 
 * la clave AES para la desencriptacion. */
char* get_dec_selected_key(void);

/* @brief libera la memoria asignada a las rutas de 
 * los archivos. */
void free_paths(void);

/* @brief Funcion que inicializa las propiedades de la ventana principal
 * del programa. La ventana contiene los Siguientes elementos:
 * 
 * Apartado de encriptacion:
 * 		- FileChooser para elegir el archivo a encriptar
 * 		- Boton de confirmacion (iniciara el proceso de encriptacion)
 * 
 * Apartado de desencriptacion:
 * 		- FileChooser para elegir el archivo a desencriptar
 * 		- FileChooser para elegir el archivo con la clave AES
 * 		- Boton de confirmacion (iniciara el proceso de encriptacion)
 * 
 * @returns 0 si no ha habido ningun error, 1 si ha ocurrido un error
 * al generar alguna de las propiedades de la ventana.
 * * * * */
 GtkWidget* create_main_window(void(*enc_func)(GtkButton* b, gpointer p),
	void(*dec_func)(GtkButton* b, gpointer p));
