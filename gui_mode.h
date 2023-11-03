#pragma once
#include <gtk/gtk.h>

/* @brief Inicia el programa con una GUI. 
* @param argc Contador de arguimentos recibidos por el programa.
* @param argv Lista de argumentos recibidos por el programa.
* * * */
void init_gui(int argc, char* argv[]);

/* @brief Funcion que inicia la rutina de encriptacion de un archivo
* en caso de que el usuario presione el boton "confirmar operacion"
* del apartado Encriptacion.
* * * */
void encrypt_trigger(GtkButton *button, gpointer user_data);

/* @brief Funcion que inicia la rutina de desencriptacion de un archivo
* en caso de que el usuario presione el boton "confirmar operacion"
* del apartado Desencriptacion.
* * * */
void decrypt_trigger(GtkButton *button, gpointer user_data);