#pragma once

/* @brief Obtiene la respuesta del usuario al cuadro de dialogo
 * de confirmar/cancelar operacion.
 * 
 * @returns Devuelve -1 si ha habido un error o no se ha elegido
 * ninguna de las opciones del dialogo. En otro caso, el valor 
 * podra ser GTK_RESPONSE_ACCEPT o GTK_RESPONSE_CANCEL dependiendo
 * de la respuesta del usuario. 
 * * * */
int get_confirm_dialog_response(void);

/* @brief Crea una ventana de dialogo que pide al usuario cancelar o
 * confirmar la operacion que ha seleccionado. La ventana tiene los
 * siguientes elementos: 
 * 
 * - Boton para cancelar operacion.
 * - Boton para confirmar operacion. 
 * 
 * Si el usuario cierra la ventana, se entiende que la operacion se 
 * cancela (mismo resultado que pulsar el boton cancelar). La respuesta
 * del usuario se puede obtener con 'get_confirm_dialog_response()'.
 * * * */
void create_confirmation_dialog(void);

/* @brief Crea una ventana que notifica que se ha producido un error
 * en el programa. No contiene mas elementos que un label.
 * * * */
void create_error_dialog(void);

/* Obtiene un puntero a la instancia actual de un cuadro de dialogo
 * de progreso en caso de que exista. 
 * 
 * @returns Devuelve nulo si no existe ninguna instancia. */
GtkWidget* get_progress_dialog_instance();

/* @brief Crea una ventana de dialogo que indica al usuario que debe
 * esperar a que una operacion se termine. La ventana no se puede cerrar
 * por parte del usuario. La ventana solo se cerrara cuando la operacion
 * finalice por parte del programa. 
 * 
 * @return Devuelve la instancia de la ventana para que pueda ser cerrada
 * externamente tras hacer las operaciones convenientes.
 * * * */
void create_progress_dialog(void);

void create_end_dialog(void);
