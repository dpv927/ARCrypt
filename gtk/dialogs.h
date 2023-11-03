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

/* @brief Crea una ventana que notifica que la operacion que se estaba 
* llevando a cabo ha finalizado con exito.
* * * */
void create_end_dialog(void);