#include <gtk/gtk.h>
#include <stdio.h>
#include "gui_mode.h"
#include "gtk/gui.h"
#include "gtk/dialogs.h"
#include "openSSL/encryption.h"
#include "openSSL/decryption.h"

void init_gui(int argc, char* argv[]) {
  GtkWidget *window;
	gtk_init(NULL, NULL);
	
	window = create_main_window(encrypt_trigger, decrypt_trigger);
	gtk_widget_show(window);
	
  gtk_main();
  free_paths();
}
 
/* Funcion a ejecutar para encriptar */
void encrypt_trigger(GtkButton *button, gpointer user_data) { 
 
	char* enc_path = get_enc_selected_file(); 
	if(!enc_path) return;
	
	create_confirmation_dialog();
	int response = get_confirm_dialog_response();
	
  	if(response == GTK_RESPONSE_CANCEL)
    	return;
  
	encryptFile_withAES(enc_path);
}

/* Funcion a ejecutar para desencriptar */
void decrypt_trigger(GtkButton *button, gpointer user_data) { 

  char* dec_path = get_dec_selected_file(); 
	char* key_path = get_dec_selected_key();
	if(!dec_path || !key_path) return;
	
	create_confirmation_dialog();
	int response = get_confirm_dialog_response();
	
  	if(response == GTK_RESPONSE_CANCEL)
    	return;
  
	decryptFile_withAES(dec_path, key_path);
}