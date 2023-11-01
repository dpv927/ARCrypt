#include <gtk/gtk.h>
#include <stdio.h>
#include <unistd.h>
#include "gui.h"
#include "dialogs.h"
#include "widgets.h"

void enc_fn(GtkButton *button, gpointer user_data) { 
	printf("Esta funcion podria encriptar.\n");
	char* enc_path = get_enc_selected_file(); 
	if(enc_path) printf("La ruta seria: %s\n", enc_path);
	
	create_confirmation_dialog();
	int response = get_confirm_dialog_response();
	printf("response: %d\n", response);
	
	create_end_dialog();
	
	printf("hello");
}

void dec_fn(GtkButton *button, gpointer user_data) { 
	printf("\nEsta funcion podria desencriptar.\n");
	char* dec_path = get_dec_selected_file(); 
	char* key_path = get_dec_selected_key();
	
	if(dec_path) printf("La ruta seria: %s\n", dec_path);
	if(key_path) printf("La clave seria: %s\n", key_path);
	
	create_confirmation_dialog();
	int response = get_confirm_dialog_response();
	printf("response: %d\n", response);
}

int main(int argc, char *argv[]) {	
	GtkWidget *window;
	gtk_init(&argc, &argv);
	
	window = create_main_window(enc_fn, dec_fn);
	gtk_widget_show(window);
	
    gtk_main();
    free_paths();
    return 0;
}
