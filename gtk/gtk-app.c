#include <gtk/gtk.h>
#include <stdio.h>
#include "main_window.h"

void enc_fn(GtkButton *button, gpointer user_data) { 
	printf("Esta funcion podria encriptar.\n");
	char* enc_path = get_enc_selected_file(); 
	if(enc_path) printf("La ruta seria: %s\n", enc_path);
}

void dec_fn(GtkButton *button, gpointer user_data) { 
	printf("\nEsta funcion podria desencriptar.\n");
	char* dec_path = get_dec_selected_file(); 
	char* key_path = get_dec_selected_key();
	
	if(dec_path) printf("La ruta seria: %s\n", dec_path);
	if(key_path) printf("La clave seria: %s\n", key_path);
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
