#include <gtk/gtk.h>
#include <stdio.h>
#include "windows.h"

/* Files (paths) */
static char* enc_selected_file = NULL;
static char* dec_selected_file = NULL;
static char* dec_selected_key  = NULL;

/* Exec to get the file to encrypt */
char* get_enc_selected_file(void) {
	return enc_selected_file;
}

/* Exec to get the file to decrypt */
char* get_dec_selected_file(void) {
	return dec_selected_file;
}

/* Exec to get the AES key file */
char* get_dec_selected_key(void) {
	return dec_selected_key;
}

/* Free all the paths */
void free_paths(void) {
	if(enc_selected_file) g_free(enc_selected_file);
	if(dec_selected_file) g_free(dec_selected_file);
	if(dec_selected_key)  g_free(dec_selected_key);
}

/* Exec to get selected file to encrypt -> Chooser updated*/
void on_enc_file_selected(GtkFileChooserButton* chooser, gpointer p) {
	if(enc_selected_file) g_free(enc_selected_file);
	
	enc_selected_file = gtk_file_chooser_get_filename(
		GTK_FILE_CHOOSER(chooser));
	
	/* El boton de encriptado esta desactivado por defecto para que
	 * no se produzcan entradas nulas. Hay que activarlo. */
	GtkWidget *target_button = GTK_WIDGET(p);
	gtk_widget_set_sensitive(target_button, TRUE);
			
	#ifdef MODULE_DEBUG
	printf("Se ha seleccionado un nuevo archivo a ecriptar (%s)\n",
		enc_selected_file);
	#endif
}

/* Exec to get selected file to decrypt -> Chooser updated*/
void on_dec_file_selected(GtkFileChooserButton* chooser, gpointer p) {
	if(dec_selected_file) g_free(enc_selected_file);
	
	dec_selected_file = gtk_file_chooser_get_filename(
		GTK_FILE_CHOOSER(chooser));
		
	/* El boton de desencriptado esta desactivado por defecto para que
	 * no se produzcan entradas nulas. Hay que activarlo en caso de que
	 * el valor de la ruta de la clave AES no sea nulo. */
	if(dec_selected_key) {
		GtkWidget *target_button = GTK_WIDGET(p);
		gtk_widget_set_sensitive(target_button, TRUE);
	}
		
	#ifdef MODULE_DEBUG
	printf("Se ha seleccionado un nuevo archivo a desencriptar (%s)\n",
		enc_selected_file);
	#endif
}

/* Exec to get selected AES key file at decrypt -> Chooser updated*/
void on_dec_key_selected(GtkFileChooserButton* chooser, gpointer p) {
	if(dec_selected_key) g_free(enc_selected_file);
	
	dec_selected_key = gtk_file_chooser_get_filename(
		GTK_FILE_CHOOSER(chooser));
		
	/* El boton de desencriptado esta desactivado por defecto para que
	 * no se produzcan entradas nulas. Hay que activarlo en caso de que
	 * el valor de la ruta de la clave AES no sea nulo. */
	if(dec_selected_file) {
		GtkWidget *target_button = GTK_WIDGET(p);
		gtk_widget_set_sensitive(target_button, TRUE);
	}

	#ifdef MODULE_DEBUG
	printf("Se ha seleccionado una nueva clave AES (%s)\n",
		enc_selected_file);
	#endif
}

void on_window_delete_event(GtkWidget *widget, GdkEvent *event, 
	gpointer user_data) {
    gtk_main_quit();
    #ifdef MODULE_DEBUG
    printf("El programa ha finalizado con exito.\n");
    #endif
}

/* Exec to initialize main window propierties */
GtkWidget* create_main_window(void(*enc_func)(GtkButton* b, gpointer p),
	void(*dec_func)(GtkButton* b, gpointer p)) {
		
	GtkBuilder *builder;
    GtkWidget *window;
    GtkWidget *enc_button;
    GtkWidget *dec_button;
    GtkWidget *enc_file_selector;
    GtkWidget *dec_file_selector;
    GtkWidget *dec_key_selector;
    
    /* Ventana ,main */
    builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, win_paths[MAIN_WIN], NULL);
    window = GTK_WIDGET(gtk_builder_get_object(builder, WIDGET_NAME));
		
	if(window == NULL) 
		return NULL;
	
	// Si el usuario cierra la ventana -> el programa finaliza
	g_signal_connect(window, "delete-event", G_CALLBACK(
		on_window_delete_event), NULL);
			
	// Obtener los botones
	enc_button = GTK_WIDGET(gtk_builder_get_object(builder, "enc_button"));
    dec_button = GTK_WIDGET(gtk_builder_get_object(builder, "dec_button"));
    
    // Obtener los fileChooser
    enc_file_selector = GTK_WIDGET(gtk_builder_get_object(builder, "enc_selector"));
    dec_file_selector = GTK_WIDGET(gtk_builder_get_object(builder, "dec_selector0"));
    dec_key_selector = GTK_WIDGET(gtk_builder_get_object(builder, "enc_selector1"));    
	
	if(enc_button == NULL || dec_button == NULL || enc_file_selector == NULL || 
		dec_file_selector == NULL || dec_key_selector == NULL)
		return NULL;
	
	// Asignar funciones a ejecutar al hacer click en los botones
	g_signal_connect(enc_button, "clicked", G_CALLBACK(enc_func), NULL);
    g_signal_connect(dec_button, "clicked", G_CALLBACK(dec_func), NULL);
    
    // Asignar funciones a ejecutar al update de los fileChooser
    g_signal_connect(enc_file_selector, "file-set", G_CALLBACK(
		on_enc_file_selected), enc_button);
	g_signal_connect(dec_file_selector, "file-set", G_CALLBACK(
		on_dec_file_selected), dec_button);
	g_signal_connect(dec_key_selector, "file-set", G_CALLBACK(
		on_dec_key_selected), dec_button);
    
    g_object_unref(builder);
    return window;
}
