#include <gtk/gtk.h>
#include <stdio.h>
#include "widgets.h"

/* ######################
*  #      Dialogo de    #
*  #     Confirmacion   #
*  ###################### */

static int CONFIRM_DIALOG_RESPONSE = -1;

int get_confirm_dialog_response(void) {
	return CONFIRM_DIALOG_RESPONSE;
}

void on_continue_button_clicked(GtkButton *button, gpointer user_data) {
	#ifdef MODULE_DEBUG
	printf("El usuario ha pulsado continuar\n");
	#endif
    CONFIRM_DIALOG_RESPONSE = GTK_RESPONSE_ACCEPT;
    gtk_widget_destroy(GTK_WIDGET(user_data));
    gtk_main_quit();
}

void on_cancel_button_clicked(GtkButton *button, gpointer user_data) {
    CONFIRM_DIALOG_RESPONSE = GTK_RESPONSE_CANCEL;
    #ifdef MODULE_DEBUG
	printf("El usuario ha pulsado cancelar\n");
	#endif
    gtk_widget_destroy(GTK_WIDGET(user_data));
    gtk_main_quit();
}

void on_confirm_delete_event(GtkWidget *widget, GdkEvent *event, 
	gpointer user_data) {
	#ifdef MODULE_DEBUG
    printf("El usuario ha cerrado la ventana (Cancela la operacion).\n");
    #endif
	CONFIRM_DIALOG_RESPONSE = GTK_RESPONSE_CANCEL;
    gtk_main_quit();
}

void create_confirmation_dialog(void) {    
	GtkBuilder* builder;
    GtkWidget* window;
    GtkWidget* ok_button;
    GtkWidget* cancel_button;
    CONFIRM_DIALOG_RESPONSE = -1;
    
    /* Ventana ,main */
    builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, win_paths[CONFIRM_WIN], NULL);
    window = GTK_WIDGET(gtk_builder_get_object(builder, WIDGET_NAME));
	
	if(window == NULL)
		return;
	
	// Si el usuario cierra la ventana -> la respuesta es cancelar
	g_signal_connect(window, "delete-event", G_CALLBACK(
		on_confirm_delete_event), NULL);
	
	// Obtener los botones
	ok_button = GTK_WIDGET(gtk_builder_get_object(builder, "button1"));
    cancel_button = GTK_WIDGET(gtk_builder_get_object(builder, "button0"));
    
    if(ok_button == NULL || cancel_button == NULL)
		return;
	
	// Asignar funciones a ejecutar al hacer click en los botones
	g_signal_connect(ok_button, "clicked", G_CALLBACK(
		on_continue_button_clicked), window);
    g_signal_connect(cancel_button, "clicked", G_CALLBACK(
		on_cancel_button_clicked), window);

    g_object_unref(builder);   
	gtk_widget_show_all(window);
	gtk_main();
}


/* ######################
*  #      Dialogo de    #
*  #     	Error       #
*  ###################### */

void on_finish_button_clicked(GtkButton *button, gpointer user_data) {
    gtk_widget_destroy(GTK_WIDGET(user_data));
    gtk_main_quit();
}

void on_error_delete_event(GtkWidget *widget, GdkEvent *event, 
	gpointer user_data) {
	gtk_widget_destroy(GTK_WIDGET(user_data));
    gtk_main_quit();
}

void create_error_dialog(void) {    
	GtkBuilder* builder;
    GtkWidget* window;
    GtkWidget* button;
    
    /* Ventana ,main */
    builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, win_paths[ERROR_WIN], NULL);
    window = GTK_WIDGET(gtk_builder_get_object(builder, WIDGET_NAME));
	
	if(window == NULL)
		return;
	
	// Si el usuario cierra la ventana
	g_signal_connect(window, "delete-event", G_CALLBACK(
		on_error_delete_event), window);
	
	// Obtener el boton
	button = GTK_WIDGET(gtk_builder_get_object(builder, "button"));
    
    if(button == NULL)
		return;
	
	// Asignar funciones a ejecutar al hacer click en los botones
	g_signal_connect(button, "clicked", G_CALLBACK(
		on_finish_button_clicked), window);

    g_object_unref(builder);   
	gtk_widget_show_all(window);
	gtk_main();
}


/* ######################
*  #      Dialogo de    #
*  #     Finalizacion   #
*  ###################### */

void create_end_dialog(void) {
	GtkBuilder* builder;
    GtkWidget* window;
    GtkWidget* button;
    
    /* Ventana ,main */
    builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, win_paths[FINISH_WIN], NULL);
    window = GTK_WIDGET(gtk_builder_get_object(builder, WIDGET_NAME));
	
	if(window == NULL)
		return;
	
	// Si el usuario cierra la ventana
	g_signal_connect(window, "delete-event", G_CALLBACK(
		on_error_delete_event), window);
	
	// Obtener el boton
	button = GTK_WIDGET(gtk_builder_get_object(builder, "button"));
    
    if(button == NULL)
		return;
	
	// Asignar funciones a ejecutar al hacer click en los botones
	g_signal_connect(button, "clicked", G_CALLBACK(
		on_finish_button_clicked), window);

    g_object_unref(builder);   
	gtk_widget_show_all(window);
	gtk_main();
}
