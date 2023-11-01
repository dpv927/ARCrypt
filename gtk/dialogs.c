#include <gtk/gtk.h>
#include <stdio.h>
#include "widgets.h"

/* Respuesta de los dialogos */
static int confirm_dialog_response = -1;

int get_confirm_dialog_response(void) {
	return confirm_dialog_response;
}

/* ######################
*  #      Dialogo de    #
*  #     Confirmacion   #
*  ###################### */

void on_continue_button_clicked(GtkButton *button, gpointer user_data) {
    confirm_dialog_response = GTK_RESPONSE_ACCEPT;
    gtk_widget_destroy(GTK_WIDGET(user_data));
    gtk_main_quit();
}

void on_cancel_button_clicked(GtkButton *button, gpointer user_data) {
    confirm_dialog_response = GTK_RESPONSE_CANCEL;
    gtk_widget_destroy(GTK_WIDGET(user_data));
    gtk_main_quit();
}

void on_confirm_delete_event(GtkWidget *widget, GdkEvent *event, 
	gpointer user_data) {
	confirm_dialog_response = GTK_RESPONSE_CANCEL;
    gtk_main_quit();
    #ifdef MODULE_DEBUG
    printf("El usuario ha cancelado la operacion.\n");
    #endif
}

void create_confirmation_dialog(void) {    
	GtkBuilder* builder;
    GtkWidget* window;
    GtkWidget* ok_button;
    GtkWidget* cancel_button;
    confirm_dialog_response = -1;
    
    /* Ventana ,main */
    builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, win_paths[CONFIRM_WIN], NULL);
    window = GTK_WIDGET(gtk_builder_get_object(builder, WIDGET_NAME));
	
	if(window == NULL) {
		confirm_dialog_response = -1;
		return;
	}
	
	// Si el usuario cierra la ventana -> la respuesta es cancelar
	g_signal_connect(window, "delete-event", G_CALLBACK(
		on_confirm_delete_event), NULL);
	
	// Obtener los botones
	ok_button = GTK_WIDGET(gtk_builder_get_object(builder, "button1"));
    cancel_button = GTK_WIDGET(gtk_builder_get_object(builder, "button0"));
    
    if(ok_button == NULL || cancel_button == NULL) {
		confirm_dialog_response = -1;
		return;
	}
	
	// Asignar funciones a ejecutar al hacer click en los botones
	g_signal_connect(ok_button, "clicked", G_CALLBACK(on_continue_button_clicked), window);
    g_signal_connect(cancel_button, "clicked", G_CALLBACK(on_cancel_button_clicked), window);

    g_object_unref(builder);   
	gtk_widget_show_all(window);
	gtk_main();
}
