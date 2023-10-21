#include <gtk/gtk.h>

int main(int argc, char *argv[]) {
    GtkBuilder *builder;
    GtkWidget *window;
    
    /* Iniciar GTK */
    gtk_init(&argc, &argv);
    builder = gtk_builder_new();
    
    /* Obtener la ventana del archivo XML */
    gtk_builder_add_from_file(builder, "./models/notebook2.glade", NULL);
    window = GTK_WIDGET(gtk_builder_get_object(builder, "window"));
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}

