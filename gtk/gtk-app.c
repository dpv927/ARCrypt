
#include <gtk/gtk.h>

// Esta estructura se utiliza para pasar datos a la función file_chooser_dialog
typedef struct {
    GtkEntry *entry;
} FileChooserData;

void activate(GtkApplication *app, gpointer user_data);

// Función para abrir un cuadro de diálogo y seleccionar un archivo
static void file_chooser_dialog(GtkWidget *widget, gpointer data) {
    FileChooserData *file_data = (FileChooserData *)data;
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;

    dialog = gtk_file_chooser_dialog_new("Seleccionar un archivo",
                                         GTK_WINDOW(gtk_widget_get_toplevel(GTK_WIDGET(widget))),
                                         action,
                                         "_Cancelar", GTK_RESPONSE_CANCEL,
                                         "_Abrir", GTK_RESPONSE_ACCEPT,
                                         NULL);

    res = gtk_dialog_run(GTK_DIALOG(dialog));
    if (res == GTK_RESPONSE_ACCEPT) {
        char *filename;
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        filename = gtk_file_chooser_get_filename(chooser);
        g_print("Archivo seleccionado: %s\n", filename);

        // Coloca la ruta del archivo en el campo de texto
        gtk_entry_set_text(file_data->entry, filename);

        g_free(filename);
    }

    gtk_widget_destroy(dialog);
}

static void create_tab(GtkNotebook *notebook, const char *label_text) {
    GtkWidget *tab_label = gtk_label_new(label_text);
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkEntry *entry1 = GTK_ENTRY(gtk_entry_new());
    GtkEntry *entry2 = GTK_ENTRY(gtk_entry_new());
    GtkWidget *label1 = gtk_label_new("Archivo de entrada:");
    GtkWidget *label2 = gtk_label_new("Archivo de salida:");
    GtkWidget *button1 = gtk_button_new_with_label("Seleccionar");
    GtkWidget *button2 = gtk_button_new_with_label("Seleccionar");
    GtkWidget *confirm_button = gtk_button_new_with_label("Confirmar y Salir");

    GtkWidget *hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_container_add(GTK_CONTAINER(hbox1), entry1);
    gtk_container_add(GTK_CONTAINER(hbox1), button1);

    GtkWidget *hbox2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_container_add(GTK_CONTAINER(hbox2), entry2);
    gtk_container_add(GTK_CONTAINER(hbox2), button2);

    gtk_box_pack_start(GTK_BOX(vbox), label1, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox1, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label2, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox2, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), confirm_button, FALSE, FALSE, 0);

    // Conecta los botones a la función de selección de archivo
    FileChooserData data1 = {entry1};
    g_signal_connect(G_OBJECT(button1), "clicked", G_CALLBACK(file_chooser_dialog), &data1);

    FileChooserData data2 = {entry2};
    g_signal_connect(G_OBJECT(button2), "clicked", G_CALLBACK(file_chooser_dialog), &data2);

    // Conecta el botón de confirmación para cerrar la aplicación
    g_signal_connect(G_OBJECT(confirm_button), "clicked", G_CALLBACK(gtk_main_quit), NULL);

    gtk_notebook_append_page(notebook, vbox, tab_label);
}

int main(int argc, char **argv) {
    GtkApplication *app;
    GtkWidget *window;
    GtkWidget *notebook;

    app = gtk_application_new("com.example.filechooser", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);

    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}

void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window;
    GtkWidget *notebook;

    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Encriptación y Desencriptación");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);

    notebook = gtk_notebook_new();

    create_tab(GTK_NOTEBOOK(notebook), "Encriptación");
    create_tab(GTK_NOTEBOOK(notebook), "Desencriptación");

    gtk_container_add(GTK_CONTAINER(window), notebook);

    gtk_widget_show_all(window);
}
