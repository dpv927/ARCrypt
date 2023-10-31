#include <gtk/gtk.h>
#include <stdio.h>
#include "main_window.h"

void but_fn(GtkButton *button, gpointer user_data) { 
	printf("Pressed\n");
}

int main(int argc, char *argv[]) {
	GtkWidget *window;
	gtk_init(&argc, &argv);
   
	window = create_main_window(but_fn, but_fn);

	gtk_widget_show(window);
    gtk_main();
    free_paths();
    return 0;
}
