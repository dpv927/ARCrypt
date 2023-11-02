#pragma once
#include <gtk/gtk.h>

void init_gui(int argc, char* argv[]);

void encrypt_trigger(GtkButton *button, gpointer user_data);

void decrypt_trigger(GtkButton *button, gpointer user_data);
