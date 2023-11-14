#pragma once

/* Imprimir un mensaje de informacion */
#define p_info(message) printf("\033[1;32mInfo:\033[0m %s\n", message);

/* Imprimir un mensaje de informacion doble */
#define p_infoString(message, string) printf("\033[1;32mInfo:\033[0m %s %s\n", message, string);

/* Imprimir un mensaje de error */
#define p_error(message) printf("\033[1;31mError:\033[0m %s\n", message);

/* Imprimir un mensaje de error doble */
#define p_error(message) printf("\033[1;31mError:\033[0m %s\n", message);

#define next_line() printf("\n");

/* Obtener un input del usuario */
#define user_input(about, format, var)\
  printf("\033[0;31m[\033[0;33m%s\033[0;31m]->\033[0m ", about);\
  scanf(format, var);
  
/* Imprimir el titulo de una seccion */
#define print_title(text) printf("\033[0;31m[%s\033[0;31m]\n", text);

/* Imprimir una opcion de un menu */
#define print_option(index, text) printf("\033[0;31m[\033[0;33m%d\033[0;31m]\033[0m %s\n", index, text);
