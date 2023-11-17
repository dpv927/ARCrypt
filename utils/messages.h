#pragma once

#define p_info(message)\
  printf("\033[1;32mInfo:\033[0m %s\n", message);

#define p_infoString(message, string)\
    printf("\033[1;32mInfo:\033[0m %s %s\n", message, string);

#define p_error(message)\
  printf("\033[1;31mError:\033[0m %s\n", message);