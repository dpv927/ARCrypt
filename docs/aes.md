## AES

## Introduccion

AES es un encriptador de bloques de 128 bits independientemente del tamano de la clave. Usa claves de 128, 192 o 256 bits. La salida de la encriptacion
sera tambien un bloque de 128 bits.

<div align="center">
  <img src="https://github.com/dpv927/kayberc/assets/113710742/4bd1fa96-a681-45da-a293-c3117cd3c85c">
</div>
<br>

Representación de un bloque de 128 bits (Entiéndase Bn como el Byte número N del bloque):

| B0 | B1 | B2 | B3 | B4 | B5 | B9 | B10 | B11 | B12 | B13 | B14 | B15 |  
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |  

Para AES, los bloques de 128 bits se representarán como una matriz 4x4 de la siguiente forma:

| | | | |
| --- | --- | --- | --- |
| B0 | B4 | B8 | B12 |
| B1 | B5 | B9 | B13 |
| B2 | B6 | B10 | B14 |
| B3 | B7 | B11 | B15 |

## Operaciones (Capas)

1) ByteSubstitution
2) Shiftrows
3) MixColumns
4) Key Addition

ByteSubstitution provee confusion, mientras que Shiftrows y MixColumns proveen difusion, lo que en conjunto genera una mayor seguiridad a la hora
de encriptar un bloque.

> [!NOTE]
> En la ultima ronda, la capa MixColumns no se realiza, ya que esta comprobado que no surte efecto en el resultado final.

Las capas 1,2,3,4 en conjunto se consideran una roda. Diferentes tamanos de clave necesitan numeros de rondas diferentes:
- Para clave de 128 bits: 10 rondas.
- Para clave de 192 bits: 12 rondas.
- Para clave de 256 bits: 14 rondas.

## Que pasa dentro de las rondas

![imagen](https://github.com/dpv927/kayberc/assets/113710742/db2415ba-e444-4f88-8ca2-9a19eb03a0f4)

### Byte Substitution

La operacion se describe como S(Ai) = Bi. Esto significa que cada bit del bloque se sustituye por su correspondiente de una tabla estatica llamada
'S-box'. Para saber en que posicion de la tabla se encuentra el elemento a sustituir, debemos dividir cada byte en dos digitos hexadecimales y 
buscar en la tabla la fila que indique el primer digito y la columna que indique el segundo.

Por ejemplo, para Ai = C2:
```
Ai = C2(hex) = (x,y) = (C,2) = (1100,0010)
Bi = S(Ai) = 25(hex) = (0010,0101) # Bi no tiene coorelacion con Ai!
```

La tabla S-box es la siguiente: 

<table>
<tbody><tr>
<th>
</th>
<th>00</th>
<th>01</th>
<th>02</th>
<th>03</th>
<th>04</th>
<th>05</th>
<th>06</th>
<th>07</th>
<th>08</th>
<th>09</th>
<th>0a</th>
<th>0b</th>
<th>0c</th>
<th>0d</th>
<th>0e</th>
<th>0f
</th></tr>
<tr>
<th>00
</th>
<td>63</td>
<td>7c</td>
<td>77</td>
<td>7b</td>
<td>f2</td>
<td>6b</td>
<td>6f</td>
<td>c5</td>
<td>30</td>
<td>01</td>
<td>67</td>
<td>2b</td>
<td>fe</td>
<td>d7</td>
<td>ab</td>
<td>76
</td></tr>
<tr>
<th>10
</th>
<td>ca</td>
<td>82</td>
<td>c9</td>
<td>7d</td>
<td>fa</td>
<td>59</td>
<td>47</td>
<td>f0</td>
<td>ad</td>
<td>d4</td>
<td>a2</td>
<td>af</td>
<td>9c</td>
<td>a4</td>
<td>72</td>
<td>c0
</td></tr>
<tr>
<th>20
</th>
<td>b7</td>
<td>fd</td>
<td>93</td>
<td>26</td>
<td>36</td>
<td>3f</td>
<td>f7</td>
<td>cc</td>
<td>34</td>
<td>a5</td>
<td>e5</td>
<td>f1</td>
<td>71</td>
<td>d8</td>
<td>31</td>
<td>15
</td></tr>
<tr>
<th>30
</th>
<td>04</td>
<td>c7</td>
<td>23</td>
<td>c3</td>
<td>18</td>
<td>96</td>
<td>05</td>
<td>9a</td>
<td>07</td>
<td>12</td>
<td>80</td>
<td>e2</td>
<td>eb</td>
<td>27</td>
<td>b2</td>
<td>75
</td></tr>
<tr>
<th>40
</th>
<td>09</td>
<td>83</td>
<td>2c</td>
<td>1a</td>
<td>1b</td>
<td>6e</td>
<td>5a</td>
<td>a0</td>
<td>52</td>
<td>3b</td>
<td>d6</td>
<td>b3</td>
<td>29</td>
<td>e3</td>
<td>2f</td>
<td>84
</td></tr>
<tr>
<th>50
</th>
<td>53</td>
<td>d1</td>
<td>00</td>
<td>ed</td>
<td>20</td>
<td>fc</td>
<td>b1</td>
<td>5b</td>
<td>6a</td>
<td>cb</td>
<td>be</td>
<td>39</td>
<td>4a</td>
<td>4c</td>
<td>58</td>
<td>cf
</td></tr>
<tr>
<th>60
</th>
<td>d0</td>
<td>ef</td>
<td>aa</td>
<td>fb</td>
<td>43</td>
<td>4d</td>
<td>33</td>
<td>85</td>
<td>45</td>
<td>f9</td>
<td>02</td>
<td>7f</td>
<td>50</td>
<td>3c</td>
<td>9f</td>
<td>a8
</td></tr>
<tr>
<th>70
</th>
<td>51</td>
<td>a3</td>
<td>40</td>
<td>8f</td>
<td>92</td>
<td>9d</td>
<td>38</td>
<td>f5</td>
<td>bc</td>
<td>b6</td>
<td>da</td>
<td>21</td>
<td>10</td>
<td>ff</td>
<td>f3</td>
<td>d2
</td></tr>
<tr>
<th>80
</th>
<td>cd</td>
<td>0c</td>
<td>13</td>
<td>ec</td>
<td>5f</td>
<td>97</td>
<td>44</td>
<td>17</td>
<td>c4</td>
<td>a7</td>
<td>7e</td>
<td>3d</td>
<td>64</td>
<td>5d</td>
<td>19</td>
<td>73
</td></tr>
<tr>
<th>90
</th>
<td>60</td>
<td>81</td>
<td>4f</td>
<td>dc</td>
<td>22</td>
<td>2a</td>
<td>90</td>
<td>88</td>
<td>46</td>
<td>ee</td>
<td>b8</td>
<td>14</td>
<td>de</td>
<td>5e</td>
<td>0b</td>
<td>db
</td></tr>
<tr>
<th>a0
</th>
<td>e0</td>
<td>32</td>
<td>3a</td>
<td>0a</td>
<td>49</td>
<td>06</td>
<td>24</td>
<td>5c</td>
<td>c2</td>
<td>d3</td>
<td>ac</td>
<td>62</td>
<td>91</td>
<td>95</td>
<td>e4</td>
<td>79
</td></tr>
<tr>
<th>b0
</th>
<td>e7</td>
<td>c8</td>
<td>37</td>
<td>6d</td>
<td>8d</td>
<td>d5</td>
<td>4e</td>
<td>a9</td>
<td>6c</td>
<td>56</td>
<td>f4</td>
<td>ea</td>
<td>65</td>
<td>7a</td>
<td>ae</td>
<td>08
</td></tr>
<tr>
<th>c0
</th>
<td>ba</td>
<td>78</td>
<td>25</td>
<td>2e</td>
<td>1c</td>
<td>a6</td>
<td>b4</td>
<td>c6</td>
<td>e8</td>
<td>dd</td>
<td>74</td>
<td>1f</td>
<td>4b</td>
<td>bd</td>
<td>8b</td>
<td>8a
</td></tr>
<tr>
<th>d0
</th>
<td>70</td>
<td>3e</td>
<td>b5</td>
<td>66</td>
<td>48</td>
<td>03</td>
<td>f6</td>
<td>0e</td>
<td>61</td>
<td>35</td>
<td>57</td>
<td>b9</td>
<td>86</td>
<td>c1</td>
<td>1d</td>
<td>9e
</td></tr>
<tr>
<th>e0
</th>
<td>e1</td>
<td>f8</td>
<td>98</td>
<td>11</td>
<td>69</td>
<td>d9</td>
<td>8e</td>
<td>94</td>
<td>9b</td>
<td>1e</td>
<td>87</td>
<td>e9</td>
<td>ce</td>
<td>55</td>
<td>28</td>
<td>df
</td></tr>
<tr>
<th>f0
</th>
<td>8c</td>
<td>a1</td>
<td>89</td>
<td>0d</td>
<td>bf</td>
<td>e6</td>
<td>42</td>
<td>68</td>
<td>41</td>
<td>99</td>
<td>2d</td>
<td>0f</td>
<td>b0</td>
<td>54</td>
<td>bb</td>
<td>16
</td></tr>
<tr>
</td></tr></tbody></table>

### Shiftrows

Esta capa lo unico que hace es desplazar los bytes de la matriz hacia la izquierda. La primera fila no se desplaza, la segunda se desplaza 1 byte,
la tercera 2, y la ultima 3. Por ejemplo para el siguiente bloque:

| | | | |
| --- | --- | --- | --- |
| B0 | B4 | B8 | B12 |
| B1 | B5 | B9 | B13 |
| B2 | B6 | B10 | B14 |
| B3 | B7 | B11 | B15 |

Tendremos el siguiente resultado:

| | | | |
| --- | --- | --- | --- |
| B0 | B4 | B8 | B12 |
| B5 | B9 | B13 | B1 |
| B10 | B14 | B2 | B6 |
| B15 | B3 | B7 | B11 |

### MixColumns

En este caso deberemos multiplicar cada columna de la matriz que representa un bloque por una matriz fija, siendo todas las operaciones en Z256.

![imagen](https://github.com/dpv927/kayberc/assets/113710742/66aec7d1-64d1-400c-bcb3-b85a446c67d1)

### Key Addition

En todas las rondas se genera una clave derivada de la clave de la ronda anterior, haciendo una operacion XOR entre la sub-clave y el bloque.
Para generar las subclaves, se inicia un proceso llamado 'Expansion de claves', el cual sigue el siguiente procedimiento:

![imagen](https://github.com/dpv927/kayberc/assets/113710742/1dc05598-67f1-4e53-b8db-8006ccc66752)

Se aplica la funcion g() a la palabra w4 que contiene los bytes (b12,b13,b14,b15) y el resultado se le aplica la operacion XOR con la palabbra 
w1 que contiene los bytes (b0,b1,b2,b3), generando la palabra w5. Para generar w6, se aplica XOR(w5,w2), para w7 se aplica XOR(w6,w3), y asi
sucesivamente.

#### La funcion g()

La funcion g toma como argumento una 32 bits, 4 bytes. Tiene tres pasos:
- Se aplica una rotacion de 1 byte. Ej: para una palabra (b0,b1,b2,b3), tendremos el resultado (b1,b2,b3,b4).
- Se aplica una substitucion de cada byte por su correspondiente en la tabla S-Box.
- Se aplica una operacion XOR con una constante almacenada en un array llamado Rcon[]. La palabra cambiara dependiendo de ronda.





