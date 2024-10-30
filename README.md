# Proyecto Final Progamación de Sistemas
Programa de encriptación y desencriptación de archivos usando los algoritmos AES o BLOWFISH y claves con 128, 192 o 256 bits.

## Instrucciones
El proyecyo consiste en crear un programa en C que encripta o desencripta un archivo usando el algoritmo de encriptación [AES](https://es.wikipedia.org/wiki/Advanced_Encryption_Standard) o [BLOWFISH](https://en.wikipedia.org/wiki/Blowfish_(cipher)) . El programa usa la implementación del algoritmo AES y BLOWFISH en [crypto-algorithms](https://github.com/B-Con/crypto-algorithms). El programa tiene el siguiente comportamiento:

```
$ ./encrypter -h
encrypter encripta o desencripta un archivo usando los algoritmos AES o BLOWFISH.
uso:
 ./encrypter [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>
 ./encrypter -h
Opciones:
 -h			Ayuda, muestra este mensaje
 -d			Desencripta el archivo en lugar de encriptarlo.
 -k <passphrase>	Especifica la frase de encriptación.
 -a <algo>		Especifica el algoritmo de encriptación, opciones: aes, blowfish. [default: aes]
 -b <bits>		Especifica los bits de encriptación, opciones: 128, 192, 256. [default: 128]
```

El argumento *<nombre_archivo>* es obligatorio y especifica el nombre del archivo a encriptar/desencriptar. La opción *-d* es opcional y especifica que el archivo debe ser desencriptado, por defecto el archivo es encriptado. La opción *-k* es obligatoria y especifica la clave o key de encriptación/desencriptación. La opción *-a* es opcional con un argumento <algo> obligatorio que representa el algoritmo a utilizar, siendo AES o BLOWFISH, por defecto es AES. La opción *-b* con argumento obligatorio <bits> representa los bits de encriptación: 128 (16 bytes),192 (24 bytes) y 256 (32 bytes) bits; por defecto se utilizan 128 bits. La clave ingresada puede ser cualquier cadena de caracteres.

## Ejemplos de uso
Si deseamos encriptar el archivo Makefile con la clave de encriptación "hola" :
```
./encrypter -k hola Makefile
Leyendo el archivo Makefile (617 bytes)...
Archivo Makefile encriptado exitosamente en Makefile.enc...
```
El programa debe crear un nuevo archivo encriptado con el nombre del archivo original y la extensión *.enc*.

Si deseamos desencriptar un archivo ya encriptado, por ejemplo *imagen.png.tar.gz.enc*, el cual fue encriptado con la clave "progsys2024" :
```
$ ./encrypter -d -k progsys2024 imagen.png.tar.gz.enc
Leyendo el archivo imagen.png.tar.gz.enc (37680 bytes)...
Archivo imagen.png.tar.gz.enc desencriptado exitosamente en imagen.png.tar.gz
```
El programa debe crear un nuevo archivo desencriptado con el nombre del archivo original.
Con las macros, podemos obtener el algoritmo y el tamaño de bits para poder desencriptarHex a su valor binario byte por byte. Una forma es, en un arreglo de 16 bytes:
```C
BYTE key_arg_binario[16];
```
usar el siguiente lazo para recorrer dos caracteres por dos caracteres la clave en texto Hex *key_arg_str* y almacenar el valor de cada byte en *key_arg*:
```C
//Convertir clave en representación hex a binario...
BYTE byte, i;
for(i=0;i<16;i++){
    sscanf(key_arg_str + 2*i,"%2hhx", &byte);
    key_arg_binario[i] = byte;
}
```

El segundo reto es crear un archivo de salida nuevo con el nombre del archivo de entrada concatenando *.dec* o *.enc* al final del nombre. Usar *calloc, strcpy, strcat* para el nuevo nombre y la función *open* con las banderas *O_CREAT* y *O_TRUNC* para crear el archivo. Es importante asegurarse que el archivo nuevo tenga permisos de lectura y escritura para el usuario dueño (usar por ejemplo *S_IRUSR* y *S_IWUSR* en *open*).

El tercer reto fue manejar los diferentes *key_setup* de los algoritmos AES y BLOWFISH, donde AES utiliza claves específicas de 128, 192 y 256 bits mientras BLOWFISH admite un rango de 32 bits a 448 bits.

El cuarto reto fue escribir o leer el header del archivo. La primera información a leer en el header es el tamaño del archivo original en bytes tipo long y una máscara de bits creada para saber el algoritmo y tamaño de bits que se usó al momento de encriptar:
```
#define AES 0x10
#define BLOWFISH 0x20
#define KEY_128 0x01
#define KEY_192 0x02
#define KEY_256 0x04
```
Con las macros, podemos obtener el algoritmo y el tamaño de bits para poder desencriptar correctamente el archivo en un solo byte.
