#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include "aes.h"
#include "sha256.h"
#include "blowfish.h"

#define AES 0x10
#define BLOWFISH 0x20
#define KEY_128 0x01
#define KEY_192 0x02
#define KEY_256 0x04

void toSHA256(BYTE *buf, char *str);
void writeHeader(int fd_write, struct stat *mi_stat, BYTE *bitmask);
void readHeader(int fd_read, long int *originalSize, BYTE *bitmask);
bool decodeBitmask(BYTE bitmask, char **algorithm, int *keybits);

bool dflag = false; // bandera encriptación/desencriptación

void print_help(char *command)
{
	printf("encrypter encripta o desincripta un archivo usando el algoritmo AES o BLOWFISH.\n");
	printf("uso:\n %s [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>\n", command);
	printf(" %s -h\n", command);
	printf("Opciones:\n");
	printf(" -h\t\t\tAyuda, muestra este mensaje\n");
	printf(" -d\t\t\tDesincripta el archivo en lugar de encriptarlo.\n");
	printf(" -k <key>\t\tEspecifica la frase de encriptación.\n");
	printf(" -a <algo>\t\tEspecifica el algoritmo de encriptación, opciones: aes, blowfish. [default: aes]\n");
	printf(" -b <bits>\t\tEspecifica los bits de encriptación, opciones: 128, 192, 256. [default: 128]\n");
}

int main(int argc, char **argv)
{
	struct stat mi_stat;
	char *input_file = NULL;
	char *key_arg_str = NULL;
	char *algo = "aes";
	char *bitsChar = NULL;
	int bits = 128;

	int opt, index;

	while ((opt = getopt(argc, argv, "dhk:a:b:")) != -1)
	{
		switch (opt)
		{
		case 'd':
			dflag = true;

			break;
		case 'h':
			print_help(argv[0]);
			return 0;
		case 'k':
			key_arg_str = optarg;
			break;
		case 'a':
			algo = optarg;
			break;
		case 'b':
			bitsChar = optarg;
			break;
		case '?':
		default:
			fprintf(stderr, "uso:\n %s [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>\n", argv[0]);
			fprintf(stderr, "     %s -h\n", argv[0]);
			return 1;
		}
	}

	// handling non valid number for bits
	if (bitsChar)
	{
		bits = atoi(bitsChar);
		if (bits == 0)
		{
			fprintf(stderr, "Invalid bit size.\n");
			return 1;
		}
	}

	/* Aquí recoge argumentos que no son opción, por ejemplo el nombre del input file */
	for (index = optind; index < argc; index++)
		input_file = argv[index];

	if (!input_file)
	{
		fprintf(stderr, "Especifique el nombre del archivo.\n");
		fprintf(stderr, "uso:\n %s [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>\n", argv[0]);
		fprintf(stderr, "     %s -h\n", argv[0]);
		return 1;
	}
	else
	{
		/* Ejemplo como verificar existencia y tamaño de un archivo */
		if (stat(input_file, &mi_stat) < 0)
		{
			fprintf(stderr, "Archivo %s no existe!\n", input_file);
			return 1;
		}
		else if(dflag){
			char *extension = &input_file[strlen(input_file) - 4];
			if(strcmp(extension, ".enc") != 0){
				fprintf(stderr, "Nombre de archivo no valido: archivo sin extensión .enc\n");
				return 1;
			}
		}
		else
			printf("Leyendo el archivo %s (%ld bytes)...\n", input_file, mi_stat.st_size);
	}

	// Arreglo bytes clave de encriptación/desencriptación
	BYTE *key_arg_binario;
	WORD *key_schedule;
	BLOWFISH_KEY key_blowfish;

	// Buffer de encriptación/desencriptación
	BYTE aes_buffer[AES_BLOCK_SIZE];
	BYTE blowfish_buffer[BLOWFISH_BLOCK_SIZE];

	// Declaracion del bitmask
	BYTE bitmask = 0;

	// Abrir archivo solo lectura
	int fd_read = open(input_file, O_RDONLY, 0);

	long int originalSize;

	if (dflag) //si se va a desencriptar, se obtiene la información sobre cómo fue encriptado en el header
	{
		readHeader(fd_read, &originalSize, &bitmask);
		if(!decodeBitmask(bitmask, &algo, &bits)){
			fprintf(stderr, "No se pudo determinar las propiedades del archivo (cabecera inválida).\n");
			return 1;
		}
	}
	else //si se va a encriptar, se prepara el tamaño especificado de la clave en la bitmask
	{
		if (bits == 128)
		{
			bitmask |= KEY_128;
		}
		else if (bits == 192)
		{
			bitmask |= KEY_192;
		}
		else if (bits == 256)
		{
			bitmask |= KEY_256;
		}
		else
		{
			fprintf(stderr, "Número de bits de encriptación no soportado: %d\n Usar: 128, 192 o 256\n", bits);
			return 1;
		}
	}

	int bytesNmbr = bits / 8;

	if (key_arg_str) // conversión de la cadena de caracteres a clave con longitud de bits adecuada
	{
		key_arg_binario = (BYTE *)malloc(bytesNmbr * sizeof(BYTE));
		BYTE buf[SHA256_BLOCK_SIZE];
		toSHA256(buf, key_arg_str);
		for (int i = 0; i < bytesNmbr; i++)
		{
			key_arg_binario[i] = buf[i];
		}
	}
	else
	{
		fprintf(stderr, "Error al especificar la clave de encriptación.\n");
		fprintf(stderr, "uso:\n %s [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>\n", argv[0]);
		fprintf(stderr, "     %s -h\n", argv[0]);
		return 1;
	}

	if (strcmp(algo, "aes") == 0)
	{
		// Buffer de encriptación/desencriptación
		bitmask |= AES;
		if (bits == 128) // Se pide el espacio necesario para el keySchedule respectivo a cada tamaño de clave
		{
			key_schedule = (WORD *)malloc(44 * sizeof(WORD));
		}
		else if (bits == 192)
		{
			key_schedule = (WORD *)malloc(52 * sizeof(WORD));
		}
		else if (bits == 256)
		{
			key_schedule = (WORD *)malloc(60 * sizeof(WORD));
		}
		aes_key_setup(key_arg_binario, key_schedule, bits);
	}
	else if (strcmp(algo, "blowfish") == 0)
	{
		bitmask |= BLOWFISH;
		blowfish_key_setup(key_arg_binario, &key_blowfish, bytesNmbr);
	}
	else
	{
		fprintf(stderr, "Algoritmo de encriptación no soportado: %s\n Algoritmos soportados: AES, Blowfish\n", algo);
		return 1;
	}

	int ALGO_BLOCK_SIZE = (strcmp(algo, "aes") == 0) ? AES_BLOCK_SIZE : BLOWFISH_BLOCK_SIZE; 
	BYTE read_buffer[ALGO_BLOCK_SIZE];

	// Crear nombre archivo de salida
	char *output_file = (char *)calloc(strlen(input_file) + 5, 1);
	strcpy(output_file, input_file);

	if (dflag) // si se está desencriptando, se trunca la extensión .enc
	{
		output_file[strlen(output_file) - 4] = 0;
	}
	else
	{
		strcat(output_file, ".enc");
	}

	// Crear/truncar archivo de salida con permisos de escritura y lectura para el dueño
	int fd_write = open(output_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);

	if (!dflag) //El header con la información de encriptación es lo primero en ser escrito
	{
		writeHeader(fd_write, &mi_stat, &bitmask);
	}

	// Leer el archivo de lectura
	if (strcmp(algo, "aes") == 0)
	{
		printf("Usando AES con clave de %d bits...\n", bits);
		while (read(fd_read, read_buffer, AES_BLOCK_SIZE) > 0)
		{
			if (dflag)
				aes_decrypt(read_buffer, aes_buffer, key_schedule, bits);
			else
			{
				aes_encrypt(read_buffer, aes_buffer, key_schedule, bits);
			}

			write(fd_write, aes_buffer, AES_BLOCK_SIZE);
			memset(read_buffer, 0, sizeof(read_buffer));
		}
		free(key_schedule);
	}
	else if (strcmp(algo, "blowfish") == 0)
	{
		printf("Usando BLOWFISH con clave de %d bits...\n", bits);
		while (read(fd_read, read_buffer, BLOWFISH_BLOCK_SIZE) > 0)
		{
			if (dflag)
				blowfish_decrypt(read_buffer, blowfish_buffer, &key_blowfish);
			else
				blowfish_encrypt(read_buffer, blowfish_buffer, &key_blowfish);

			write(fd_write, blowfish_buffer, BLOWFISH_BLOCK_SIZE);
			memset(read_buffer, 0, sizeof read_buffer);
		}
	}

	if (dflag) // Al desencriptar, se truncan los bytes de padding añadidos por la encriptación
	{
		ftruncate(fd_write, originalSize);
		printf("Archivo %s desencriptado exitosamente en %s...\n", input_file, output_file);
	}
	else
	{
		printf("Archivo %s encriptado exitosamente en %s...\n", input_file, output_file);
	}

	// Se libera la memoria utilizada
	free(key_arg_binario);
	free(output_file);
	close(fd_read);
	close(fd_write);

	return 0;
}

void toSHA256(BYTE *buf, char *str)
{
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (unsigned char *)str, strlen(str));
	sha256_final(&ctx, buf);
}

void writeHeader(int fd_write, struct stat *mi_stat, BYTE *bitmask)
{
	write(fd_write, &mi_stat->st_size, sizeof(long int));
	write(fd_write, bitmask, sizeof(BYTE));
}

void readHeader(int fd_read, long int *originalSize, BYTE *bitmask)
{
	read(fd_read, originalSize, sizeof(long int));
	read(fd_read, bitmask, sizeof(BYTE));
}

bool decodeBitmask(BYTE bitmask, char **algorithm, int *keybits)
{
	if (bitmask & AES)
	{
		*algorithm = "aes";
	}
	else if (bitmask & BLOWFISH)
	{
		*algorithm = "blowfish";
	}
	else{
		return false;
	}

	if (bitmask & KEY_128)
	{
		*keybits = 128;
	}
	else if (bitmask & KEY_192)
	{
		*keybits = 192;
	}
	else if (bitmask & KEY_256)
	{
		*keybits = 256;
	}
	else{
		return false;
	}

	return true;
}
