EXEC = encrypter
DEPS = sha256.h aes.h blowfish.h

# Target para compilar el ejecutable final
$(EXEC): main.o sha256.o aes.o blowfish.o $(DEPS)
	gcc -o $@ main.o sha256.o aes.o blowfish.o $(DFLAGS)

%.o: %.c $(DEPS)
	gcc -c $< $(DFLAGS)

.PHONY: sanitize debug clean
# Compila usando la opción -g para facilitar la depuración con gdb.
debug: DFLAGS = -g
debug: clean $(EXEC)

# Compila habilitando la herramienta AddressSanitizer para
# facilitar la depuración en tiempo de ejecución.
sanitize: DFLAGS = -fsanitize=address,undefined
sanitize: clean $(EXEC)


clean:
	rm -rf $(EXEC) *.o 
	rm -f *.enc
	rm -f *.dec
