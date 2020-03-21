#!/bin/bash

# Instalador.
# OBS: É necessario permissão de administrador para este script.
root=`id -u`
if [ $root != 0 ]
then
	echo "> Execute esse script como administrador: sudo $0"
	exit 126
fi

# Limpar a tela
clear

wd=0

# Verificando arquivos
echo "#-----> Verificação de arquivos <-----#"
echo " "
echo "#-----> ATENÇÃO <-----#"
echo "Caso você tenha movido algum arquivo para outro lugar,"
echo "é possivel que ocorra erros na hora da instalação."
echo " "
echo "> Verificando wordlist..."
if [ -f wordlist/wordlist.txt ]
then
	echo "> [OK]: wordlist.txt"
	wd=1
else
	echo "> [ERRO]: Arquivo wordlist.txt não encontrado em wordlist/wordlist.txt"
fi

echo "> Verificando spectre..."
if [ -f bin/Debug/spectre ]
then
	echo "> [OK]: spectre"
else
	echo "> [ERRO]: Erro ao encontrar o binario"
	echo "> Tentando compilar..."
	if [ -d bin/Debug ]
	then
		if [ -f src/main.c ]
		then
		       if  gcc -w src/main.c -o bin/Debug/spectre >> /dev/null
                       then
                                echo "> [OK] Compilado."
                        else
                                echo "> [ERRO]: Erro ao compilar arquivo"
                                exit 1
                        fi

		else
			echo "> [ERRO]: Arquivo de codigo não encontrado."
			exit 1
		fi

	else
		mkdir bin/Debug
		if [ -f src/main.c ]
                then
                       if  gcc -w src/main.c -o bin/Debug/spectre  >> /dev/null
		       then
				echo "> [OK] Compilado."
			else
				echo "> [ERRO]: Erro ao compilar arquivo"
				exit 1
			fi
                else
                        echo "> [ERRO]: Arquivo de codigo não encontrado."
                        exit 1
                fi

	fi
fi

# Instalação do software
echo "> Instalando..."
if cp bin/Debug/spectre /usr/bin
then
	echo "> [OK]: Instalado."
	mkdir /usr/share/Spectre > /dev/null
	cp wordlist/wordlist.txt /usr/share/Spectre/wordlist.txt > /dev/null
else
	echo "> [ERRO]: Erro ao instalar software"
	exit 1

fi

exit 0
