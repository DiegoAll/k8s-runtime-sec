#!/bin/bash

# Actualiza el sistema
sudo apt-get update

# Configura el entorno para la instalación
sudo apt-get install -y tzdata
sudo cp /usr/share/zoneinfo/America/Bogota /etc/localtime
sudo dpkg-reconfigure -f noninteractive tzdata

# Instala los paquetes básicos
sudo apt-get install -y wget tar sudo adduser net-tools curl

# Instala paquetes adicionales
sudo apt-get install -y nmap pkexec python3


# Instalar golang mas actualizado


# Configurar path source 
# wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
# sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
# export PATH=$PATH:/usr/local/go/bin
# ~/bashrc


# Instala utilidades adicionales
sudo apt-get install -y make gcc git kmod

# Crea y configura el usuario 'falcox'
sudo useradd -m -s /bin/bash falcox


# Crear log para kern.log
touch /var/log/kern.log

# Configura la contraseña para el usuario root (esto es una vulnerabilidad de seguridad)
echo "root:toor" | sudo chpasswd

# Agrega el usuario 'falcox' al grupo sudo y configura NOPASSWD
echo "falcox ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/falcox

# Configura permisos para el archivo de sudoers
sudo chmod 044 /etc/sudoers.d/falcox

# Crea directorios y archivos necesarios para el usuario 'falcox'
sudo mkdir -p /home/falcox/.ssh
sudo touch /home/falcox/.ssh/id_rsa

# Cambia al usuario 'falcox'
sudo -u falcox bash <<EOF
cd /home/falcox
EOF

echo "Instalación y configuración completadas."
