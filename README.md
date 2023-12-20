<div align="center">
  <h1>hostExplorer_V2</h1>
  <h4>Esta herramienta esta creada con el fin de poder realizar escaneos de red</h4>
</div>
<ul>
    <li>Esta herramienta cuneta con funciones, que permiten obtener IP, hostname, MAC, etc de los equipos detectados en la red.</li>
    <li>Nueva version [multisystem]: <a href="https://github.com/clhore/hostExplorer_V3">https://github.com/clhore/hostExplorer_V3</li> 
</ul> 

Ejemplo de escaneo modo defauld
======
    
      hostExplorer -i 10.70.240.0 --mask 24

<img src="img/example.png"></br>
Si revisamos el trefico de la red, obserbaremos las peticiones icmp y dns que realiza la herramienta en el modo default(1).
<img src="img/icmp_request.png"></br>
<img src="img/dns_request.png"></br>


Ejemplo de escaneo TCP
======

      hostExplorer -i 10.70.240.0 --mask 24 -m 2

<img src="img/example_m2.png"></br>
Si revisamos el trefico de la red, obserbaremos las peticiones icmp, dns y tcp que realiza la herramienta en el modo(2)[escaneo tcp].
<img src="img/icmp_request_m2.png"></br>
<img src="img/dns_request_m2.png"></br>
<img src="img/tcp_request_m2.png"></br>


Ejemplo de escaneo UDP
======

      hostExplorer -i 10.70.240.0 --mask 24 -m 3

<img src="img/example_m3.png"></br>
Si revisamos el trefico de la red, obserbaremos las peticiones icmp, dns y tcp que realiza la herramienta en el modo(3)[escaneo udp].
<img src="img/icmp_request_m3.png"></br>
<img src="img/dns_request_m3.png"></br>


Instalacion automatica
======

    curl -O https://raw.githubusercontent.com/clhore/hostExplorer_V2/main/hostExplorer && sudo chmod +x hostExplorer
    sudo ./hostExplorer --install=true


Instalacion manual
======
Instalar las librerias de python: 

    pip3 install ipaddress
    pip3 install tabulate
    pip3 install icmplib
    pip3 install python3-nmap
    pip3 install pandas

or

    curl -O https://raw.githubusercontent.com/clhore/hostExplorer_V2/main/requirements.txt
    python3 -m pip install -r requirements.txt


Instalar dependencias:

    Arch Linux: sudo pacman -S nmap whiptail curl
    Ubuntu: sudo apt-get install nmap whiptail curl

    
Instalacion de hostExplorer: 

    sudo mkdir /opt/hostExplorer
    cd /opt/hostExplorer
    sudo curl -O https://raw.githubusercontent.com/clhore/hostExplorer_V2/main/hostExplorer
    sudo curl -O https://raw.githubusercontent.com/clhore/hostExplorer_V2/main/oui_hex.txt
    sudo chmod +x hostExplorer
    sudo ln -s /opt/hostExplorer/hostExplorer
    
    
Help Panel
======
<div align="center">
  <img src="img/help.png">
</div>
