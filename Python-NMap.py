import time
from datetime import datetime
import ipaddress
import netifaces
import shutil
import socket
import nmap
import sys




# - Clase principal para analizar una red
class PythonNMap:


# - Inicializa la clase y crea una instancia
    def __init__(self):
        self.scanner = nmap.PortScanner()


# - Limpieza de Pantalla
    def clear_screen(self):
        print("\n" * 2)


# - Banner de Inicio
    def print_banner(self):

        terminal_width = shutil.get_terminal_size().columns

        banner = [
            "=" * 100,
            "██████╗  ██║   ██║ ████████╗ ██╗   ██╗ ███████╗ ███╗   ██╗   ███╗   ██╗ ███╗   ███╗  █████╗  ██████╗ ",
            "██╔══██╗  ██║ ██║  ╚══██╔══╝ ██║   ██║ ██╔══██║ ████╗  ██║   ████╗  ██║ ████╗ ████║ ██╔══██╗ ██╔══██╗",
            "██████╔╝   ████║      ██║    ████████║ ██║  ██║ ██╔██╗ ██║   ██╔██╗ ██║ ██╔████╔██║ ███████║ ██████╔╝",
            "██╔═══╝     ██║       ██║    ██║   ██║ ██║  ██║ ██║╚██╗██║   ██║╚██╗██║ ██║╚██╔╝██║ ██╔══██║ ██╔══╝  ",
            "██║         ██║       ██║    ██║   ██║ ███████║ ██║ ╚████║   ██║ ╚████║ ██║ ╚═╝ ██║ ██║  ██║ ██║     ",
            "╚═╝         ╚═╝       ╚═╝    ╚═╝   ╚═╝ ╚═════╝  ╚═╝  ╚═══╝   ╚═╝  ╚═══╝ ╚═╝     ╚═╝ ╚═╝  ╚═╝ ╚═╝     ",
            "=" * 100,
            "Herramienta de Escaneo de Redes",
            "Exclusiva para Fines Academicos y Eticos",
            "=" * 100,
            "Copyright of Daniel Humberto, 2025",
            "=" * 100,
            ""
        ]

        for line in banner:
            padding = (terminal_width - len(line)) // 2
            print(" " * padding + line)


# - Validación de IP
    def validate_ip(self, ip):

        parts = ip.split('.')

        if len(parts) != 4:
            return False
        for part in parts:
            try:
                if not 0 <= int(part) <= 255:
                    return False
            except ValueError:
                return False
        return True


#  1.- Escaneo de Puertos
    def port_scan(self):

        while True:

            print("\nEscaneo de Puertos:")
            print("A. Detectar puertos abiertos")
            print("B. Identificar servicios en puertos")
            print("C. Volver al menú principal")

            choice = input("\nSeleccione una opción: ").upper()

            if choice == 'A':

                target = input("\nIngrese la dirección IP objetivo: ")

                if not self.validate_ip(target):
                    print("IP inválida")
                    continue

                print("\nEscaneando puertos abiertos...")
                self.scanner.scan(target, '1-1024', '-sS')

                for host in self.scanner.all_hosts():
                    print(f"\nHost : {host}")
                    for proto in self.scanner[host].all_protocols():
                        ports = self.scanner[host][proto].keys()
                        for port in ports:
                            state = self.scanner[host][proto][port]['state']
                            if state == 'open':
                                print(f"Puerto {port}: {state}")

            elif choice == 'B':

                target = input("\nIngrese la dirección IP objetivo: ")
                port = input("Ingrese el puerto a escanear: ")

                if not self.validate_ip(target):
                    print("IP inválida")
                    continue

                print("\nIdentificando servicios...")
                self.scanner.scan(target, port, '-sV')

                try:
                    service = self.scanner[target]['tcp'][int(port)]['name']
                    version = self.scanner[target]['tcp'][int(port)]['version']
                    print(f"\nServicio: {service}")
                    print(f"Versión: {version}")
                except:
                    print("No se pudo identificar el servicio")

            elif choice == 'C':
                break


#  2.- Detección de Sistemas Operativos
    def os_detection(self):

        while True:

            print("\nDetección de Sistemas Operativos:")
            print("A. Identificar SO")
            print("B. Obtener detalles del SO")
            print("C. Volver al menú principal")

            choice = input("\nSeleccione una opción: ").upper()

            if choice in ['A', 'B']:

                target = input("\nIngrese la dirección IP objetivo: ")

                if not self.validate_ip(target):
                    print("IP inválida")
                    continue

                print("\nDetectando sistema operativo...")
                self.scanner.scan(target, arguments='-O')

                try:
                    os_matches = self.scanner[target]['osmatch']
                    if choice == 'A':
                        print(f"\nSistema Operativo más probable: {os_matches[0]['name']}")
                    else:
                        print("\nDetalles del Sistema Operativo:")
                        for os in os_matches:
                            print(f"Nombre: {os['name']}")
                            print(f"Precisión: {os['accuracy']}%")
                            print("---")
                except:
                    print("No se pudo detectar el sistema operativo")

            elif choice == 'C':
                break


#  3.- Escaneo de Redes
    def network_scan(self):

        while True:

            print("\nEscaneo de Redes:")
            print("A. Escanear rango de IPs")
            print("B. Identificar dispositivos activos")
            print("C. Volver al menú principal")

            choice = input("\nSeleccione una opción: ").upper()

            if choice == 'A':

                network = input("\nIngrese el rango de red (ejemplo: 192.168.1.0/24): ")
                print("\nEscaneando red...")
                self.scanner.scan(hosts=network, arguments='-sP')

                for host in self.scanner.all_hosts():
                    print(f"\nHost: {host}")
                    print(f"Estado: {self.scanner[host].state()}")

            elif choice == 'B':

                network = input("\nIngrese el rango de red: ")
                print("\nIdentificando dispositivos activos...")
                self.scanner.scan(hosts=network, arguments='-sn')

                print("\nDispositivos activos:")
                for host in self.scanner.all_hosts():
                    if self.scanner[host].state() == 'up':
                        print(f"Host: {host}")

            elif choice == 'C':
                break


#  4.- Detección de Servicios (
    def service_detection(self):

        while True:

            print("\nDetección de Servicios:")
            print("A. Identificar servicios y versiones")
            print("B. Obtener banners de servicios")
            print("C. Volver al menú principal")

            choice = input("\nSeleccione una opción: ").upper()

            if choice == 'A':

                target = input("\nIngrese la dirección IP objetivo: ")

                if not self.validate_ip(target):
                    print("IP inválida")
                    continue

                print("\nIdentificando servicios...")
                self.scanner.scan(target, '1-1024', '-sV')

                for host in self.scanner.all_hosts():
                    print(f"\nHost : {host}")
                    for proto in self.scanner[host].all_protocols():
                        ports = self.scanner[host][proto].keys()
                        for port in ports:
                            service = self.scanner[host][proto][port]
                            print(f"\nPuerto {port}:")
                            print(f"Servicio: {service['name']}")
                            print(f"Versión: {service['version']}")

            elif choice == 'B':

                target = input("\nIngrese la dirección IP objetivo: ")

                if not self.validate_ip(target):
                    print("IP inválida")
                    continue

                print("\nObteniendo banners...")
                self.scanner.scan(target, '1-1024', '-sV --version-intensity 5')

                for host in self.scanner.all_hosts():
                    for proto in self.scanner[host].all_protocols():
                        ports = self.scanner[host][proto].keys()
                        for port in ports:
                            service = self.scanner[host][proto][port]
                            if 'product' in service:
                                print(f"\nPuerto {port}:")
                                print(f"Producto: {service['product']}")
                                print(f"Banner: {service.get('extrainfo', 'No disponible')}")

            elif choice == 'C':
                break


#  5.- Automatización de Seguridad
    def security_automation(self):

        print("\nAutomatización de Pruebas de Seguridad")
        target = input("\nIngrese la dirección IP objetivo: ")

        if not self.validate_ip(target):
            print("IP inválida")
            return

        print("\nRealizando escaneo de seguridad automatizado...")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"security_scan_{timestamp}.txt"

        with open(report_file, 'w') as f:

            f.write("=== Reporte de Seguridad Automatizado ===\n\n")

            print("Escaneando puertos...")
            self.scanner.scan(target, '1-1024', '-sS -sV')
            f.write("Puertos y Servicios:\n")

            for proto in self.scanner[target].all_protocols():
                ports = self.scanner[target][proto].keys()
                for port in ports:
                    state = self.scanner[target][proto][port]['state']
                    service = self.scanner[target][proto][port]['name']
                    f.write(f"Puerto {port}: {state}, Servicio: {service}\n")

            print("Detectando sistema operativo...")
            self.scanner.scan(target, arguments='-O')
            f.write("\nSistema Operativo:\n")

            if 'osmatch' in self.scanner[target]:
                for os in self.scanner[target]['osmatch']:
                    f.write(f"SO: {os['name']}, Precisión: {os['accuracy']}%\n")

        print(f"\nReporte guardado en: {report_file}")


#  6.- Generación de Informes Personalizados
    def generate_report(self):

        print("\nGeneración de Informes Personalizados")
        target = input("\nIngrese la dirección IP objetivo: ")

        if not self.validate_ip(target):
            print("IP inválida")
            return

        print("\nGenerando informe detallado...")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"detailed_report_{timestamp}.txt"

        with open(report_file, 'w') as f:

            f.write("=== Informe Detallado de Escaneo ===\n\n")
            f.write(f"Objetivo: {target}\n")
            f.write(f"Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            self.scanner.scan(target, '1-1024', '-sS -sV -O -A')

            f.write("Información del Host:\n")
            f.write(f"Estado: {self.scanner[target].state()}\n\n")

            f.write("Puertos y Servicios:\n")

            for proto in self.scanner[target].all_protocols():
                f.write(f"\nProtocolo: {proto}\n")
                ports = self.scanner[target][proto].keys()
                for port in ports:
                    service = self.scanner[target][proto][port]
                    f.write(f"\nPuerto {port}:\n")
                    f.write(f"Estado: {service['state']}\n")
                    f.write(f"Servicio: {service['name']}\n")
                    f.write(f"Versión: {service['version']}\n")
                f.write("\nSistema Operativo:\n")
                for os in self.scanner[target]['osmatch']:
                    f.write(f"Nombre: {os['name']}\n")
                    f.write(f"Precisión: {os['accuracy']}%\n")

        print(f"\nInforme guardado en: {report_file}")


#  7.- Escaneos Personalizados
    def custom_scan(self):

        while True:

            print("\nTipos de Escaneo Personalizados:")
            print("A. Escaneo TCP/UDP/SYN/ACK")
            print("B. Escaneo intensivo personalizado")
            print("C. Volver al menú principal")

            choice = input("\nSeleccione una opción: ").upper()

            if choice == 'A':

                target = input("\nIngrese la dirección IP objetivo: ")

                if not self.validate_ip(target):
                    print("IP inválida")
                    continue

                print("\nSeleccione tipo de escaneo:")
                print("1. TCP")
                print("2. UDP")
                print("3. SYN")
                print("4. ACK")
                scan_type = input("Opción: ")

                args = {
                    '1': '-sT',
                    '2': '-sU',
                    '3': '-sS',
                    '4': '-sA'
                }

                if scan_type in args:

                    print(f"\nRealizando escaneo {args[scan_type]}...")
                    self.scanner.scan(target, '1-1024', args[scan_type])

                    for host in self.scanner.all_hosts():
                        print(f"\nResultados para {host}:")
                        for proto in self.scanner[host].all_protocols():
                            ports = self.scanner[host][proto].keys()
                            for port in ports:
                                state = self.scanner[host][proto][port]['state']
                                print(f"Puerto {port}: {state}")

            elif choice == 'B':

                target = input("\nIngrese la dirección IP objetivo: ")

                if not self.validate_ip(target):
                    print("IP inválida")
                    continue

                print("\nIngrese argumentos personalizados de Nmap")
                print("Ejemplo: -sS -sV -O --script vuln")
                args = input("Argumentos: ")

                print("\nRealizando escaneo personalizado...")
                self.scanner.scan(target, arguments=args)

                print("\nResultados del escaneo:")
                print(self.scanner.csv())

            elif choice == 'C':
                break


#  8.- Automatización de Escaneo Total de la Red
    def Full_Network_Scanning(self):

        print("\nEscaneo Global de Red")
        network = input("\nIngrese el rango de red (ejemplo: 192.168.1.0/24): ")

        print("\nIniciando escaneo global de la red...")
        print("Este proceso puede tardar varios minutos dependiendo del tamaño de la red.")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"global_network_scan_{timestamp}.txt"

        with open(report_file, 'w') as f:

            f.write("=== Reporte de Escaneo Global de Red ===\n\n")
            f.write(f"Red objetivo: {network}\n")
            f.write(f"Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            try:
                print("\nPaso 1/4: Descubriendo dispositivos activos...")
                self.scanner.scan(hosts=network, arguments='-sn')

                active_hosts = []
                f.write("Dispositivos activos:\n")

                for host in self.scanner.all_hosts():
                    if self.scanner[host].state() == 'up':
                        active_hosts.append(host)
                        f.write(f"- {host}\n")

                f.write(f"\nTotal de dispositivos activos: {len(active_hosts)}\n\n")

            except Exception as e:
                print(f"Error en descubrimiento de hosts: {e}")
                f.write(f"Error en descubrimiento de hosts: {e}\n")
                return

            for i, host in enumerate(active_hosts):
                f.write(f"\n{'=' * 50}\n")
                f.write(f"Host: {host}\n")
                f.write(f"{'=' * 50}\n\n")

                try:
                    print(f"\nPaso 2/4: Escaneando puertos en host {i + 1}/{len(active_hosts)}: {host}")
                    self.scanner.scan(host, '1-1024', '-sS --min-rate 1000 --max-retries 2')

                    f.write("Puertos abiertos:\n")
                    open_ports = []

                    for proto in self.scanner[host].all_protocols():
                        ports = sorted(self.scanner[host][proto].keys())
                        for port in ports:
                            state = self.scanner[host][proto][port]['state']
                            if state == 'open':
                                open_ports.append(str(port))
                                f.write(f"- Puerto {port}/{proto}: {state}\n")

                    if not open_ports:
                        f.write("- No se encontraron puertos abiertos\n")

                except Exception as e:
                    print(f"Error al escanear puertos en {host}: {e}")
                    f.write(f"Error al escanear puertos: {e}\n")
                    continue

                if open_ports:
                    try:
                        print(f"Paso 3/4: Identificando servicios en host: {host}")
                        ports_str = ','.join(open_ports)
                        self.scanner.scan(host, ports=ports_str, arguments='-sV --version-intensity 0')

                        f.write("\nServicios detectados:\n")
                        for port in open_ports:
                            port = int(port)
                            try:
                                service = self.scanner[host]['tcp'][port].get('name', 'desconocido')
                                version = self.scanner[host]['tcp'][port].get('version', '')
                                product = self.scanner[host]['tcp'][port].get('product', '')
                                f.write(f"- Puerto {port}: {service} - {product} {version}\n")
                            except KeyError:
                                f.write(f"- Puerto {port}: No se pudo identificar el servicio\n")
                    except Exception as e:
                        print(f"Error al identificar servicios en {host}: {e}")
                        f.write(f"Error al identificar servicios: {e}\n")
                else:
                    f.write("\nNo se realizó identificación de servicios (sin puertos abiertos)\n")

                if i < min(5, len(active_hosts)):
                    try:
                        print(f"Paso 4/4: Detectando sistema operativo en host: {host}")
                        self.scanner.scan(host, arguments='-O --max-os-tries 1')

                        f.write("\nSistema Operativo:\n")
                        if 'osmatch' in self.scanner[host] and len(self.scanner[host]['osmatch']) > 0:
                            os_match = self.scanner[host]['osmatch'][0]
                            f.write(f"- Posible SO: {os_match['name']} (Precisión: {os_match['accuracy']}%)\n")
                        else:
                            f.write("- No se pudo detectar el sistema operativo\n")
                    except Exception as e:
                        print(f"Error al detectar SO en {host}: {e}")
                        f.write(f"Error al detectar sistema operativo: {e}\n")

        print(f"\nEscaneo global completado.")
        print(f"Reporte guardado en: {report_file}")




# - Menú Principal
    def main_menu(self):

            while True:

                self.clear_screen()
                self.print_banner()

                print("\nMenú Principal:")
                print("")
                print("1. Escaneo de Puertos")
                print("2. Detección de Sistemas Operativos")
                print("3. Escaneo de Redes")
                print("4. Detección de Servicios")
                print("5. Automatización de Pruebas de Seguridad")
                print("6. Generación de Informes Personalizados")
                print("7. Escaneos Personalizados de Seguridad")
                print("8. Automatización de Escaneo Total de la Red")
                print("9. Salir")

                choice = input("\nSeleccione una opción: ")

                if choice == '1':
                    self.port_scan()
                elif choice == '2':
                    self.os_detection()
                elif choice == '3':
                    self.network_scan()
                elif choice == '4':
                    self.service_detection()
                elif choice == '5':
                    self.security_automation()
                elif choice == '6':
                    self.generate_report()
                elif choice == '7':
                    self.custom_scan()
                elif choice == '8':
                    self.Full_Network_Scanning()
                elif choice == '9':
                    print("\nSaliendo del programa...")
                    sys.exit()
                else:
                    print("\nOpción inválida")
                    time.sleep(2)


# - Punto de Entrada
if __name__ == "__main__":
    try:
        scanner = PythonNMap()
        scanner.main_menu()
    except KeyboardInterrupt:
        print("\n\nPrograma interrumpido por el usuario.")
        sys.exit()
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)