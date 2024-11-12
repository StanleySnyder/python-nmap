import nmap

def scan_network(target_ip, port_range='22-80'):
    nm = nmap.PortScanner()
    
    try:
        print(f"Сканирование хоста {target_ip} с портами {port_range}...")
        nm.scan(target_ip, port_range)
        
        print(f"Результаты сканирования для хоста {target_ip}:")
        print(f"Статус хоста: {nm[target_ip].state()}")
        
        for proto in nm[target_ip].all_protocols():
            print(f"Протокол: {proto}")
            ports = nm[target_ip][proto].keys()
            for port in ports:
                print(f"  Порт: {port} -> {nm[target_ip][proto][port]['state']}")
    
    except Exception as e:
        print(f"Ошибка: {e}")

if __name__ == "__main__":
    target_ip = input("Введите IP-адрес для сканирования: ")
    
    port_range = input("Введите диапазон портов (по умолчанию 22-80): ")
    if not port_range:
        port_range = '22-80'
    
    scan_network(target_ip, port_range)
