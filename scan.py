import nmap

def scanNetwork(network):
    return_list = []
    nm = nmap.PortScanner()
    a = nm.scan(hosts=network, arguments='-sn -T5')

    for k, v in a['scan'].items():
        if str(v['status']['state']) == 'up':
            try:
                return_list.append([str(v['addresses']['ipv4']), str(v['addresses']['mac'])])
            except:
                pass

    return return_list
