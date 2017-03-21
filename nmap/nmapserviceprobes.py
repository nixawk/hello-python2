#!/usr/bin/python
# -*- coding: utf-8 -*-

import os


def parse_probestr(probestr):
    """Prase probe str in nmap, returns name, payload
    """
    name, payload, _ = probestr.split('|')
    return (name, payload)


def parse_portstr(portstr):
    """Parse port str in nmap, return port lists
    """
    results = []

    _, p = portstr.split('ports ')
    ports = p.split(',')

    for port in ports:
        if '-' in port:
            start, end = port.split('-')
            _ = [int(_) for _ in range(int(start), int(end) + 1)]
            results.extend(_)
        else:
            results.append(int(port))
    return list(set(results))


def parse_probe_chunk(chunk):
    """Prase nmap probe / port strings
    """
    result = {'name': '', 'payload': '', 'ports': []}

    lines = chunk.splitlines()
    for line in lines:
        if line.startswith('Probe '):
            name, payload = parse_probestr(line)
            result['name'] = name
            result['payload'] = payload
        elif line.startswith('ports') or line.startswith('sslports'):
            ports = parse_portstr(line)
            result['ports'].extend(ports)

    return result


def parse_nmap_service_probes(filename):
    """Get probe name, payload, ports.
    """
    results = []
    if not os.path.exists(filename):
        print('{} not found.'.format(filename))
        return results

    with open(filename) as nf:
        data = nf.read()
        if not data:
            print("{} is empty.".format(filename))
            return results

        chunks = data.split('\n\n#')
        for chunk in chunks:
            ret = parse_probe_chunk(chunk)
            if ret not in results: results.append(ret)

    return results


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("[*] {} <nmap-service-probes>".format(sys.argv[0]))

    filename = sys.argv[1]
    print('[*] parse {}'.format(filename))
    print(parse_nmap_service_probes(filename))
