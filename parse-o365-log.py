#!/usr/bin/env python3

import csv
import json
import sys


def print_list(l, t=0):
    for i in l:
        if isinstance(i, str):
            print(' '*t + '  - {}'.format(i))
        elif isinstance(i, int):
            print(' '*t + '  - {}'.format(i))
        elif isinstance(i, dict):
            print(' '*t + '  - {')
            print_dict(i, t+4)
            print(' '*(t+4) + '}')
        elif isinstance(i, list):
            print(' '*t + '  - [')
            print_list(i, t+4)
            print(' '*(t+4) + ']')
        else:
            print('####### ERROR, type {} not supported yet.'.format(type(i)))


def print_dict(d, t=0):
    for k in d:
        if isinstance(d[k], str):
            print(' '*t + '  - {} = {}'.format(k, d[k]))
        elif isinstance(d[k], int):
            print(' '*t + '  - {} = {}'.format(k, d[k]))
        elif isinstance(d[k], dict):
            print(' '*t + '  - {} = {{'.format(k))
            print_dict(d[k], t+4)
            print(' '*(t+4) + '}')
        elif isinstance(d[k], list):
            print(' '*t + '  - {} = ['.format(k))
            print_list(d[k], t+4)
            print(' '*(t+4) + ']')
        else:
            print('####### ERROR, type {} not supported yet.'.format(type(d[k])))


def main():
    auditData = []
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        lines = csv.reader(f, delimiter=',', quotechar='"')
        for line in lines:
            auditData.append(line[3])
    # remove headers
    del(auditData[0])

    i = 0
    elements = []
    elements.append('CreationTime')
    elements.append('UserId')
    elements.append('Operation')
    elements.append('ResultStatus')
    elements.append('UserAgent')
    elements.append('ClientIP')
    elements.append('ActorIpAddress')
    
    results = []
    results.append(elements)

    for line in auditData:
        try:
            details = json.loads(line)
        except json.decoder.JSONDecodeError as je:
            print('JSON parsing error.')
            continue
        
        # print('')
        # print('##################################################')
        # print('')
        # print('line = {}'.format(i))
        # print_dict(details)
        # i += 1

        if details['Operation'] == 'UserLoggedIn':
            for extendedProperty in details['ExtendedProperties']:
                if extendedProperty['Name'] == 'UserAgent':
                    details['UserAgent'] = extendedProperty['Value']
        r = [ details.get(e, 'N/A') for e in elements ]
        # print(r)
        # print(type(r))
        
        results.append(r)
    # Optionnal : write to file
    with open('some.csv', 'w', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(results)


if __name__ == '__main__':
    main()

