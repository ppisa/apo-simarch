#!/usr/bin/python

import sys

def aphosval(s):
    s = s.strip()
    if s[0] != '"':
        sys.stderr.write('apostrophed val extract error - no aposstrophe at start\n')
    p = s.find('"', 1)
    if p == -1:
        sys.stderr.write('apostrophed val extract error - no final aposstrophe\n')
    return s[1:p], s[p + 1: ]

def tonextfied(s):
    s.strip()
    if s[0] != ',':
        sys.stderr.write('coma delimiting next fiels missing\n')
    return s[1:]

def fieldextract(s, delim = ',', delim_optional = False):
    p = s.find(delim)
    if p == -1:
        if not delim_optional:
            sys.stderr.write('missing field end\n')
        return s.strip(), ''
    return s[0:p].strip(), s[p + 1:].strip()

pinfo_all = []
pinfo2_all = []
membership_all = []
exclusions_all = []

for line in sys.stdin:
    line = line.strip()
    if len(line) <= 1:
        continue
    if line[0] != '{':
        sys.stderr.write('line is not starting by {\n')
    p = line.find('}')
    if p == -1:
        sys.stderr.write('line is not finished by }\n')
    line = line[1:p].strip()
    name, line = aphosval(line)
    line = tonextfied(line)
    args, line = aphosval(line)
    if len(args) >= 1:
        args = args.split(',')
    else:
        args = []
    line = tonextfied(line)
    match, line = fieldextract(line)
    mask, line = fieldextract(line)
    pinfo, line = fieldextract(line)
    pinfo2, line = fieldextract(line)
    membership, line = fieldextract(line, delim_optional = True)
    exclusions = line.strip()
    if len(exclusions) == 0:
        exclusions = '0'
    sys.stdout.write('    instdes("'+ name + '", [')
    no_coma = True
    for a in args:
        if no_coma:
            no_coma = False
        else:
            sys.stdout.write(',')
        sys.stdout.write("'" + a + "'")
    sys.stdout.write('], ' + match + ', ' + mask + ', ' + pinfo + ', ' + pinfo2 +
                    ', ' + membership + ', ' + exclusions + '),\n')

    pinfo_all.extend([ x.strip() for x in pinfo.split('|') if not x in pinfo_all])
    pinfo2_all.extend([ x.strip() for x in pinfo2.split('|') if not x in pinfo2_all])
    membership_all.extend([ x.strip() for x in membership.split('|') if not x in membership_all])
    exclusions_all.extend([ x.strip() for x in exclusions.split('|') if not x in exclusions_all])

print pinfo_all
print pinfo2_all
print membership_all
print exclusions_all

