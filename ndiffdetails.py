#!/usr/bin/env python

from ndiff import *

def main():
    global verbose
    diffout = "diff.xml"
    cmdout = "nmap-details.sh"

    try:
        opts, input_filenames = getopt.gnu_getopt(sys.argv[1:], "hv", ["verbose", "diffout=", "cmdout="])
    except getopt.GetoptError, e:
        usage_error(e.msg)
    for o, a in opts:
        if o == "--diffout":
            diffout = a
        elif o == "--cmdout":
            cmdout = a
        elif o == "-v" or o == "--verbose":
            verbose = True

    if len(input_filenames) != 2:
        usage_error(u"need exactly two input filenames.")

    filename_a = input_filenames[0]
    filename_b = input_filenames[1]

    try:
        scan_a = Scan()
        scan_a.load_from_file(filename_a)
        scan_b = Scan()
        scan_b.load_from_file(filename_b)
    except IOError, e:
        print >> sys.stderr, u"Can't open file: %s" % str(e)
        sys.exit(EXIT_ERROR)

    diff = ScanDiff(scan_a, scan_b)
    targets = []
    ports = {}

    if diff.cost > 0:
        for host,h_diff in diff.host_diffs.iteritems():
            if h_diff.cost > 0 and h_diff.host_b.state == "up":
                scan_host = False
                for port,p_diff in h_diff.port_diffs.iteritems():
                    if (p_diff.port_a.state != p_diff.port_b.state and
                        p_diff.port_b.state is not None and
                        p_diff.port_b.state.startswith("open")):
                            scan_host = True
                            ports[p_diff.port_b.spec[0]]=1
                if scan_host:
                    targets.append(h_diff.host_b.get_id())

        difffile = open(diffout, 'w')
        diff.print_text(f=difffile)
        difffile.close()

        if ports:
            cmdfile = open(cmdout, 'w')
            cmdfile.write("set -x\n")
            cmdfile.write("OUTFILE=nmap-details\n")
            cmdfile.write('test -z "$1" || OUTFILE=$1\n')
            cmdfile.write("/usr/local/bin/nmap -v --open -p %s -sV -sC -oA $OUTFILE %s\n"
                    % ( reduce(lambda x,y: str(x)+","+str(y), ports.keys()),
                        " ".join(targets)))
            cmdfile.close()

if __name__ == "__main__":
    main()
