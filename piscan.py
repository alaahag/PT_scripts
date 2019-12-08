#!/usr/bin/python

import sys
import datetime
import time
import re
import socket
from contextlib import closing

# -------------------------------
# this script runs on Python 2.x
# author: Alaa H.J <MasterX>
# -------------------------------


# global:
# the default name of the output file (you can change it from here):
the_output_file = "piscan_res.txt"


#
# function to draw menu
#
def show_menu():
    # didn't use argument, so we will print the menu section here
    print ""
    print "|------------------------------------------|"
    print "|  'piscan' - IPs & Ports Scanner  [v1.0]  |"
    print "|                                          |"
    print "|        By: Alaa H.J     {MasterX}        |"
    print "|------------------------------------------|"
    print
    print "-> Usage:"
    print ">             ./piscan.sh -v <IPs> -p <Ports> -o <Output>"
    print
    print
    print "-> Options:"
    print ">             -v"
    print ">             (Verbose mode: a 'heavy scan', but it can dig for HTTP-responses)"
    print
    print ">             <IP-range> (IPStart-IPEnd)"
    print
    print ">             -p <Port-range> (PortStart-PortEnd)"
    print ">             or"
    print ">             -p <Custom,Ports> (Port1,Port2,Port3...)"
    print
    print ">             -o <Output>"
    print ">             (Default file: '" + the_output_file + "')"
    print
    print
    print "-> Examples:"
    print ">             ./piscan.sh 192.168.0.1-192.168.0.100 -p 80 -o ports_res.txt"
    print ">             ./piscan.sh -v 127.0.0.1 -p 1-500 -o my_ports.txt"
    print ">             ./piscan.sh 172.16.1.1-172.16.5.100 -p 135,139,80"
    print


#
# function to scan specific port
#
def scan_specific_target_quickly(ip, port, text_port):
    # scan a specific port (quickly)

    # ipv4 tcp
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        try:
            # try to connect
            if sock.connect_ex((ip, port)) == 0:
                # open port detected
                print '\x1b[1;32;40m' + text_port + str(port) + '\x1b[0m'

                # append to file
                with open(the_output_file, "a") as output_file:
                    output_file.write(text_port + str(port) + "\n")

        except socket.error:
            # socket exception
            pass

    return


#
# function to scan specific port
#
def scan_specific_target_verbose(ip, port, text_port):
    # scan a specific port (verbose)

    # ipv4 tcp
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        try:
            # try connect
            sock.connect((ip, port))

            ########################################################
            # if we reached here, means: open port detected
            ########################################################

            # send HTTP header
            print '\x1b[1;32;40m' + text_port + str(port) + '\x1b[0m'
            sock.send('GET / HTTP/1.1\r\n\r\n')

            # get reply from HTTP header
            reply = str(sock.recv(1024)).strip()

            # print reply, if there's any reply
            if reply != "":
                print '\33[93m' + reply + '\x1b[0m'

            # append to file
            with open(the_output_file, "a") as output_file:
                output_file.write(text_port + str(port) + "\n")
                if reply != "":
                    output_file.write(reply + "\n")

        except socket.error:
            # socket exception
            pass

    return


#
# function to get datetime-now and return it as string
#
def get_date_time_now():
    return str(datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))


#
# function to do scanning for ips and ports
#
def scan_ip_ports(ip_start, ip_end, ports_start, port_end, ip_output_string, port_output_string, is_verbose):
    # loop in the ips and scan for open-ports

    # convert list of ips to ints
    for i in range(4):
        ip_start[i] = int(ip_start[i])
        ip_end[i] = int(ip_end[i])

    # port splits to int
    port_start = ports_start.split(",")
    for i in range(len(port_start)):
        port_start[i] = int(port_start[i])

    port_end = int(port_end)

    # first we will get how many ports we need to scan so we can calculate the duration needed we subtract each
    # section of the ip_end from the section of ip_start and multiply the result with 256 with number of times
    # depends on position, except the last section of the ip (ip_start[3] and ip_end[3]) then we multiply the result
    # with the range of ports to be scanned to get the total duration (estimated)
    duration_ips = (ip_end[0] - ip_start[0]) * 256 * 256 * 256 + (ip_end[1] - ip_start[1]) * 256 * 256 + (ip_end[2] - ip_start[2]) * 256 + ip_end[3] - ip_start[3] + 1

    # get the number of items in array to know the number of ports used with 'split' so we can calculate duration time with it
    duration_splitted_port_start = len(port_start)
    duration_ports = duration_splitted_port_start + 1
    if port_end != 0:
        # if we used a port-range then we calculate it
        duration_ports += port_end - port_start[0]

    # timeout duration, speed of each scan (we will multiply it with the number of total ips and ports to be scanned to calculate the max estimated duration)
    max_timeout = 0.1
    total_duration = duration_ips * duration_ports * max_timeout
    socket.setdefaulttimeout(max_timeout)

    try:
        print
        print "> #####################################################"
        print "> ################### STARTING SCAN ###################"
        print "> #####################################################"
        print "> IP-range:                " + ip_output_string
        print "> Port(s):                 " + port_output_string
        print "> Start time:              " + get_date_time_now()
        print "> Max estimated duration:  ~ %g seconds or less" % total_duration
        print "> -----"

        # scan start-time
        start_time = time.time()

        # append to file
        with open(the_output_file, "a") as output_file:
            output_file.writelines([
                "\n",
                "> #####################################################\n",
                "> ################### STARTING SCAN ###################\n",
                "> #####################################################\n",
                "> IP-range:                " + ip_output_string + "\n",
                "> Port(s):                 " + port_output_string + "\n",
                "> Start time:              " + get_date_time_now() + "\n",
                "> Max estimated duration:  ~ %g seconds" % total_duration + " or less\n",
                "> -----\n"])

        # loop for starting-ip to end-ip and scan for open ports start with the very left side section
        # (we divided the ip to 4 parts and will start incrementing each side til you reach the goal)
        for i in range(duration_ips):
            # generate ip for each loop and print it on screen
            generated_ip = str(ip_start[0]) + "." + str(ip_start[1]) + "." + str(ip_start[2]) + "." + str(ip_start[3])
            print "\n> Scanning IP: %s , Port(s): %s ..." % (generated_ip, port_output_string)

            # append to file
            with open(the_output_file, "a") as output_file:
                output_file.write("\n> Scanning IP: %s , Port(s): %s ..." % (generated_ip, port_output_string) + "\n")

            # we will skip scanning the 255 of the very right side because it's a broadcast (so we save time)
            if ip_start[3] != 255:
                # save the string of "open port detected" to a variable, because we will use it more than once
                text_open_port = "-> [+] Open-Port detected!  IP: " + generated_ip + " ,  Port: "

                # if there's no port-range then we will split the ip-start (of ports) to scan them all
                if port_end == 0:
                    for p in range(len(port_start)):
                        # we will scan the ip and the ports here
                        if is_verbose:
                            # verbose mode
                            scan_specific_target_verbose(generated_ip, port_start[p], text_open_port)
                        else:
                            # quick mode
                            scan_specific_target_quickly(generated_ip, port_start[p], text_open_port)
                else:
                    # we will scan port-range here
                    for p in range(port_start[0], port_end + 1, 1):
                        # we will scan the ip and the range of ports related to it here
                        if is_verbose:
                            # verbose mode
                            scan_specific_target_verbose(generated_ip, p, text_open_port)
                        else:
                            # quick mode
                            scan_specific_target_quickly(generated_ip, p, text_open_port)

            # increment the ip-parts of the ip (we start from the very right section of ip-part, incrementing it and we will make it 0 if we reached 255 then increment the ip-part section before it [third then second then first ip-part])
            if ip_start[3] == 255:
                # fourth ip-part will be 0 and we will increment the third ip-part with 1
                ip_start[3] = 0
                if ip_start[2] == 255:
                    # third ip-part will be 0 and we will increment the second ip-part with 1
                    ip_start[2] = 0
                    if ip_start[1] == 255:
                        # second ip-part will be 0 and we will increment the first ip-part with 1
                        ip_start[1] = 0
                        ip_start[0] += 1
                    else:
                        ip_start[1] += 1
                else:
                    ip_start[2] += 1
            else:
                # increment the forth ip-part of the ip here
                ip_start[3] += 1

        ########################################################
        # if we reached here, means we have completed our scans
        ########################################################

        # calculate time elapsed and get datetime of now (print them)
        time_elapsed = int(time.time() - start_time)
        date_time_finish = get_date_time_now()
        print "\n> -----"
        print "\33[92m> [v] SCAN COMPLETED!  :::  %s (elapsed: %d seconds).\033[1;m" % (date_time_finish, time_elapsed)
        print ">     Output file:     :::  " + the_output_file
        print "> #####################################################"

        # append to file
        with open(the_output_file, "a") as output_file:
            output_file.writelines([
                "\n> -----\n",
                "> [v] SCAN COMPLETED!  :::  %s (elapsed: %d seconds).\n" % (date_time_finish, time_elapsed),
                ">     Output file:     :::  " + the_output_file + "\n",
                "> #####################################################\n"])

    # errors handling
    except IOError as io_e:
        # file exception
        print "\33[91m> [x] " + io_e.message + "\033[1;m"
        print "\33[91m> [x] Scan interrupted!  :::  (" + get_date_time_now() + ")\033[1;m"
        print "> #####################################################"

    except:
        # on exception (like when pressing CTRL+C or anything else) then log the error and quit
        # also append to file

        # get termination date time to string
        termination_date_time = get_date_time_now()
        print "\n> -----"
        print "\33[91m> [x] Scan interrupted!  :::  (" + termination_date_time + ")\033[1;m"
        print ">     Output file:       :::   " + the_output_file
        print "> #####################################################"

        # append to file the error
        with open(the_output_file, "a") as output_file:
            output_file.writelines([
                "\n> -----\n",
                "> [x] Scan interrupted!  :::  (" + termination_date_time + ")\n",
                ">     Output file:       :::   " + the_output_file + "\n",
                "> #####################################################\n"])

    return


#
# function to output error
#
def output_error():
    # function to print invalid input and exit

    print "> [!] Invalid input or syntax."
    sys.exit()

    # return


#
# function to validate ip range and output error if invalid
#
def validate_ip_range(arr_ips):
    # we will validate the IP range here
    # the ip must be from 0 to 255 (for each section of the ip)
    # the function will get array of list [4], these are the ip-parts separated

    # check each part of it's not in range (0-255)
    # if not in range then we exit from program
    for i in arr_ips:
        if int(i) > 255:
            print "> [!] Invalid IP address."
            sys.exit()

    return


#
# function to validate ip address and output error if invalid
#
def validate_port_range(p):
    # we will validate the port range here
    # the port must be from 1 to 65535 max
    # the function will get 'p' as the port value

    # check port if in range of valid ports
    # if not, then we will exit from program
    p = int(p)
    if p < 1 or p > 65535:
        print "> [!] Invalid Port(s)."
        sys.exit()

    return


#
# function to check for valid args (input) and it will calculate ip-range and calls the scanning function if everything looks fine
#
def validate_input(argv):
    # validate input syntax

    # -v IP_START-IP_END -p PORT_START-PORT_END -o OUTPUT
    # optionals: -v     -IP_END     -PORT_END     -o OUTPUT
    if re.match("^(-v |-V )?([0-9]{1,3}\.){3}[0-9]{1,3}(-([0-9]{1,3}\.){3}[0-9]{1,3})? -(p|P) [0-9]{1,5}((-[0-9]{1,5})|(,[0-9]{1,5})+)?( -(o|O) [0-9a-zA-Z.,{}@%_=$^~+-]+)?$", argv):
        # probably a good result here, but we need to check more about the inputs (start-range and end-range for ip and port)

        # deal with ports (start and end)
        # string array of port-start and port-end
        temp_argv = re.compile("-(p|P) [0-9]{1,5}((-[0-9]{1,5})|(,[0-9]{1,5})+)?").search(argv).group()
        temp_argv = temp_argv[3:]
        arr_ports = temp_argv.split('-')

        # split the first port to array (if the user used ips like this: 80,139,135 etc)
        # also filter duplicates (duplicated inputs in ports) like 135,135 etc
        arr_splitted_ports = arr_ports[0].split(',')

        # array of ports to string with (,)
        # also clear duplicates values
        port_output_string = ",".join(list(set(arr_splitted_ports)))

        # validate port-start
        # the port must be from 1 to 65535 max
        for ports_splits in arr_splitted_ports:
            validate_port_range(ports_splits)

        # save the port_start (could be splitted with ,) and port_end
        # also clear duplicates
        port_start = port_output_string
        port_end = 0

        # check the count of port-end (if it's 0 then there's no port-end there)
        if len(arr_ports) > 1:
            # if there's a second port (range) then we need to save it to string so we can show it later in the output
            # but first, we need to validate it (port-end)
            # the port must be from 1 to 65535 max
            validate_port_range(arr_ports[1])
            port_output_string = port_output_string + " to " + str(arr_ports[1])

            # check if portEnd is lesser than portStart (if yes then it's not good)
            if int(arr_ports[1]) < int(arr_ports[0]):
                # error, exit
                output_error()

            # save the port-end in global
            port_end = arr_ports[1]

        ########################################################
        # if we reached here, means the inputted ports are good
        ########################################################

        # deal with ip address (start and end)
        # string array of ip-start and ip_end
        arr_ips = re.findall("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", argv)

        # split the ip-start to numbers so we can easily increment it
        arr_ip_start_splits = arr_ips[0].split('.')

        # validate ip-start
        # the ip values must be between 0 to 255 (included) for each part of the ip
        # we will send to the function the 4 parts of ip splitted in array so we can validate it easily
        validate_ip_range(arr_ip_start_splits)

        # save to string (so we can display it later in the output)
        ip_output_string = arr_ips[0]

        # check the count of ip-end (if it's  0 then there's no ip-end there)
        # so we just replace the ip end with ip start
        if len(arr_ips) == 1:
            # if we reached here, means we have only 1 ip address (no range)
            # we will make the second ip = the first ip because of null
            arr_ip_end_splits = arr_ip_start_splits
        else:
            # second ip address here
            # same things goes for ip-end so we can read it
            arr_ip_end_splits = arr_ips[1].split('.')

            # first. we will need to validate ip-end
            # the ip values must be between 0 to 255 (included) for each part of the ip
            # we will send to the function the 4 parts of ip splitted in array so we can validate it easily
            validate_ip_range(arr_ip_end_splits)

            # validate the ipStart and end (the ipStart shouldn't be bigger than the end)
            # we will do it like the following formula, starting from left to right:
            # lets say for example we have this ip:
            # 192.168.20.5
            # we will calc the number of ips of it, like this:
            # 192*1000000000
            # +
            # 168*1000000
            # +
            # 20*1000
            # +
            # 5*1
            # the total of all (above)=192168020005 should be lesser than ipEnd address number
            ip_start_total = 0
            ip_end_total = 0
            ip_indexer = 1000000000

            # doing the formula here
            for i in range(4):
                ip_start_total += ip_indexer * int(arr_ip_start_splits[i])
                ip_end_total += ip_indexer * int(arr_ip_end_splits[i])
                ip_indexer /= 1000

            # if the beginning ip is greater then end ip means invalid input
            if ip_start_total > ip_end_total:
                # error, exit
                output_error()
            elif ip_end_total > ip_start_total:
                # to add the second ip to the string (note we will not add it if it's equal to the starting ip)
                # we will save the string so we can use it later for printing info on screen
                ip_output_string = ip_output_string + " to " + arr_ips[1]

        ##########################################################
        # if we reached here, means the inputs of ip+ports are ok
        ##########################################################

        # save the output string to variable (check if you used custom output)
        global the_output_file
        temp_output = re.compile("-(o|O) [0-9a-zA-Z.,{}@%_=$^~+-]+").search(argv)
        if temp_output is not None:
            the_output_file = temp_output.group()[3:]

        # save the verbose mode to string (True or False)
        if str(argv[:2]).lower() == "-v":
            # verbose mode, heavy scan (it can dig for HTTP headers)
            is_verbose_mode = True
        else:
            # quick mode
            is_verbose_mode = False

        ########################################################################
        # if we reached here, means everything looks fine and we are ready!
        ########################################################################
        # call function to deal with scanning ips / ports
        scan_ip_ports(arr_ip_start_splits, arr_ip_end_splits, port_start, port_end, ip_output_string, port_output_string, is_verbose_mode)
    else:
        # invalid input, exit
        output_error()

    return


########################################################################
# MAIN
########################################################################

# check if the user used an argument or called for help (to show menu)
if len(sys.argv) == 1 or (len(sys.argv) == 2 and (sys.argv[1] == "--h" or sys.argv[1] == "--help")):
    # call function to draw the menu
    show_menu()
else:
    # call function to deal with the input (send the args to function)
    tmp_argv = " ".join(sys.argv[1:])
    validate_input(tmp_argv)
