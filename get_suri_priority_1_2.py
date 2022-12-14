import os
import re
from os import listdir, chdir, getcwd
from os.path import isfile, isdir, join, abspath

####
start_dir = abspath( getcwd() )
priority_3_re = re.compile( r"Priority: 3" )
priority_3_list = []
priority_1_re = re.compile( r"Priority: 1" )
priority_2_re = re.compile( r"Priority: 2" )
priorities_list = []
ip_re = re.compile( r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" )
priorities_ips_list = []
priorities_ips_list_nodups = []

####
def get_suri_priorities():
    print( "start get_suri_priorities()" )
    suricata_dir = abspath( "/var/log/suricata/" )
    if isdir( suricata_dir ):
        chdir( suricata_dir )
        try:
            fast_file = open( "fast.log", "r" )
            for line in fast_file:
                priority_3_search = priority_3_re.search( line )
                if priority_3_search:
                    priority_3_list.append( line )
                priority_1_search = priority_1_re.search( line )
                priority_2_search = priority_2_re.search( line )
                if priority_1_search or priority_2_search:
                    priorities_list.append( line )
                    priorities_ips_search = ip_re.search( line )
                    if priorities_ips_search:
                        priorities_ips_list.append( priorities_ips_search.group( 0 ) )
        finally:
            fast_file.close()
    else:
        print( "open suricata dir fail" )
    print( "end get_suri_priorities()" )

####
ret_get_suri_priorities = get_suri_priorities()

####
try:
    priorities_ips_list_nodups = [*set(priorities_ips_list)]
    chdir( start_dir )
    out_suri_priorities_1_2 = open( "sinister_ips_suri_priorities_1_2", "w" )
    for ip in priorities_ips_list_nodups:
        out_suri_priorities_1_2.write( "{0}\n".format( ip ) )
finally:
    out_suri_priorities_1_2.close()

####

