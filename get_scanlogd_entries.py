import os
import re
import gzip
from os import listdir, chdir, getcwd
from os.path import isfile, isdir, abspath, join

start_dir = abspath( getcwd() )
scanlogd_ip_list = []
scanlogd_re = re.compile( r"scanlogd" )
ip_re = re.compile( r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" )
####
def get_scanlogd_entries():
    syslog_dir = abspath( "/var/log/" )
    if isdir( syslog_dir ):
        chdir( syslog_dir )
        for file in listdir( getcwd() ):
            if "syslog" in file:
                if "gz" in file:
                    try:
                        syslog_gz_fh = gzip.open( file, "r" )
                        for gz_line in syslog_gz_fh:
                            gz_line_str = gz_line.decode()
                            scanlogd_search = scanlogd_re.search( gz_line_str )
                            ip_search = ip_re.search( gz_line_str )
                            if scanlogd_search and ip_search:
                                scanlogd_ip_list.append( ip_search.group( 0 ) )
                    finally:
                        syslog_gz_fh.close()
                else:
                    try:
                        syslog_fh = open( file, "r" )
                        for line in syslog_fh:
                            scanlogd_search = scanlogd_re.search( line )
                            ip_search = ip_re.search( line )
                            if scanlogd_search and ip_search:
                                scanlogd_ip_list.append( ip_search.group( 0 ) )
                    finally:
                        syslog_fh.close()
    else:
        print( "syslog dir open fail" )

####
ret_get_scanlogd_entries = get_scanlogd_entries()

####
try:
    chdir( start_dir )
    out_scanlogd_entries = open( "sinister_ips_scanlogd", "w" )
    for ip in scanlogd_ip_list:
        out_scanlogd_entries.write( "{0}\n".format( ip ) )
finally:
    out_scanlogd_entries.close()
