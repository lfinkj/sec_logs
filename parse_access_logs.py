import os
import re
import gzip
from os import listdir, chdir, getcwd
from os.path import isfile, isdir, join, abspath

####
start_dir = abspath( getcwd() )
access_out_list = []
abnormal_requests_list = []
request_str_list = []
request_ips_list = []

####
def get_access_logs():
    print( "start get_access_logs()" )
    access_dir = abspath( "/var/log/apache2" )
    if isdir( access_dir ):
        chdir( access_dir )
        access_dir_files = listdir( access_dir )
        access_re = re.compile( r"^access" )
        for dir_file in access_dir_files:
            access_found = access_re.search( dir_file )
            if access_found:
                if "gz" in dir_file:
                    try:
                        cur_gz_file = gzip.open( dir_file, "r" )
                        for gz_line in cur_gz_file:
                            gz_line_str = gz_line.decode()
                            if "\n" not in gz_line_str or len( gz_line_str ) < 4:
                                abnormal_requests_list.append( gz_line_str )
                            else:
                                cur_gz_line_str = gz_line_str.strip()
                                cur_gz_line_str_no_pars = cur_gz_line_str.replace( "\\\"", "''" )
                                gz_line_list = cur_gz_line_str_no_pars.split( "\"" )
                                access_out_list.append( gz_line_list )
                    finally:
                        cur_gz_file.close()
                else:
                    try:
                        cur_file = open( dir_file, "r" )
                        for line in cur_file:
                            if "\"" not in line or len( line ) < 4:
                                abnormal_requests_list.append( line )
                            else:
                                cur_line = line.strip()
                                cur_line_no_pars = cur_line.replace( "\\\"", "''" )
                                line_list = cur_line_no_pars.split( "\"" )
                                access_out_list.append( line_list )
                    finally:
                        cur_file.close()
    else:
        print( "open access dir fail" )
    print( "end get_access_logs()" )

####
ret_get_access_logs = get_access_logs()

#### parse access lines
try:
    chdir( start_dir )
    out_access_lines = open( "out_access_lines", "w" )
    for entry in access_out_list:
        ip_only = entry[0].split( " - - " )
        request_ips_list.append( ip_only[0] )
        request_str_list.append( entry[1] )
        out_access_lines.write( "{0}\n".format( entry ) )
        #for item in entry:
            #out_access_lines.write( "{0}\n".format( item ) )
    for abnormal_entry in abnormal_requests_list:
        out_access_lines.write( "{0}\n".format( abnormal_entry ) )
finally:
    out_access_lines.close()

#### request strings parsing
try:
    out_request_strs = open( "out_request_strs", "w" )
    req_str_list_no_dups = [*set(request_str_list)]
    for req_str in req_str_list_no_dups:
        out_request_strs.write( "{0}        {1}\n".format( request_str_list.count( req_str ), req_str ) )
finally:
    out_request_strs.close()

#### request ips parsing
try:
    out_request_ips = open( "out_request_ips", "w" )
    request_ips_list_no_dups = [*set(request_ips_list)]
    for ip in request_ips_list_no_dups:
        out_request_ips.write( "{0}        {1}\n".format( request_ips_list.count( ip ), ip ) )
finally:
    out_request_ips.close()




####

