import re
import os
import gzip
from os import listdir, chdir, getcwd
from os.path import isfile, isdir, abspath, join

#### globals
start_dir = abspath( getcwd() )
errors_list = []
all_alerts_files = []
all_alerts_dirs = []
accepted_success_entries_list = []
ips_list_dups = []
ips_list_no_dups = []
accepted_user_re = re.compile( r"\ Accepted password\ " )
ip_re = re.compile( r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" )
accepted_ips = r"redundant ips here"

#### loop all ossec alert files, get all accepted success users, get all accepted successfull, get no duplicates ip list
def all_success_accepted_entries():
    print( "start all_success_accepted_entries()" )
    ossec_dir = abspath( "/var/ossec/logs/alerts" )
    if isdir( ossec_dir ):
        chdir( ossec_dir )
        for dir_item in listdir( ossec_dir ):
            if isfile( dir_item ) and "alert" in dir_item:
                all_alerts_files.append( dir_item )                                                 #### single out and append alerts.log file to alerts_files_list
            if isdir( dir_item ):
                all_alerts_dirs.append( dir_item )
        for alert_dir in all_alerts_dirs:
            chdir( alert_dir )
            cur_alert_dir = abspath( getcwd() )
            alerts_dir_names = listdir( cur_alert_dir )
            for alert_file_dir in alerts_dir_names:
                cur_alert_file_dir = cur_alert_dir + "/" + alert_file_dir
                cur_alerts_files = listdir( cur_alert_file_dir )
                for cur_alerts_file in cur_alerts_files:                                            #### for loop inside ossec alerts months directory
                    if "gz" in cur_alerts_file:
                        alrt_file = cur_alert_file_dir + "/" + cur_alerts_file
                        try:
                            cur_gz_alert_fh = gzip.open( alrt_file, "r" )
                            for gz_line in cur_gz_alert_fh:                                         #### loop lines in alert log gz file
                                gz_text_line = gz_line.decode()
                                accepted_user_match = accepted_user_re.search( gz_text_line )
                                if accepted_user_match:                               #### check for accepted success user entries
                                    cur_success_accepted_line = gz_text_line
                                    accepted_success_entries_list.append(  cur_success_accepted_line.strip() )
                                    ip_re_match = ip_re.search( cur_success_accepted_line )
                                    ips_list_dups.append( ip_re_match.group( 0 ) )
                        finally:
                            cur_gz_alert_fh.close()
                    elif "sum" not in cur_alerts_file:
                        alrt_file = cur_alert_file_dir + "/" + cur_alerts_file
                        try:
                            cur_alert_fh = open( alrt_file, "r" )
                            for line in cur_alert_fh:                                               #### loop lines in alert log file
                                accepted_user_match = accepted_user_re.search( line )
                                if accepted_user_match:                               #### check for accepted success user entries
                                    cur_success_accepted_line = line
                                    accepted_success_entries_list.append( cur_success_accepted_line.strip() )
                                    ip_re_match = ip_re.search( cur_success_accepted_line )
                                    ips_list_dups.append( ip_re_match.group( 0 ) )
                        finally:
                            cur_alert_fh.close()
        print( "end all_success_accepted_entries()" )
    else:
        errors_list.append( "open ossec dir error" )

####
ret_all_success_accepted_entries = all_success_accepted_entries()
ips_list_no_dups = [*set(ips_list_dups)]

####
def check_accepted_ips():
    chdir( start_dir )
    try:
        out_accepts_successes_file = open( "out_accepts_successes_ossec", "w" )
        for accept_success_line in accepted_success_entries_list:
            if accepted_ips not in accept_success_line:
                out_accepts_successes_file.write( "{0}\n".format( accept_success_line ) )
    finally:
        out_accepts_successes_file.close()

####
ret_check_accepted_ips = check_accepted_ips()

####
#print( "\n\n\nerrors: {0}".format( errors_list ) )
