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
inv_users_fail_root_list = []
ip_occurences = []
ips_list_dups = []
ips_list_no_dups = []
user_names_no_dups = []
usr_names_dups = []
usr_names_no_dups = []
inv_user_name_by_ip = []
inv_user_re = re.compile( r"\ Invalid\ user\ " )
fail_root_re = re.compile( r"\:\ Failed\ password\ for\ root" )
ip_re = re.compile( r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" )
usr_name_re = re.compile( r"Invalid\ user\ .*\ from\ " )

#### loop all ossec alert files, get all invalid users, get all failed roots, get no duplicates ip list
def get_ossec_logs():
    print( "\nstart all_logs_ips()\n" )
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
                                inv_user_match = inv_user_re.search( gz_text_line )
                                fail_root_match = fail_root_re.search( gz_text_line )
                                if inv_user_match or fail_root_match:                               #### check for invalid user entries
                                    cur_inv_usr = gz_text_line
                                    inv_users_fail_root_list.append(  cur_inv_usr.strip() )
                                    ip_re_match = ip_re.search( cur_inv_usr )
                                    ips_list_dups.append( ip_re_match.group( 0 ) )                  #### append invalud users and failed roots to list
                        finally:
                            cur_gz_alert_fh.close()
                    elif "sum" not in cur_alerts_file:
                        alrt_file = cur_alert_file_dir + "/" + cur_alerts_file
                        try:
                            cur_alert_fh = open( alrt_file, "r" )
                            for line in cur_alert_fh:                                               #### loop lines in alert log file
                                inv_user_match = inv_user_re.search( line )
                                fail_root_match = fail_root_re.search( line )
                                if inv_user_match or fail_root_match:                               #### check for invalid user entries
                                    cur_inv_usr = line
                                    inv_users_fail_root_list.append( cur_inv_usr.strip() )
                                    ip_re_match = ip_re.search( cur_inv_usr )
                                    ips_list_dups.append( ip_re_match.group( 0 ) )
                        finally:
                            cur_alert_fh.close()
        print( "end all_logs_ips()\n" )
    else:
        errors_list.append( "open ossec dir error" )

####
ret_get_ossec_logs = get_ossec_logs()
ips_list_no_dups = [*set(ips_list_dups)]

#### write all invalid users and failed root entries to file
try:
    print( "start out_inv_users_fail_roots\n" )
    chdir( start_dir )
    out_inv_users_fail_root_file = open( "out_inv_users_fail_roots", "w" )
    for inv_usr in inv_users_fail_root_list:
        out_inv_users_fail_root_file.write( "{0}\n".format( inv_usr ) )
finally:
    print( "end out_inv_users_fail_roots\n" )
    out_inv_users_fail_root_file.close()

#### write ips no duplicates list to file
try:
    print( "start out_ips_no_dups\n" )
    ips_no_dups_out = open( "sinister_ips_inv_usrs_fail_roots", "w" )
    for ip in ips_list_no_dups:
        ips_no_dups_out.write( "{0}\n".format( ip ) )
finally:
    print( "end out_ips_no_dups\n" )
    ips_no_dups_out.close()

#### count occurences of ips in all ossec alert log files
print( "start out_ossec_ips_occurences\n" )
all_alerts_lines_str = ' '.join( inv_users_fail_root_list )
for cur_ip in ips_list_no_dups:
    cur_ip_cnt = all_alerts_lines_str.count( cur_ip )
    ip_occurences.append( str( cur_ip_cnt ) + "," + str( cur_ip ) )
try:
    ip_occurences_file = open( "out_ossec_ip_occurences", "w" )
    for item in ip_occurences:
        ip_occurences_file.write( "{0}\n".format( item ) )
finally:
    ip_occurences_file.close()
print( "end out_ossec_ip_occurences\n" )

#### list inv users and fail roots by ip, count failed roots
try:
    print( "start out_inv_usr_by_ip, out_fail_root_ip_counts\n" )
    out_inv_usr_by_ip_file = open( "out_inv_usr_by_ip", "w" )
    out_fail_root_ip_counts = open( "out_fail_root_ip_counts", "w" )
    for inv_usr_ip in ips_list_no_dups:
        raw_ip_str = inv_usr_ip.replace( ".", "\." )
        inv_usr_ip_re = re.compile( raw_ip_str )
        fail_root_ctr = 0
        for alert_line in inv_users_fail_root_list:
            inv_usr_ip_match = inv_usr_ip_re.search( alert_line )
            if inv_usr_ip_match:
                out_inv_usr_by_ip_file.write( "{0}\n".format( alert_line ) )
                inv_user_name_by_ip.append( alert_line )
                fail_root_match = fail_root_re.search( alert_line )
                if fail_root_match:
                    fail_root_ctr += 1                                                      #### count failed root attempts
        fail_root_ip_cnt_str = str( fail_root_ctr ) + "," + inv_usr_ip
        out_fail_root_ip_counts.write( "{0}\n".format( fail_root_ip_cnt_str ) )
finally:
    print( "end out_inv_usr_by_ip, out_fail_root_ip_counts\n" )
    out_fail_root_ip_counts.close()
    out_inv_usr_by_ip_file.close()

#### list invalid user names, count invalid user names
print( "start out_inv_user_names_counts\n" )
for usr_name_line in inv_users_fail_root_list:
    usr_name_match = usr_name_re.search( usr_name_line )
    if usr_name_match:
        usr_str = usr_name_match.group(0)[13:]
        user_name_only = usr_str.replace( " from ", "" ) 
        usr_names_dups.append( user_name_only )
all_usr_names_str = ' '.join( usr_names_dups )
for users_name in usr_names_dups:
    users_name_str = " " + users_name + " " 
    cur_user_name_count = all_usr_names_str.count( users_name_str )
    usr_names_no_dups.append( str( cur_user_name_count ) + "," + users_name )
all_user_names_no_dups = [*set(usr_names_no_dups)]
try:
    out_inv_usr_counts = open( "out_inv_user_names_counts", "w" )
    for usrname in all_user_names_no_dups:
        out_inv_usr_counts.write( "{0}\n".format( usrname ) )
finally:
    out_inv_usr_counts.close()
print( "end out_inv_user_names_counts\n" )

#### list invalid user names ip occurences
try:
    print( "start out_invalid_users_list_by_ips\n" )
    out_invalid_users_list_by_ips_file = open( "out_invalid_users_list_by_ips", "w" )
    for invalid_user_line in inv_user_name_by_ip:
        ip_addr_re_match = ip_re.search( invalid_user_line )
        invalid_user_ip_match = usr_name_re.search( invalid_user_line )
        if invalid_user_ip_match:
            invalid_user_ip_addr = ip_addr_re_match.group(0)
            tmp_usr_str = invalid_user_ip_match.group(0)[13:]
            just_usr_name = tmp_usr_str.replace( " from ", "" )
            ip_usr_write_string = just_usr_name + "," + invalid_user_ip_addr
            out_invalid_users_list_by_ips_file.write( "{0}\n".format( ip_usr_write_string ) )
finally:
    print( "end out_invalid_users_list_by_ips\n" )
    out_invalid_users_list_by_ips_file.close()

####
#print( "\n\n\nerrors: {0}".format( errors_list ) )
