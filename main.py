from flask import Flask, request, render_template 
from functions import *

app = Flask(__name__)


@app.route("/shodan")
def shodan_render():
   return render_template('shodan.html')

@app.route("/whois")
def whois_render():
   return render_template('whois.html')

@app.route("/domain")
def domain_render():
   return render_template('domain.html')

@app.route("/malscan")
def analysis_render():
   return render_template('viruscheck.html')





@app.route("/whois_scan", methods=["POST"])
def who_is():
   data = request.get_json()
   addr = data.get("addr")
   return whois_query(addr)

@app.route("/shodan_scan", methods=["POST"])
def run_shodan():
   data = request.get_json()
   IP = data.get("IP")
   return shodan_query(IP)

@app.route("/domain_scan", methods=["POST"])
def domain():
   data = request.get_json()
   domain = data.get("domain")
   return domain_query(domain)

@app.route("/malware_scan", methods=["POST"])
def malscan():
   data = request.get_json()
   link = data.get("link")
   return malware_scan(link)


if __name__ == '__main__':
    app.run(debug=True)

   