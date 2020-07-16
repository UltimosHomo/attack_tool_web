from flask import Flask, render_template, request, jsonify
import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
from lib import attack
from lib import goose
import socket


IP_TARGET = '192.168.127.1'
app = Flask(__name__)


@app.route('/')
def show_default_page():
    return render_template('plc-lt.html')


@app.route('/plc-lt')
def show_plc_lt_page():
    return render_template('plc-lt.html')


@app.route('/plc-conveyor')
def show_plc_conveyor_page():
    return render_template('plc-conveyor.html')


@app.route('/ied')
def show_ied_page():
    return render_template('ied.html')


@app.route('/scada')
def show_scada_page():
    return render_template('scada.html')


@app.route('/update/target', methods=['POST', 'GET'])
def update_plc_ip():
    global IP_TARGET
    if request.method == 'GET':
        return IP_TARGET
    elif request.method == 'POST':
        try:
            socket.inet_aton(request.form['ip'])
            IP_TARGET = request.form['ip']
            logger.info('[Settings: Target address changed] ' + IP_TARGET)
            return "OK"
        except socket.error:
            return IP_TARGET


@app.route('/status/plc', methods=['GET'])
def return_status_plc():
    status_plc = attack.plc_status_check(IP_TARGET)
    return status_plc


@app.route('/status/ping', methods=['GET'])
def return_status_ied1():
    status_ied1 = attack.ping_status_check(IP_TARGET)
    return status_ied1


@app.route('/status/log', methods=['GET'])
def read_log():
    with open("attack.log", "r") as file:
        file_content = file.readlines()
        log_content = ''
        for line in range(len(file_content)):
            log_content += file_content[-(line+1)] + "<br>"
            if line > 29:
                break
    return log_content


@app.route('/attack/plc/modbus/disable', methods=['POST'])
def execute_modbus_disable():
    logger.info('[Modbus attack: Disable] ' + attack.mb_stop(IP_TARGET))
    return 'OK'


@app.route('/attack/plc/modbus/disrupt', methods=['POST'])
def execute_modbus_disrupt():
    logger.info('[Modbus attack: Disrupt] ' + attack.mb_disrupt(IP_TARGET))
    return 'OK'


@app.route('/attack/plc/modbus/restore', methods=['POST'])
def execute_modbus_restore():
    logger.info('[Modbus attack: Restore] ' + attack.mb_restore(IP_TARGET))
    return 'OK'


@app.route('/attack/dos/tcp-syn', methods=['POST'])
def execute_dos_tcp_syn():
    logger.info('[DoS attack: TCP Syn] ' + IP_TARGET + " " + attack.dos_syn(IP_TARGET))
    return 'OK'


@app.route('/attack/dos/tcp-xmas', methods=['POST'])
def execute_dos_tcp_xmas():
    logger.info('[DoS attack: TCP Xmas] ' + IP_TARGET + " " + attack.dos_xmas(IP_TARGET))
    return 'OK'


@app.route('/attack/malware/eicar', methods=['POST'])
def execute_malware_eicar():
    logger.info('[Malware: EICAR] Sending EICAR malware test packet to target ' + IP_TARGET + " "
                + attack.malware_eicar(IP_TARGET))
    return 'OK'


@app.route('/attack/malware/passwd', methods=['POST'])
def execute_malware_passwd():
    logger.info('[Malware: Steal password] Trying to retrieve password from target ' + IP_TARGET + " "
                + attack.malware_passwd(IP_TARGET))
    return 'OK'


@app.route('/attack/cve/2015-5374', methods=['POST'])
def execute_cve_2015_5374():
    logger.info('[Exploit: CVE-2015-5374] Exploiting Siemens SIPROTEC 4 and SIPROTEC Compact EN100 Ethernet Module '
                '< V4.25' + attack.cve_2015_5374(IP_TARGET))
    return 'OK'


@app.route('/attack/cve/2014-0750', methods=['POST'])
def execute_cve_2014_0705():
    logger.info('[Exploit: CVE-2014-0750] Exploiting GE Proficy CIMPLICITY HMI - Remote Code Execution '
                + attack.cve_2014_0750(IP_TARGET))
    return 'OK'


@app.route('/attack/ied/goose/trip', methods=['POST'])
def execute_goose_trip():
    logger.info('[GOOSE: Trip] Sending trip command to IED '
                + goose.ref620_trip())
    return 'OK'


def init_log():
    global logger
    log_handler = ConcurrentRotatingFileHandler('attack.log', maxBytes=10000, backupCount=3)
    log_format = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    log_handler.setFormatter(log_format)
    logger = logging.getLogger("Attack_log")
    logger.setLevel(logging.INFO)
    logger.addHandler(log_handler)


if __name__ == "__main__":
    init_log()
    app.run()
    # app.run(debug=True)
