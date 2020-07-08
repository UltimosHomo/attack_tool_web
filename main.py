from flask import Flask, render_template, request
import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
from lib import attack
import socket


IP_PLC = '192.168.127.1'
app = Flask(__name__)


@app.route('/')
def show_home_page():
    return render_template('index.html', log=read_log())


@app.route('/update/plc_ip', methods=['POST', 'GET'])
def update_plc_ip():
    global IP_PLC
    if request.method == 'GET':
        return IP_PLC
    elif request.method == 'POST':
        try:
            socket.inet_aton(request.form['ip'])
            IP_PLC = request.form['ip']
            logger.info('[Settings: PLC address changed] ' + IP_PLC)
            return IP_PLC
        except socket.error:
            return IP_PLC


@app.route('/status/plc', methods=['GET'])
def return_status_plc():
    status_plc = attack.plc_status_check(IP_PLC)
    return status_plc


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
    logger.info('[Modbus attack: Disable] ' + attack.mb_stop(IP_PLC))
    logger.info('[Modbus attack: Disable] DONE')
    return render_template('index.html')


@app.route('/attack/plc/modbus/disrupt', methods=['POST'])
def execute_modbus_disrupt():
    logger.info('[Modbus attack: Disrupt] ' + attack.mb_disrupt(IP_PLC))
    logger.info('[Modbus attack: Disrupt] DONE')
    return render_template('index.html')


@app.route('/attack/plc/modbus/restore', methods=['POST'])
def execute_modbus_restore():
    logger.info('[Modbus attack: Restore] ' + attack.mb_restore(IP_PLC))
    logger.info('[Modbus attack: Restore] DONE')
    return render_template('index.html')


@app.route('/attack/dos/tcp-syn', methods=['POST'])
def execute_dos_tcp_syn():
    logger.info('[DoS attack: TCP Syn] ' + attack.dos_syn(IP_PLC))
    logger.info('[DoS attack: TCP Syn] DONE')
    return render_template('index.html')


@app.route('/attack/dos/tcp-xmas', methods=['POST'])
def execute_dos_tcp_xmas():
    logger.info('[DoS attack: TCP Xmas] ' + attack.dos_xmas(IP_PLC))
    logger.info('[DoS attack: TCP Xmas] DONE')
    return render_template('index.html')


@app.route('/attack/malware/eicar', methods=['POST'])
def execute_malware_eicar():
    logger.info('[Malware: EICAR] Sending EICAR malware test packet to target'
                + attack.malware_eicar(IP_PLC))
    logger.info('[Malware: EICAR] DONE')
    return render_template('index.html')


@app.route('/attack/malware/passwd', methods=['POST'])
def execute_malware_passwd():
    logger.info('[Malware: Steal password] Trying to retrieve password from target'
                + attack.malware_passwd(IP_PLC))
    logger.info('[Malware: Steal password] DONE')
    return render_template('index.html')


@app.route('/attack/cve/2015-5374', methods=['POST'])
def execute_cve_2015_5374():
    logger.info('[Exploit: CVE-2015-5374] Exploiting Siemens SIPROTEC 4 and SIPROTEC Compact EN100 Ethernet Module '
                '< V4.25' + attack.cve_2015_5374(IP_PLC))
    logger.info('[Exploit: CVE-2015-5374] DONE')
    return render_template('index.html')


@app.route('/attack/cve/2014-0750', methods=['POST'])
def execute_cve_2014_0705():
    logger.info('[Exploit: CVE-2014-0750] Exploiting GE Proficy CIMPLICITY HMI - Remote Code Execution'
                + attack.cve_2014_0750(IP_PLC))
    logger.info('[Exploit: CVE-2014-0750] DONE')
    return render_template('index.html')


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
