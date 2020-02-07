from itty import *
import urllib2
import json
import re
import requests
from operator import itemgetter
from threatresponse import ThreatResponse

################################################  CHANGE THIS VALUES ##################################################

### WEBEXT TEAMS CHAT BOT VALUES ####
bot_email = "mybotname@webex.bot"
bot_name = "MY_BOT_NAME"
# BOT ACCESS TOKEN
bearer = "012345678ABCDEFGH"
webhook_url = 'https://MYURL.ngrok.io'
webhook_name = 'MY_WEBHOOK_NAME'
roomid_filter = 'YOUR_ROOM_ID'

### THRESHOLD FOR TG BEHAVIOURAL INDICATORS REPORTING ###
tg_severity_threshold = 75

### API KEYS TO USE ###

### UMBRELLA-INVESTIGATE API-KEY ###
investigate_token = 'xxxxxxxxxxxxxxxxxxxx'
### THREATGRID API-KEY ###
api_key = 'xxxxxxxxxxxxxxxxxxxx'
### CTR API CLIENT-ID ###
ctr_client_id = 'xxxxxxxxxxxxxxxxxxxx'
### CTR API CLIENT-PASSWORD ###
ctr_client_password = 'xxxxxxxxxxxxxxxxxxxx'

### PROTECTED NETWORK CONFIG ###
protectednet = '10.0.0.0/8'
protecteddomain = 'example.com'

#######################################################################################################################

global_targets_list = []
umbrella_categories = {}
webhook_roomid = ''
investigation_report = []
observable_types_list = []
debugflag = False # USED FOR OFF-CHAT DEBUG

regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

client = ThreatResponse(
    client_id=ctr_client_id,
    client_password=ctr_client_password,
)

def json_loads_byteified(json_text):
    return _byteify(
        json.loads(json_text, object_hook=_byteify),
        ignore_dicts=True
    )

def json_load_byteified(file_handle):
    return _byteify(
        json.load(file_handle, object_hook=_byteify),
        ignore_dicts=True
    )

def _byteify(data, ignore_dicts = False):
    if isinstance(data, unicode):
        return data.encode('utf-8')
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    return data

def check(Ip):
    if (re.search(regex, Ip)):
        return True

    else:
        return False

def sendSparkGET(url):
    request = urllib2.Request(url,
                              headers={"Accept": "application/json",
                                       "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + bearer)
    contents = urllib2.urlopen(request).read()
    return contents


def sendSparkPOST(url, data):
    request = urllib2.Request(url, json.dumps(data),
                              headers={"Accept": "application/json",
                                       "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + bearer)
    contents = urllib2.urlopen(request).read()
    return contents

@post('/')
def index(request):
    global investigation_report
    webhook = json.loads(request.body)
    print
    webhook['data']['id']
    result = sendSparkGET('https://api.ciscospark.com/v1/messages/{0}'.format(webhook['data']['id']))
    result = json.loads(result)
    msg = None
    if webhook['data']['personEmail'] != bot_email:
        in_message = result.get('text', '').lower()
        in_message = in_message.replace(bot_name.lower(), '')
        if in_message.startswith('help'):
            msg = "**How To Use:**\n- *help*, bring this help; \n- *investigate*, put your indicators in free form or with types specified explicitly (<type>:\"observable\"), types:  \n    - " + '  \n    - '.join(observable_types_list)


            sendSparkPOST("https://api.ciscospark.com/v1/messages",
                          {"roomId": webhook['data']['roomId'], "markdown": msg})
        else:
            sendSparkPOST("https://api.ciscospark.com/v1/messages",
                          {"roomId": webhook['data']['roomId'], "markdown": "*Let the investigation begin...*"})

            analyze_string_investigation(in_message)

            sendSparkPOST("https://api.ciscospark.com/v1/messages",
                              {"roomId": webhook['data']['roomId'], "markdown": "***  \n" + '  \n'.join(investigation_report) + "\n\n***"})

            sendSparkPOST("https://api.ciscospark.com/v1/messages",
                          {"roomId": webhook['data']['roomId'],
                           "markdown": "*Mission accomplished, observe my findings above...*"})
        investigation_report = []

    return "true"

def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary

def get_addr_network(address, net_size):
    #Convert ip address to 32 bit binary
    ip_bin = ip_to_binary(address)
    #Extract Network ID from 32 binary
    network = ip_bin[0:32-(32-net_size)]
    return network

def ip_in_prefix(ip_address, prefix):
    #CIDR based separation of address and network size
    [prefix_address, net_size] = prefix.split("/")
    #Convert string to int
    net_size = int(net_size)
    #Get the network ID of both prefix and ip based net size
    prefix_network = get_addr_network(prefix_address, net_size)
    ip_network = get_addr_network(ip_address, net_size)
    return ip_network == prefix_network


def webex_print(header, message):
    global investigation_report
    if debugflag:
        print(header + message.replace('\n', ''))
    investigation_report.append(header + message)

    return

def query_threatgrid(type,value):

    url = "https://panacea.threatgrid.com/api/v2/search/submissions?q=" + value +"&api_key=" + api_key + "&advanced=true"
    headers = {
        'Cache-Control': "no-cache",
        'Content-Type': "application/json",
    }

    response = requests.request("GET", url, headers=headers)
    data = json_loads_byteified(response.text)
    IOCS_list = []
    IOCS_dict = []
    for item in data['data']['items']:
        if 'analysis' in item['item']:
            if 'behaviors' in item['item']['analysis']:
                for ioc in item['item']['analysis']['behaviors']:
                    # print ioc
                    if ioc['threat'] < tg_severity_threshold:
                        continue
                    else:
                        iocfull = str(ioc['threat']) + " - " + ioc['title']
                        if iocfull not in IOCS_list:
                            IOCS_list.append(iocfull)
                            IOCS_dict.append({'threat': ioc['threat'], 'title': ioc['title']})

    sorted_d = sorted(IOCS_dict, key=itemgetter('threat'),reverse=True)
    for ioc in sorted_d:
        webex_print("- *Indicator*: ", str(ioc['threat']) + ' - ' + ioc['title'])


def get_umbrella_categories_list():

    global umbrella_categories

    url = "https://investigate.api.umbrella.com/domains/categories"

    headers = {
        'Authorization': "Bearer " + investigate_token,
        'Cache-Control': "no-cache",
    }

    response = requests.request("GET", url, headers=headers)
    umbrella_categories = json_loads_byteified(response.text)

def investigate_lookup_for_domain(domain_investigate,lastseen):
    #lastseen argument is not used in this script, function imported from another script

    headers = {
        'Authorization': "Bearer " + investigate_token,
        'Cache-Control': "no-cache",
    }

    url = "https://investigate.api.umbrella.com/domains/categorization/" + domain_investigate
    response = requests.request("GET", url, headers=headers)
    data = json_loads_byteified(response.text)
    for domain in data:
        sec_category = ""
        for cat in data[domain]['security_categories']:
            sec_category = sec_category + ", " + umbrella_categories[cat]

        content_category = ""
        for cat in data[domain]['content_categories']:
            content_category = sec_category + ", " + umbrella_categories[cat]

        status = "None"
        if str(data[domain]['status']) == "-1":
            status = "**Malicious**"
        elif str(data[domain]['status']) == "0":
            status = "Not Classified"
        elif str(data[domain]['status']) == "1":
            status = "Benign"


        if len(sec_category.strip(", "))>0 and len(content_category.strip(", "))>0:
            webex_print("- *Known hosted domain*: ", domain_investigate + " *Status:* " + status + " *SecurityCat.:* " + sec_category.strip(", ") + " *ContentCat.:* " + content_category.strip(", "))
        elif len(sec_category.strip(", "))>0:
            webex_print("- *Known hosted domain*: ",
                        domain_investigate + " *Status:* " + status + " *SecurityCat.:* " + sec_category.strip(", "))
        elif len(content_category.strip(", "))>0:
            webex_print("- *Known hosted domain*: ",
                        domain_investigate + " *Status:* " + status + " *ContentCat.:* " + content_category.strip(", "))
        else:
            webex_print("- *Known hosted domain*: ", domain_investigate + " *Status:* " + status)


def investigate_lookup_for_ip(ip_address):

    url = "https://investigate.api.umbrella.com/dnsdb/ip/a/" + ip_address + ".json"

    headers = {
        'Authorization': "Bearer " + investigate_token,
        'Cache-Control': "no-cache",
    }

    # ACTIVE DB REQUEST
    response = requests.request("GET", url, headers=headers)
    data = json_loads_byteified(response.text)

    domainlist = []
    for domain in data['rrs']:
        domain['rr'] = domain['rr'].strip('.')
        domainlist.append(domain['rr'])

    count = 0
    for domain_investigate in domainlist:
        if count > 10:
            webex_print("", '*... results limited to 10*')
            break
        count = count + 1
        investigate_lookup_for_domain(domain_investigate,'')


def analyze_string_investigation(indicators):

    global global_targets_list

    indicators_parse = client.inspect.inspect({'content': indicators})
    result_dump = json.dumps(indicators_parse)
    result_loads = json.loads(result_dump)

    for indicator in result_loads:
        webex_print("", "**[OBSERVABLE]** *Type*: " + indicator['type'] + " *Value*: " + indicator['value'] + "\n")
        response = client.enrich.observe.observables(indicators_parse)
        result_dump = json.dumps(response)
        if debugflag:
            print result_dump
        result_loads = json.loads(result_dump)

        for module in result_loads['data']:
            if module['module'] == 'Private Intelligence':
                continue
            webex_print("", "\n**[" + module['module'] + "]**" + "\n")

            if "verdicts" in module['data']:
                for doc in module['data']['verdicts']['docs']:
                    webex_print("- *Verdict*: ", doc['disposition_name'])
            if "judgements" in module['data']:
                judgement_list = []
                for doc in module['data']['judgements']['docs']:
                    comment = ''
                    if 'reason' in doc:
                        comment = doc['reason']
                    elif 'source' in doc:
                        comment = doc['source']
                    string_event = doc['disposition_name'] + ' -> ' + comment
                    if string_event not in judgement_list:
                        judgement_list.append(string_event)
                count = 0
                for judgement in judgement_list:
                    if count > 10:
                        webex_print("", '*... results limited to 10*')
                        break
                    count = count + 1
                    webex_print("- *Judgements*: ", judgement)
            if "indicators" in module['data']:
                count = 0
                for doc in module['data']['indicators']['docs']:
                    if count > 10:
                        webex_print("", '*... results limited to 10*')
                        break
                    count = count + 1
                    if 'short_description' in doc:
                        description = doc['short_description']
                    else:
                        description = doc['description']
                    webex_print("- *Indicator*: ", description)

            # SIGHTINGS FOR OTHER
            if module['module'] == 'Firepower' or module['module'] == 'Private Intelligence' or module[
                'module'] == 'Stealthwatch Enterprise' or module['module'] == 'VirusTotal':
                if 'sightings' in module['data']:
                    count = 0
                    for doc in module['data']['sightings']['docs']:
                        if count > 10:
                            webex_print("", '*... results limited to 10*')
                            break
                        count = count + 1
                        source = ''
                        destination = ''
                        if 'short_description' in doc:
                            description = doc['short_description']
                        else:
                            description = doc['description']
                        webex_print("- *Sighting*: ", description)
                        if 'relations' in doc:
                            count_1 = 0
                            for relation in doc['relations']:
                                if count_1 > 10:
                                    webex_print("", '*... results limited to 10*')
                                    break
                                count_1 = count_1 + 1
                                if 'source' in relation:
                                    source = relation['source']['value']
                                    if module['module'] != 'VirusTotal' and check(source):
                                        if ip_in_prefix(source, protectednet) and source not in global_targets_list:
                                            global_targets_list.append(source)
                                if 'related' in relation:
                                    destination = relation['related']['value']
                                    if module['module'] != 'VirusTotal' and check(destination):
                                        if ip_in_prefix(destination,
                                                        protectednet) and destination not in global_targets_list:
                                            global_targets_list.append(destination)
                                webex_print("       - *Connection*: ", source + " -> " + destination)
            # SIGHTINGS FOR AMP4E
            if module['module'] == 'AMP for Endpoints':
                if 'sightings' in module['data']:
                    targets_list = []
                    targets_list_dicts = []
                    for doc in module['data']['sightings']['docs']:
                        if 'targets' in doc:
                            for target in doc['targets']:
                                hostname = ""
                                ip = ""
                                mac = ""
                                if 'observables' in target:
                                    for observable in target['observables']:
                                        if observable['type'] == 'hostname':
                                            hostname = observable['value']
                                        if observable['type'] == 'mac_address':
                                            mac = observable['value']
                                        if observable['type'] == 'ip':
                                            ip = observable['value']
                                    if hostname not in targets_list:
                                        targets_list.append(hostname)
                                        targets_list_dicts.append({'hostname': hostname, 'ip': ip, 'mac': mac})
                                        if hostname not in global_targets_list:
                                            if len(ip)>0:
                                                ipaddress = "(" + ip + ")"
                                            else:
                                                ipaddress = ''
                                            global_targets_list.append(hostname + ipaddress)
                    for target in targets_list_dicts:
                        webex_print("- *Target*: ",
                                    "Hostname: " + target['hostname'] + " IP: " + target['ip'] + " MAC: " + target[
                                        'mac'])

            # SIGHTINGS FOR ESA
            if module['module'] == 'SMA Email':
                if 'sightings' in module['data']:
                    targets_list = []
                    for doc in module['data']['sightings']['docs']:
                        if 'relations' in doc:
                            srcip = ''
                            fromaddr = ''
                            toaddr = ''
                            mid = ''
                            subject = ''
                            for relation in doc['relations']:

                                if 'ip' in relation['source']['type']:
                                    srcip = relation['source']['value']
                                if 'email' in relation['source']['type']:
                                    fromaddr = relation['source']['value']
                                if 'cisco_mid' in relation['source']['type']:
                                    mid = relation['source']['value']
                                if 'email_subject' in relation['related']['type']:
                                    subject = relation['related']['value']
                                if 'email' in relation['related']['type']:
                                    toaddr = relation['related']['value']
                            webex_print("- *Sighting*: ",
                                        "SRC IP: " + srcip + " From: " + fromaddr + " MID: " + mid + " To: " + toaddr + " Subject: " + subject)
                            if fromaddr not in targets_list and fromaddr.find(protecteddomain) != -1:
                                targets_list.append(fromaddr)
                                if fromaddr not in global_targets_list:
                                    global_targets_list.append(fromaddr)

                            if toaddr not in targets_list and toaddr.find(protecteddomain) != -1:
                                targets_list.append(toaddr)
                                if toaddr not in global_targets_list:
                                    global_targets_list.append(toaddr)

            if module['module'] == 'Threat Grid':
                query_threatgrid(indicator['type'],indicator['value'])

            if module['module'] == 'Umbrella':
                if indicator['type'] == 'ip':
                    investigate_lookup_for_ip(indicator['value'])


    webex_print("", '\n**[All Targets]**\n')
    for target in global_targets_list:
        webex_print('',"- " + target)
    global_targets_list = []

def delete_webhook(webhook_id):

    url = "https://api.ciscospark.com/v1/webhooks/" + webhook_id

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + bearer
    }

    response = requests.request("DELETE", url, headers=headers, data=payload)

def add_webhook():

    url = "https://api.ciscospark.com/v1/webhooks"
    payload = "{\"name\": \"" + webhook_name + "\",\"targetUrl\": \"" + webhook_url + "\",\"resource\": \"messages\",\"event\": \"created\",\"filter\": \"roomId=" + roomid_filter + "\"}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + bearer
    }

    response = requests.request("POST", url, headers=headers, data=payload)

def update_webhook():

    url = "https://api.ciscospark.com/v1/webhooks"
    payload = "{\"name\": \"" + webhook_name + "\",\"targetUrl\": \"" + webhook_url + "\",\"status\": \"active\"}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + bearer
    }

    response = requests.request("PUT", url, headers=headers, data=payload)

def delete_room(room_id):
    # DOES NOT DELETE 1-to-1 ROOMS
    url = "https://api.ciscospark.com/v1/rooms/" + room_id
    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + bearer
    }

    response = requests.request("DELETE", url, headers=headers, data=payload)
    print "    === ROOM DELETED ==="

def get_bot_status():

    url = "https://api.ciscospark.com/v1/rooms"

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + bearer
    }

    response = requests.request("GET", url, headers=headers, data=payload)
    data = json_loads_byteified(response.text)
    print "Bot is currently member of Webex Rooms:"
    if 'items' in data:
        for room in data['items']:
            print " => Title: " + room['title'].encode('utf8')
            print "    " + " ID: " + room['id']
            if room['id'] != roomid_filter:
                delete_room(room['id'])


    url = "https://api.ciscospark.com/v1/webhooks"
    response = requests.request("GET", url, headers=headers, data=payload)
    data = json_loads_byteified(response.text)
    print "Bot is currently configured with webhooks:"
    if 'items' in data:
        for webhook in data['items']:
            print " => ID: " + webhook['id']
            print "    " + "Name: " + webhook['name'].encode('utf8')
            print "    " + "Url: " + webhook['targetUrl']
            print "    " + "Status: " + webhook['status']

            if webhook['name'].encode('utf8') != webhook_name:
                delete_webhook(webhook['id'])
                print "    === REMOVED ==="
            if webhook['status'].encode('utf8') != 'active':
                update_webhook()
                print "    === STATUS UPDATED ==="
            if webhook['filter'] != 'roomId=' + roomid_filter:
                delete_webhook(webhook['id'])
                print "    === REMOVED ==="
                add_webhook()
                print "    === ADDED WEBHOOK ==="

def main():

    get_bot_status() #PRE-START-CHECKUP

    global observable_types_list

    observable_types='file_path, mac_address, device, hostname, url, user, ipv6, email, sha256, sha1, md5, ip, domain, email_subject, imei, amp_computer_guid, cisco_mid, pki_serial, imsi, amp-device, file_name'
    observable_types_list = observable_types.replace(' ','').split(",")

    get_umbrella_categories_list()

    if debugflag:
        indicators = raw_input("Indicators: ")
        analyze_string_investigation(indicators)
        print('  \n'.join(investigation_report))

    run_itty(server='wsgiref', host='0.0.0.0', port=3000)

if __name__== "__main__":
  main()