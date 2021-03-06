from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import ssl
import re
import sys
import math
import requests
import numpy
import mdmail
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from operator import itemgetter
from threatresponse import ThreatResponse
from config import *

progress_msg_id = ""
progress_msg_text = ""
global_targets_list = []
umbrella_categories = {}
webhook_roomid = ''
investigation_report = []
observable_types_list = []
umbrella_module = True

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# USED FOR OFF-LINE DEBUG
debug_flag = False

regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

client = ThreatResponse(
    client_id=ctr_client_id,
    client_password=ctr_client_password,
)

retry_strategy = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
http = requests.Session()
http.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
})
http.mount("https://", adapter)
http.mount("http://", adapter)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        global investigation_report
        webhook = json.loads(body)
        result = send_spark_get('https://api.ciscospark.com/v1/messages/{0}'.format(webhook['data']['id'])).text
        result = json.loads(result)
        if webhook['data']['personEmail'] != bot_email:
            in_message = result.get('text', '').lower()
            in_message = in_message.replace(bot_name.lower(), '')
            if in_message.startswith('help'):
                msg = "**How To Use:**\n- *help*, bring this help; \n- *investigate*, put your indicators in free " \
                      "form or with types specified explicitly (<type>:\"observable\"), types:  " \
                      "\n    - " + '  \n    - '.join(observable_types_list)

                send_spark_post("https://api.ciscospark.com/v1/messages",
                                {"roomId": webhook['data']['roomId'], "markdown": msg})
            else:
                send_spark_post("https://api.ciscospark.com/v1/messages",
                                {"roomId": webhook['data']['roomId'], "markdown": "*Let the investigation begin...*  "})

                analyze_string_investigation(in_message)

                send_spark_post("https://api.ciscospark.com/v1/messages",
                                {"roomId": webhook['data']['roomId'],
                                 "markdown": "***  \n" + '  \n'.join(investigation_report) + "\n\n***"})
                if enable_email == True:
                    print('Sending Email Report!')
                    mdmail.send("***  \n" + '  \n'.join(investigation_report) + "\n\n***", subject='Sherlok Report',
                                from_email=mail_from, to_email=mail_to, smtp=smtp)

                send_spark_post("https://api.ciscospark.com/v1/messages",
                                {"roomId": webhook['data']['roomId'],
                                 "markdown": "*Mission accomplished, observe my findings above...*"})
            investigation_report = []

        return "true"


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

def _byteify(data, ignore_dicts=False):
    if type(data) == 'str':
        return data.encode('utf-8')
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.items()
        }
    return data


def check(ip):
    if re.search(regex, ip):
        return True

    else:
        return False


def send_spark_get(url):
    headers = {
        'Authorization': "Bearer " + bearer,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    response = http.get(url, headers=headers)
    return response


def send_spark_post(url, data):

    global progress_msg_id

    payload = json.dumps(data).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        "Accept": "application/json",
        'Authorization': 'Bearer ' + bearer
    }

    if sys.getsizeof(payload) > 7200:
        print('ByteSize: ' + str(sys.getsizeof(payload)) + ' MSG too large, splitting!')
        listpayload = json.dumps(data['markdown']).split('\\n')
        array_of_msgs = numpy.array_split(listpayload, math.ceil(sys.getsizeof(payload)/7200))
        for msg_array in array_of_msgs:
            send_spark_post(url, {"roomId": roomid_filter,
                                 "markdown": '\n'.join(msg_array).strip('"')})

    else:
        response = http.post(url, headers=headers, data=payload)
        if 'text' in json.loads(response.text):
            if json.loads(response.text)['text'] == 'Let the investigation begin...':
                progress_msg_id = json.loads(response.text)['id']

        print("POST => Code: " + str(response.status_code) + ' Length: ' + str(len(payload)) + ' ByteSize: ' + str(sys.getsizeof(payload)))
        # if int(response.status_code) >=400:
        #     print(response.text)
        # else:
        #     print('MSGCode: ' + json.loads(response.text)['id'])
        if 'id' in json.loads(response.text):
            return response.text, json.loads(response.text)['id']
        else:
            return response.text, ''

def send_spark_put(url, data):

    global progress_msg_id

    payload = json.dumps(data).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        "Accept": "application/json",
        'Authorization': 'Bearer ' + bearer
    }

    response = http.put(url, headers=headers, data=payload)
    print("PUT => Code: " + str(response.status_code) + ' Length: ' + str(len(payload)) + ' ByteSize: ' + str(
        sys.getsizeof(payload)))
    return response.text, response.status_code

def update_progress_msg(new_msg):

    global progress_msg_id
    global progress_msg_text

    if (progress_msg_id != ''):
        url = "https://api.ciscospark.com//v1/messages/" + progress_msg_id

        data = json_loads_byteified(send_spark_get(url).text)
        progress_msg_text = data['markdown'] + '\n' + new_msg

        response, status_code = send_spark_put(url, {"roomId": roomid_filter, "markdown": progress_msg_text})
        if int(status_code) >= 400:
            url = 'https://api.ciscospark.com/v1/messages'
            response, progress_msg_id = send_spark_post(url, {"roomId": roomid_filter, "markdown": progress_msg_text})
        # print(response)

def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = "".join(octet_list_bin)
    return binary


def get_addr_network(address, net_size):
    # Convert ip address to 32 bit binary
    ip_bin = ip_to_binary(address)
    # Extract Network ID from 32 binary
    network = ip_bin[0:32-(32-net_size)]
    return network


def ip_in_prefix(ip_address, prefix):
    # CIDR based separation of address and network size
    [prefix_address, net_size] = prefix.split("/")
    # Convert string to int
    net_size = int(net_size)
    # Get the network ID of both prefix and ip based net size
    prefix_network = get_addr_network(prefix_address, net_size)
    ip_network = get_addr_network(ip_address, net_size)
    return ip_network == prefix_network

def webex_print(header, message):
    global investigation_report
    if debug_flag:
        print(header + message.replace('\n', ''))
    investigation_report.append(header + message)
    return


# noinspection PyTypeChecker
def query_threatgrid(type, value):

    url = "https://panacea.threatgrid.com/api/v2/search/submissions?q=" + value + "&api_key=" + api_key
    headers = {
        'Cache-Control': "no-cache",
        'Content-Type': "application/json",
    }

    response = http.get(url, headers=headers)

    data = json_loads_byteified(response.text)
    iocs_list = []
    iocs_dict = []
    for item in data['data']['items']:
        if 'analysis' in item['item']:
            if 'behaviors' in item['item']['analysis']:
                for ioc in item['item']['analysis']['behaviors']:
                    # print ioc
                    if ioc['threat'] < tg_severity_threshold:
                        continue
                    else:
                        iocfull = str(ioc['threat']) + " - " + ioc['title']
                        if iocfull not in iocs_list:
                            iocs_list.append(iocfull)
                            iocs_dict.append({'threat': ioc['threat'], 'title': ioc['title']})

    sorted_d = sorted(iocs_dict, key=itemgetter('threat'), reverse=True)
    count = 0
    for ioc in sorted_d:
        if count > 10:
            webex_print("", '*... results limited to 10*')
            break
        count = count + 1
        webex_print("- *Indicator* for " + value + ' => ', str(ioc['threat']) + ' - ' + ioc['title'])


def get_umbrella_categories_list():

    global umbrella_categories

    url = "https://investigate.api.umbrella.com/domains/categories"

    headers = {
        'Authorization': "Bearer " + investigate_token,
        'Cache-Control': "no-cache",
    }

    response = http.get(url, headers=headers)
    if response.status_code > 400:
        print("ERROR: Invalid Umbrella Investigate token! Disabling Umbrella Queries!")
        umbrella_module = False
        # exit()
    else:
        umbrella_categories = json_loads_byteified(response.text)


# noinspection PyTypeChecker
def investigate_lookup_for_domain(domain_investigate, lastseen):
    # lastseen argument is not used in this script, function imported from another script
    headers = {
        'Authorization': "Bearer " + investigate_token,
        'Cache-Control': "no-cache",
    }

    url = "https://investigate.api.umbrella.com/domains/categorization/" + domain_investigate
    response = http.get(url, headers=headers)
    data = json_loads_byteified(response.text)
    for domain in data:
        sec_category = ""
        for cat in data[domain]['security_categories']:
            sec_category += ", " + umbrella_categories[cat]

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

        if lastseen == '':
            if len(sec_category.strip(", ")) > 0 and len(content_category.strip(", ")) > 0:
                webex_print("- *Known hosted domain*: ", domain_investigate + " *Status:* " + status + " *SecurityCat.:* " + sec_category.strip(", ") + " *ContentCat.:* " + content_category.strip(", "))
            elif len(sec_category.strip(", ")) > 0:
                webex_print("- *Known hosted domain*: ",
                            domain_investigate + " *Status:* " + status + " *SecurityCat.:* " + sec_category.strip(", "))
            elif len(content_category.strip(", ")) > 0:
                webex_print("- *Known hosted domain*: ",
                            domain_investigate + " *Status:* " + status + " *ContentCat.:* " + content_category.strip(", "))
            else:
                webex_print("- *Known hosted domain*: ", domain_investigate + " *Status:* " + status)
        else:
            if len(sec_category.strip(", ")) > 0 and len(content_category.strip(", ")) > 0:
                webex_print("- *Known hosted domain*: ", domain_investigate + " *Status:* " + status + " *SecurityCat.:* " + sec_category.strip(", ") + " *ContentCat.:* " + content_category.strip(", ") + " *LastSeen.:* " + lastseen)
            elif len(sec_category.strip(", ")) > 0:
                webex_print("- *Known hosted domain*: ",
                            domain_investigate + " *Status:* " + status + " *SecurityCat.:* " + sec_category.strip(", ")  + " *LastSeen.:* " + lastseen)
            elif len(content_category.strip(", ")) > 0:
                webex_print("- *Known hosted domain*: ",
                            domain_investigate + " *Status:* " + status + " *ContentCat.:* " + content_category.strip(", ")  + " *LastSeen.:* " + lastseen)
            else:
                webex_print("- *Known hosted domain*: ", domain_investigate + " *Status:* " + status  + " *LastSeen.:* " + lastseen)


def investigate_lookup_for_ip(ip_address):

    url = "https://investigate.api.umbrella.com/dnsdb/ip/a/" + ip_address + ".json"

    headers = {
        'Authorization': "Bearer " + investigate_token,
        'Cache-Control': "no-cache",
    }
    querystring = {"recordType": "NS,MX,A,CNAME"}

    # ACTIVE DB REQUEST
    response = http.get(url, headers=headers)
    data = json_loads_byteified(response.text)
    webex_print("", '**Active DNS DB for:** ' + ip_address)

    domain_list = []
    for domain in data['rrs']:
        domain['rr'] = domain['rr'].strip('.')
        domain_list.append(domain['rr'])

    count = 0
    for domain_investigate in domain_list:
        if count > 10:
            webex_print("", '*... results limited to 10*')
            break
        count += 1
        if umbrella_module == True:
            investigate_lookup_for_domain(domain_investigate, '')

    #PDNS REQUEST
    url = "https://investigate.api.umbrella.com/pdns/ip/" + ip_address

    response = http.get(url, headers=headers, params=querystring)
    data = json_loads_byteified(response.text)

    pdomainlist = {}
    for domain in data['records']:
        domain['rr'] = domain['rr'].strip('.')
        pdomainlist[domain['rr']] = domain['lastSeenISO']

    for domain in domain_list:
        if domain in pdomainlist.keys():
            pdomainlist.pop(domain)


    if len(pdomainlist) > 0:
        webex_print("", '**Passive DNS DB for :** ' + ip_address)

    count = 0
    for domain,lastseen in pdomainlist.items():
        if count > 10:
            webex_print("", '*... results limited to 10*')
            break
        count += 1
        if umbrella_module == True:
            investigate_lookup_for_domain(domain, lastseen)

# noinspection PyTypeChecker
def analyze_string_investigation(indicators):

    global global_targets_list
    update_progress_msg('  * Sending CTR Request. Please wait..  ')
    indicators_parse = client.inspect.inspect({'content': indicators})
    result_dump = json.dumps(indicators_parse)
    result_indicator_loads = json.loads(result_dump)
    for indicator in result_indicator_loads:
        webex_print("", "**[OBSERVABLE]** *Type*: " + indicator['type'] + " *Value*: " + indicator['value'] + "\n")

    # for indicator in result_loads:
    response = client.enrich.observe.observables(indicators_parse)
    result_dump = json.dumps(response)

    if debug_flag:
        print(result_dump)
    result_loads = json.loads(result_dump)

    for module in result_loads['data']:
        update_progress_msg('  * Analyzing module: ' + module['module'] + '  ')
        if module['module'] == 'Private Intelligence':
            continue
        webex_print("", "\n**[" + module['module'] + "]**" + "\n")

        if "verdicts" in module['data']:
            for doc in module['data']['verdicts']['docs']:
                webex_print("- *Verdict* for " + doc['observable']['value'] + ' => ', doc['disposition_name'])
        if "judgements" in module['data']:
            judgement_list = []
            for doc in module['data']['judgements']['docs']:
                comment = ''
                if 'reason' in doc:
                    comment = doc['reason']
                elif 'source' in doc:
                    comment = doc['source']
                string_event = doc['observable']['value'] + ' => ' + doc['disposition_name'] + ' (' + comment + ')'
                if string_event not in judgement_list:
                    judgement_list.append(string_event)
            count = 0
            for judgement in judgement_list:
                if count > 10:
                    webex_print("", '*... results limited to 10*')
                    break
                count += 1
                webex_print("- *Judgements*: ", judgement)
        if "indicators" in module['data']:
            count = 0
            indicators_list = []
            for doc in module['data']['indicators']['docs']:
                if count > 10:
                    webex_print("", '*... results limited to 10*')
                    break
                count += 1
                if 'short_description' in doc:
                    description = doc['short_description']
                else:
                    description = doc['description']
                if description not in indicators_list:
                    indicators_list.append(description)
                for indicator_item in indicators_list:
                    webex_print("- *Indicator*: ", indicator_item)

        # SIGHTINGS FOR OTHER
        if module['module'] == 'Firepower' or module['module'] == 'Private Intelligence' or module['module'] == 'Stealthwatch Enterprise' or module['module'] == 'VirusTotal':
            if 'sightings' in module['data']:
                count = 0
                for doc in module['data']['sightings']['docs']:
                    if count > 10:
                        webex_print("", '*... results limited to 10*')
                        break
                    count += 1
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
                            count_1 += 1
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
                relations = []
                for doc in module['data']['sightings']['docs']:
                    if 'targets' in doc:
                        hostname = ""
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
                                        if len(ip) > 0:
                                            ip_address = "(" + ip + ")"
                                        else:
                                            ip_address = ''
                                        global_targets_list.append(hostname + ip_address)
                        if 'relations' in doc:
                            for relation in doc['relations']:
                                if {'hostname': hostname, 'relation': relation['relation'], 'source': relation['source']['value'], 'related': relation['related']['value']} not in relations:
                                    relations.append({'hostname': hostname, 'relation': relation['relation'], 'source': relation['source']['value'], 'related': relation['related']['value']})
                for target in targets_list_dicts:
                    webex_print("- *Target*: ",
                                "Hostname: " + target['hostname'] + " IP: " + target['ip'] + " MAC: " + target[
                                    'mac'])
                    for relation in relations:
                        if relation['hostname'] == target['hostname']:
                            webex_print("  - *Sighting*: ", relation['relation'] + ' src: ' + relation['source'] + ' related: ' + relation['related'])

        # SIGHTINGS FOR ESA
        if module['module'] == 'SMA Email':
            if 'sightings' in module['data']:
                targets_list = []
                for doc in module['data']['sightings']['docs']:
                    if 'relations' in doc:
                        src_ip = ''
                        from_address = ''
                        to_address = ''
                        mid = ''
                        subject = ''
                        for relation in doc['relations']:
                            if 'ip' in relation['source']['type']:
                                src_ip = relation['source']['value']
                            if 'email' in relation['source']['type']:
                                from_address = relation['source']['value']
                            if 'cisco_mid' in relation['source']['type']:
                                mid = relation['source']['value']
                            if 'email_subject' in relation['related']['type']:
                                subject = relation['related']['value']
                            if 'email' in relation['related']['type']:
                                to_address = relation['related']['value']

                        webex_print("- *Sighting*: ",
                                    "SRC IP: " + src_ip + " From: " + from_address + " MID: " + mid + " To: " + to_address + " Subject: " + subject)

                        if from_address not in targets_list and from_address.find(protecteddomain) != -1:
                            targets_list.append(from_address)
                            if from_address not in global_targets_list:
                                global_targets_list.append(from_address)

                        if to_address not in targets_list and to_address.find(protecteddomain) != -1:
                            targets_list.append(to_address)
                            if to_address not in global_targets_list:
                                global_targets_list.append(to_address)

        if module['module'] == 'AMP File Reputation':
            for indicator in result_indicator_loads:
                update_progress_msg('    * ThreatGrid direct query for ' + indicator['value'])
                query_threatgrid(indicator['type'], indicator['value'])

        if module['module'] == 'Umbrella':
            for indicator in result_indicator_loads:
                if indicator['type'] == 'ip':
                    if umbrella_module == True:
                        update_progress_msg('    * Umbrella direct query for ' + indicator['value'])
                        investigate_lookup_for_ip(indicator['value'])
                if indicator['type'] == 'domain':
                    if umbrella_module == True:
                            update_progress_msg('    * Umbrella direct query for ' + indicator['value'])
                            investigate_lookup_for_domain(indicator['value'], '')

    webex_print("", '\n**[All Targets]**\n')

    for target in global_targets_list:
        webex_print('', "- " + target)
    global_targets_list = []


def delete_webhook(webhook_id):

    url = "https://api.ciscospark.com/v1/webhooks/" + webhook_id

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + bearer
    }

    http.delete(url, headers=headers, data=payload)


def add_webhook():

    url = "https://api.ciscospark.com/v1/webhooks"
    payload = "{\"name\": \"" + webhook_name + "\",\"targetUrl\": \"" + webhook_url + "\",\"resource\": \"messages\",\"event\": \"created\",\"filter\": \"roomId=" + roomid_filter + "\"}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + bearer
    }

    response = http.post(url, headers=headers, data=payload)
    print(response)


def update_webhook():

    url = "https://api.ciscospark.com/v1/webhooks"
    payload = "{\"name\": \"" + webhook_name + "\",\"targetUrl\": \"" + webhook_url + "\",\"status\": \"active\"}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + bearer
    }

    requests.request("PUT", url, headers=headers, data=payload)


def delete_room(room_id):
    # DOES NOT DELETE 1-to-1 ROOMS
    url = "https://api.ciscospark.com/v1/rooms/" + room_id
    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + bearer
    }

    response = http.delete(url, headers=headers, data=payload)
    # print(response.status_code)
    # print(response.content)
    if (response.status_code >= 400):
        print("    === ROOM DELETE FAILED => ", json.loads(response.text)['message'])
    else:
        print("    === ROOM DELETED ===")

def delete_membership(membership_id):
    # DOES NOT DELETE 1-to-1 Direct Chats
    url = "https://api.ciscospark.com/v1/memberships/" + membership_id
    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + bearer
    }

    response = http.delete(url, headers=headers, data=payload)
    # print(response.status_code)
    # print(response.text)
    # print(json.loads(response.text)['message'])
    if (response.status_code >= 400):
        print("    === MEMBERSHIP DELETE FAILED => ", json.loads(response.text)['message'])
    else:
        print("    === MEMBERSHIP DELETED ===")

def get_bot_status():

    # Get Sherloks personal details:
    url = "https://api.ciscospark.com/v1/people/me"

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + bearer
    }

    response = http.get(url, headers=headers, data=payload)
    data = json_loads_byteified(response.text)
    print("Sherloks personId is:", data['id'])
    sherloks_personid = data['id']

    # Get Sherloks membersip details:

    url = "https://api.ciscospark.com/v1/memberships"

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + bearer,
        'personId': sherloks_personid
    }

    response = http.get(url, headers=headers, data=payload)
    data = json_loads_byteified(response.text)
    print("Removing unneeded memberships")
    if 'items' in data:
        for membership in data['items']:
            if membership['roomId'] != roomid_filter and membership['roomType'] != 'direct':
                delete_membership(membership['id'])

    url = "https://api.ciscospark.com/v1/rooms"

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + bearer
    }

    response = http.get(url, headers=headers, data=payload)
    data = json_loads_byteified(response.text)
    print("Bot is currently member of Webex Rooms (Can't remove direct rooms):")
    if 'items' in data:
        for room in data['items']:
            if room['id'] != roomid_filter:
                print(" => Title: {}".format(room['title'].encode('utf8')))
            else:
                print(" => Title: {} <= CURRENT WORKROOM".format(room['title'].encode('utf8')))
            if room['id'] != roomid_filter and room['type'] != 'direct':
                delete_room(room['id'])

    url = "https://api.ciscospark.com/v1/webhooks"
    response = http.get(url, headers=headers, data=payload)
    data = json_loads_byteified(response.text)
    print("Bot is currently configured with webhooks:")
    if 'items' in data:
        for webhook in data['items']:
            print(" => ID: {}".format(webhook['id']))
            print("     Name: {}".format(webhook['name'].encode('utf8')))
            print("     Url: {}".format(webhook['targetUrl']))
            print("     Status: {}".format(webhook['status']))

            if webhook['name'] != webhook_name:
                print("    === REMOVING WEBHOOK ===")
                delete_webhook(webhook['id'])
                print("    === REMOVED ===")
            if webhook['status'] != 'active':
                print("    === UPDATING WEBHOOK STATUS ===")
                update_webhook()
                print("    === STATUS UPDATED ===")
            # if (webhook['filter'] != 'roomId=' + roomid_filter) or (webhook['targetUrl'] != webhook_url):
            if webhook['targetUrl'] != webhook_url:
                print("    === DELETING WEBHOOK ===")
                delete_webhook(webhook['id'])
                print("    === REMOVED ===")
                print("    === ADDING WEBHOOK ===")
                add_webhook()
                print("    === ADDED WEBHOOK ===")

        if len(data['items']) == 0:
            print("    === NO WEBHOOKS DETECTED ===")
            add_webhook()
            print("    === ADDED WEBHOOK ===")


def main():

    get_bot_status()  # PRE-START-CHECKUP

    global observable_types_list

    observable_types = 'file_path, mac_address, device, hostname, url, user, ipv6, email, sha256, sha1, md5, ip, domain, email_subject, imei, amp_computer_guid, cisco_mid, pki_serial, imsi, amp-device, file_name'
    observable_types_list = observable_types.replace(' ', '').split(",")

    get_umbrella_categories_list()

    if debug_flag:
        indicators = input(r"Indicators: ")
        analyze_string_investigation(indicators)
        print('  \n'.join(investigation_report))

    httpd = HTTPServer(('localhost', 3000), SimpleHTTPRequestHandler)
    httpd.serve_forever()


if __name__== "__main__":
    main()
