from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request as urllib2
import json
import ssl
import re
import requests
from operator import itemgetter
from threatresponse import ThreatResponse
from config import *

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

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        global investigation_report
        webhook = json.loads(body)
        result = send_spark_get('https://api.ciscospark.com/v1/messages/{0}'.format(webhook['data']['id']))
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
                                {"roomId": webhook['data']['roomId'], "markdown": "*Let the investigation begin...*"})

                analyze_string_investigation(in_message)

                send_spark_post("https://api.ciscospark.com/v1/messages",
                                {"roomId": webhook['data']['roomId'],
                                 "markdown": "***  \n" + '  \n'.join(investigation_report) + "\n\n***"})

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
    request = urllib2.Request(url,
                              headers={"Accept": "application/json",
                                       "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + bearer)
    contents = urllib2.urlopen(request, context=ctx).read()
    return contents


def send_spark_post(url, data):
    request = urllib2.Request(url, json.dumps(data).encode('utf-8'),
                              headers={"Accept": "application/json",
                                       "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + bearer)
    contents = urllib2.urlopen(request, context=ctx).read()
    return contents


def index(request):
    global investigation_report
    print(request)
    webhook = json.loads(request.body)
    result = send_spark_get('https://api.ciscospark.com/v1/messages/{0}'.format(webhook['data']['id']))
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
                            {"roomId": webhook['data']['roomId'], "markdown": "*Let the investigation begin...*"})

            analyze_string_investigation(in_message)

            send_spark_post("https://api.ciscospark.com/v1/messages",
                            {"roomId": webhook['data']['roomId'], "markdown": "***  \n" + '  \n'.join(investigation_report) + "\n\n***"})

            send_spark_post("https://api.ciscospark.com/v1/messages",
                            {"roomId": webhook['data']['roomId'],
                           "markdown": "*Mission accomplished, observe my findings above...*"})
        investigation_report = []

    return "true"


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

    url = "https://panacea.threatgrid.com/api/v2/search/submissions?q=" + value + "&api_key=" + api_key + "&advanced=true"
    headers = {
        'Cache-Control': "no-cache",
        'Content-Type': "application/json",
    }

    response = requests.request("GET", url, headers=headers)
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
    response = requests.request("GET", url, headers=headers)
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


def investigate_lookup_for_ip(ip_address):

    url = "https://investigate.api.umbrella.com/dnsdb/ip/a/" + ip_address + ".json"

    headers = {
        'Authorization': "Bearer " + investigate_token,
        'Cache-Control': "no-cache",
    }

    # ACTIVE DB REQUEST
    response = requests.request("GET", url, headers=headers)
    data = json_loads_byteified(response.text)

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


# noinspection PyTypeChecker
def analyze_string_investigation(indicators):

    global global_targets_list

    indicators_parse = client.inspect.inspect({'content': indicators})
    result_dump = json.dumps(indicators_parse)
    result_loads = json.loads(result_dump)

    for indicator in result_loads:
        webex_print("", "**[OBSERVABLE]** *Type*: " + indicator['type'] + " *Value*: " + indicator['value'] + "\n")
        response = client.enrich.observe.observables(indicators_parse)
        result_dump = json.dumps(response)
        if debug_flag:
            print(result_dump)
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
                    count += 1
                    webex_print("- *Judgements*: ", judgement)
            if "indicators" in module['data']:
                count = 0
                for doc in module['data']['indicators']['docs']:
                    if count > 10:
                        webex_print("", '*... results limited to 10*')
                        break
                    count += 1
                    if 'short_description' in doc:
                        description = doc['short_description']
                    else:
                        description = doc['description']
                    webex_print("- *Indicator*: ", description)

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
                                            if len(ip) > 0:
                                                ip_address = "(" + ip + ")"
                                            else:
                                                ip_address = ''
                                            global_targets_list.append(hostname + ip_address)
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

            if module['module'] == 'Threat Grid':
                query_threatgrid(indicator['type'], indicator['value'])

            if module['module'] == 'Umbrella':
                if indicator['type'] == 'ip':
                    if umbrella_module == True:
                        investigate_lookup_for_ip(indicator['value'])

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

    requests.request("DELETE", url, headers=headers, data=payload)


def add_webhook():

    url = "https://api.ciscospark.com/v1/webhooks"
    payload = "{\"name\": \"" + webhook_name + "\",\"targetUrl\": \"" + webhook_url + "\",\"resource\": \"messages\",\"event\": \"created\",\"filter\": \"roomId=" + roomid_filter + "\"}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + bearer
    }

    response = requests.request("POST", url, headers=headers, data=payload)
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

    requests.request("DELETE", url, headers=headers, data=payload)
    print("    === ROOM DELETED ===")


def get_bot_status():

    url = "https://api.ciscospark.com/v1/rooms"

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + bearer
    }

    response = requests.request("GET", url, headers=headers, data=payload)
    data = json_loads_byteified(response.text)
    print("Bot is currently member of Webex Rooms:")
    if 'items' in data:
        for room in data['items']:
            print(" => Title: {}".format(room['title'].encode('utf8')))
            print("     ID: {}".format(room['id']))
            if room['id'] != roomid_filter:
                delete_room(room['id'])

    url = "https://api.ciscospark.com/v1/webhooks"
    response = requests.request("GET", url, headers=headers, data=payload)
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
            if (webhook['filter'] != 'roomId=' + roomid_filter) or (webhook['targetUrl'] != webhook_url):
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
