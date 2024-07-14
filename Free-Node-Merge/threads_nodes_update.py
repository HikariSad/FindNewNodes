import os
import threading

import requests
import json
import base64
import re
import concurrent.futures
import time
import platform
import subprocess
from bs4 import BeautifulSoup

from cls import LocalFile, SubConvert, StrText, IpAddress
import os, sys, socket, struct, select

lock = threading.Lock()
regetflag = len(sys.argv) >= 2 and sys.argv[1].lower() == 'true'
socket.setdefaulttimeout(6)
# 配置
sub_url_arry = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription1",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription2",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription3",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription4",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription5",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription6",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription7",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription8",
    "https://jiang.netlify.app",
]

merged_link = []

# 逐条读取链接，并生成CLASH国外订阅链接
errnode = ''
clashurl = ''
openclashurl = ''
clash_node_url = ''
proxies_url = ''
clashname = ''
telename = ''
nodecount = 0
datecont = time.strftime('%m-%d', time.localtime(time.time()))

v2ry_nodes = ''


# 下载订阅链接并合并
def select_sub_urls(sub_url_arry):
    sub_links = []
    for i in range(len(sub_url_arry)):
        sub_url = sub_url_arry[i]
        try:
            rq = requests.get(sub_url, timeout=(20, 100))
            if (rq.status_code != 200):
                print("[GET Code {}] Download sub error on link: ".format(rq.status_code) + sub_url)
                continue
            print("Get node link on sub " + sub_url)
            try:
                if type(rq.content) == bytes:
                    sub_links.append(base64.b64decode(rq.content).decode("utf-8"))
                elif type(rq.content) == str:
                    sub_links.append(rq.content)
            except Exception as e:
                sub_links.append(rq.content.decode('utf-8'))
                # sub_links.append( rq.content)
                print(e)

        except Exception as e:
            print("[Unknown Error] Download sub error on link: " + sub_url)
            print(e)
    return sub_links


## 选择节点
def select_nodes(url):
    # 逐条读取链接，并进行测试
    country_count = {}

    for j in url.split():
        try:
            # if (j.find("vmess://") == -1):
            #     continue
            node = json.loads(base64.b64decode(j[8:]).decode("utf-8"))
            rq = requests.get("http://ip-api.com/json/{}?lang=zh-CN".format(node['add']))
            ip_info = json.loads(rq.content)
            if (ip_info['status'] != 'success'):
                continue

                # ping测试
            if (ping(ip_info['query'])):
                print("[ping {}测试结果：成功]", ip_info['query'])

            else:
                print("[ping {}测试结果：失败]", ip_info['query'])
                continue
            ip_country = ip_info['country']
            if (country_count.__contains__(ip_country)):
                country_count[ip_country] += 1
            else:
                country_count[ip_country] = 1
            newname = "{} {} {}".format(ip_country,
                                        (str)(country_count[ip_country] // 10) + (str)(
                                            country_count[ip_country] % 10),
                                        re.split(',| ', ip_info['org'])[0])
            print("Rename node {} to {}".format(node['ps'], newname))
            node['ps'] = newname
            merged_link.append(node)
        except:
            print("[Unknown Error]")

    # print(merged_link)
    return merged_link


def ping(host, count=4):
    # 设置系统的ping命令参数
    if platform.system() == "Windows":
        cmd = ['ping', '-n', str(count), host]
    else:
        cmd = ['ping', '-c', str(count), host]
    """
    ip为要ping的ip
    """
    data = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if data.returncode == 0:
        print(f"{host}:up")
        return True
    else:
        print(f"{host}:down")
        return False


def portOpen(ip, portstr):
    port = int(portstr)
    print('\033[1m*Port\033[0m %s:%d' % (ip, port)),
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.shutdown(2)
        print(f'{ip}:{port}\033[1;32m.... is OK.\033[0m')
        return True
    except  Exception as e:
        print(e)
        print(f'{ip}:{port}\033[1;31m.... is down!!!\033[0m')
        return False


def write(sub_links):
    # 合并整理完成的节点
    tmp = ""
    for i in sub_links:
        # bs = "vmess://" + base64.b64encode(json.dumps(i).encode("utf-8")).decode("utf-8")
        tmp = tmp + i + '\n'
    res = base64.b64encode(tmp.encode("utf-8"))
    # print(res.decode("utf-8"))
    _file = open('./o/allnode.txt', 'w', encoding='utf-8')
    _file.write(res.decode("utf-8"))
    _file.close()


def write_v2ry_nodes():
    global v2ry_nodes
    # 转换节点
    res = base64.b64encode(v2ry_nodes.encode("utf-8"))
    print(res.decode("utf-8"))
    _file = open('./o/v2ry_nodes.txt', 'w', encoding='utf-8')
    _file.write(res.decode("utf-8"))
    _file.close()


def node_handler(j):
    global clashurl
    global openclashurl
    global clash_node_url
    global proxies_url
    global clashname
    global telename
    global nodecount
    global datecont
    global errnode
    global v2ry_nodes
    try:
        # 获取锁
        with lock:
            nodestr = j + ''
            # 完成添加节点数后，其他节点链接则忽略
            if (nodecount < 160):
                onenode = ''
                cipher = ''
                # j = 'ssr://dHctMi5naXRvLmNjOjMzNDA1OmF1dGhfYWVzMTI4X21kNTphZXMtMjU2LWNmYjp0bHMxLjJfdGlja2V0X2F1dGg6T1dsbVlYTjAvP2dyb3VwPVUxTlNVSEp2ZG1sa1pYSSZyZW1hcmtzPTVyS3o1WTJYNTV5QjZhbTc2YW1zNWJxWDViaUNMWFIzTFRJdVoybDBieTVqWXc9PSZvYmZzcGFyYW09NzctOWEtLV92ZS1fdlRjMTc3LTk3Ny05TU8tX3ZXcnZ2NzEzYm14dlotLV92WGRwYm1ydnY3MTNlZS1fdlhMdnY3MTI3Ny05NzctOWIyMCZwcm90b3BhcmFtPTc3LTkyN252djczdnY3MTY3Ny05R3UtX3ZlLV92ZS1fdlE='
                # j = 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpHIXlCd1BXSDNWYW9AMTYyLjI1MS42MS4yMjE6ODA0'
                # print('Main-Line-654-j-' + str(nodecount) + '-j-' + j)
                server = ''
                port = ''
                if (j.find("vmess://") == 0):
                    j = SubConvert.check_url_v2ray_vmess(j)
                    j = base64.b64decode(j[8:].encode('utf-8')).decode('utf-8')
                    node = json.loads(j)
                    # oldname = node['ps']
                    newname = node['ps']
                    cipher = node['scy']
                    onenode = SubConvert.v2ray_vmess_to_clash(j)
                    server = node['add']
                    port = node['port']
                elif (j.find("ss://") == 0):
                    onenode = SubConvert.url_ss_to_json(j)
                    if (onenode != ''):
                        node = json.loads(onenode)
                        cipher = node['cipher']
                        if (cipher == 'ss'):
                            errnode = errnode + '\n' + j + '\n' + onenode
                            onenode = ''
                            newname = ''
                        password = node['password'].replace('<', '').replace('>', '').replace('!', '')
                        server = node['server']
                        port = node['port']
                        oldname = node['name']
                        newname = '[' + datecont + ']-' + IpAddress.get_country(server) + '-' + str(
                            nodecount).zfill(3) + '-' + server
                        # 格式一
                        # onenode = '- cipher: ' + cipher + '\n  name: \'' + newname + '\'\n  password: ' + password + '\n  server: ' + server + '\n  port: ' + str(port) + '\n  type: ss'
                        # 格式二
                        onenode = '  - {name: \'' + newname + '\', cipher: ' + cipher + ', password: ' + password + ', server: ' + server + ', port: ' + str(
                            port) + ', type: ss}'
                    else:
                        errnode = errnode + '\n' + j + '\n' + onenode
                        onenode = ''
                        newname = ''
                elif (j.find("trojan://") == 0):
                    # trojan://28d98f761aca9d636f44db62544628eb@45.66.134.219:443#%f0-45.66.134.219
                    # trojan://ee4fff2a-540e-4ac7-a16a-935567dfc36b@guoxiangdang.com:995?flow=xtls-rprx-origin&security=tls&sni=SNI&alpn=h2%2Chttp%2F1.1&type=tcp&headerType=none&host=host.com#aiguoxiangdang.com
                    if (j.find('#') == -1):
                        j = j + '#'
                    oldname = j.split("#", 1)[1]
                    password = StrText.get_str_btw(j, "trojan://", "@", 0).replace('<', '').replace('>', '')
                    server = StrText.get_str_btw(j, "@", ":", 0)
                    cipher = 'none'  # trojan无cipher
                    if (server.find('@') > -1):
                        server = server.split('@')[1]
                    newname = '[' + datecont + ']-' + IpAddress.get_country(server) + '-' + str(
                        nodecount).zfill(3) + '-' + server
                    if (j.find("?") > -1):
                        port = StrText.get_str_btw(StrText.get_str_btw(j, "@", "#", 0), ":", "?", 0)
                    else:
                        port = StrText.get_str_btw(j, "@", "#", 0).split(":", 1)[1]
                    if (port.isnumeric() and password != '' and password != 'null'):
                        # 格式一
                        onenode = '- name: \'' + newname + '\'\n  type: trojan\n  server: ' + server + '\n  port: ' + str(
                            port) + '\n  password: ' + password
                        if (j.find('?') > -1):
                            tmpstr = StrText.get_str_btw(j, "?", "#", 0) + '&'
                            if (j.find("sni=") > -1):
                                onenode = onenode + '\n  sni: ' + StrText.get_str_btw(tmpstr, "sni=", "&", 0)
                            onenode = onenode + '\n  tls: true'
                            onenode = onenode + '\n  allowInsecure: true'
                            if (j.find("type=") > -1):
                                onenode = onenode + '\n  netword: ' + StrText.get_str_btw(tmpstr, "type=", "&",
                                                                                          0)
                            if (j.find("host=") > -1):
                                onenode = onenode + '\n  host: ' + StrText.get_str_btw(tmpstr, "host=", "&", 0)
                            if (j.find("path=") > -1):
                                onenode = onenode + '\n  path: ' + StrText.get_str_btw(tmpstr, "path=", "&", 0)
                            if (j.find("encryption=") > -1):
                                onenode = onenode + '\n  encryption: ' + StrText.get_str_btw(tmpstr,
                                                                                             "encryption=", "&",
                                                                                             0)
                            if (j.find("plugin=") > -1):
                                onenode = onenode + '\n  plugin: ' + StrText.get_str_btw(tmpstr, "plugin=", "&",
                                                                                         0)
                            if (j.find("headerType=") > -1):
                                onenode = onenode + '\n  headerType: ' + StrText.get_str_btw(tmpstr,
                                                                                             "headerType=", "&",
                                                                                             0)
                            if (j.find("peer=") > -1):
                                onenode = onenode + '\n  peer: ' + StrText.get_str_btw(tmpstr, "peer=", "&", 0)
                            if (j.find("tfo=") > -1):
                                onenode = onenode + '\n  tfo: ' + StrText.get_str_btw(tmpstr, "tfo=", "&", 0)
                            if (j.find("alpn=") > -1):
                                alpn = StrText.get_str_btw(tmpstr, "tfo=", "&", 0).replace('%2C', ',').replace(
                                    '%2F', '/') + ','
                                onenode = onenode + '\n  alpn: '
                                for ia in alpn.split(','):
                                    if (ia != ''):
                                        onenode = onenode + ia + ','
                            onenode = onenode + '\n  skip-cert-verify: true'
                            onenode = onenode.strip(',')

                        # 格式二
                        # trojan://Ty33ylFA4u6A5e0NE3wRFp3DIa8lZOzC87CeKnxYgpSOSa2ZaXBjDDSY9qCcxR@45.64.22.55:443?security=tls&sni=flowery.meijireform.com&type=tcp&headerType=none
                        onenode = 'name: \'' + newname + '\', server: ' + server + ', port: ' + str(
                            port) + ', type: trojan, password: ' + password
                        if (j.find('?') > -1):
                            tmpstr = StrText.get_str_btw(j, "?", "#", 0) + '&'
                            # if (j.find("allowInsecure=") > -1):
                            #    if(StrText.get_str_btw(tmpstr, "allowInsecure=", "&", 0) == '1'):
                            #        onenode = onenode + ', skip-cert-verify: true'
                            #    else:
                            #        onenode = onenode + ', skip-cert-verify: false'

                            # "network": "tcp",
                            # "security": "tls",
                            # "tlsSettings": {
                            # "allowInsecure": true,
                            # "serverName": "flowery.meijireform.com"
                            # }
                            # , network: tcp, true: tls, allowInsecure: true, sni: flowery.meijireform.com
                            if (j.find("sni=") > -1):
                                onenode = onenode + ', sni: ' + StrText.get_str_btw(tmpstr, "sni=", "&", 0)
                            if (j.find("flow=") > -1):
                                onenode = onenode + ', flow: ' + StrText.get_str_btw(tmpstr, "flow=", "&", 0)
                            onenode = onenode + ', tls: true'  # + StrText.get_str_btw(tmpstr, "security=", "&", 0).replace('tls', 'true')
                            if (j.find("type=") > -1):
                                onenode = onenode + ', netword: ' + StrText.get_str_btw(tmpstr, "type=", "&", 0)
                            if (j.find("host=") > -1):
                                onenode = onenode + ', host: ' + StrText.get_str_btw(tmpstr, "host=", "&", 0)
                            if (j.find("path=") > -1):
                                onenode = onenode + ', path: ' + StrText.get_str_btw(tmpstr, "path=", "&", 0)
                            if (j.find("encryption=") > -1):
                                onenode = onenode + ', encryption: ' + StrText.get_str_btw(tmpstr,
                                                                                           "encryption=", "&",
                                                                                           0)
                            if (j.find("plugin=") > -1):
                                onenode = onenode + ', plugin: ' + StrText.get_str_btw(tmpstr, "plugin=", "&",
                                                                                       0)
                            if (j.find("headerType=") > -1):
                                onenode = onenode + ', headerType: ' + StrText.get_str_btw(tmpstr,
                                                                                           "headerType=", "&",
                                                                                           0)
                            if (j.find("peer=") > -1):
                                onenode = onenode + ', peer: ' + StrText.get_str_btw(tmpstr, "peer=", "&", 0)
                            if (j.find("tfo=") > -1):
                                onenode = onenode + ', tfo: ' + StrText.get_str_btw(tmpstr, "tfo=", "&", 0)
                            if (j.find("alpn=") > -1):
                                alpn = StrText.get_str_btw(tmpstr, "tfo=", "&", 0).replace('%2C', ',').replace(
                                    '%2F', '/') + ','
                                onenode = onenode + ', alpn: ' + alpn
                        if (onenode.find('skip-cert-verify:') == -1):
                            onenode = onenode + ', skip-cert-verify: false'
                        else:
                            onenode = onenode + ', skip-cert-verify: ' + StrText.get_str_btw(tmpstr,
                                                                                             "skip-cert-verify=",
                                                                                             "&", 0)
                        if (onenode.find('udp:') == -1):
                            onenode = onenode + ', udp: true'
                        onenode = '  - {' + onenode + '}'
                elif (j.find("ssr://") == 0):
                    # ssr://ip:port:protocol:method:blending:password/?obfsparam=&protoparam=&group=&remarks=remarks
                    # 159.65.1.189:5252:auth_sha1_v4:rc4-md5:http_simple:NTJzc3IubmV0/?obfsparam=&protoparam=&group=d3d3LnNzcnNoYXJlLmNvbQ&remarks=remarks
                    # 159.65.1.189:33099:origin:rc4-md5:http_simple:SGRzcndF/?obfsparam=ZG93bmxvYWQud2luZG93c3VwZGF0ZS5jb20&protoparam=&remarks=6Ziy5aSx5pWIZ2l0aHViLmNvbS9MZW9uNDA2IOS4reWbvS3pppnmuK8gSUVQTCBFcXVpbml4IEhLOCBDIDAxIDFHYnBzIE5ldGZsaXggSEJPIFRWQg&group=
                    # j = 'ssr://c2h6enpoay5ldWNkdXJsLm1lOjU2MTphdXRoX2FlczEyOF9tZDU6Y2hhY2hhMjAtaWV0ZjpwbGFpbjpiV0pzWVc1ck1YQnZjblEvP3JlbWFya3M9OEorSHB2Q2ZoN1l0NUxpSzVyVzM1YmlDTFhOb2VucDZhR3N1WlhWalpIVnliQzV0WlE9PSZwcm90b3BhcmFtPU5ERTNOVFU2Y1RFek5ETXpPREF4TXpJMiZvYmZzcGFyYW09Jmdyb3VwPWFIUjBjSE02THk5Mk1uSmhlWE5sTG1OdmJR'
                    onenode = StrText.get_str_base64(j[6:])
                    onenode = base64.b64decode(onenode).decode('utf-8')
                    node = onenode.split('/?')[0].split(':')
                    server = node[0]
                    port = node[1]
                    protocol = node[2]
                    cipher = node[3]
                    http_simple = node[4]
                    password = StrText.get_str_base64(node[5])
                    password = base64.b64decode(password).decode('utf-8').replace('<', '').replace('>', '')
                    remarks = ''
                    newname = '[' + datecont + ']-' + IpAddress.get_country(server) + '-' + str(
                        nodecount).zfill(3) + '-' + server
                    if (onenode.find('remarks=') > -1):
                        remarks = StrText.get_str_base64(
                            StrText.get_str_btw((onenode + '&'), 'remarks=', '&', 0))
                        # remarks = base64.b64decode(remarks).decode('utf-8')
                    protoparam = ''
                    if (onenode.find('protoparam=') > -1):
                        protoparam = StrText.get_str_base64(
                            StrText.get_str_btw((onenode + '&'), 'protoparam=', '&', 0))
                        # protoparam = base64.b64decode(protoparam).decode('utf-8')
                    obfsparam = ''
                    if (onenode.find('obfsparam=') > -1):
                        obfsparam = StrText.get_str_base64(
                            StrText.get_str_btw((onenode + '&'), 'obfsparam=', '&', 0))
                        # obfsparam = base64.b64decode(obfsparam).decode('utf-8')
                    group = ''
                    if (onenode.find('group=') > -1):
                        group = StrText.get_str_base64(StrText.get_str_btw((onenode + '&'), 'group=', '&', 0))
                        group = base64.b64decode(group).decode('utf-8')
                        if (group == 'null'):
                            group = ''

                    # 格式一
                    # onenode = '- name: \'' + remarks + '\'\n  server: ' + server + '\n  port: ' + str(port) + '\n  protocol: ' + protocol + '\n  cipher: ' + cipher + '\n  obfs: ' + http_simple + '\n  obfs-param: ' + obfsparam + '\n  password: ' + password + '\n  protocol-param: ' + protoparam + '\n  group: ' + group + '\n  type: ssr'
                    # 格式二
                    # - {name: "linkthink.app", server: dg-hk-node02.linkthink.app, port: 12025, type: ssr, cipher: dummy, password: e5opjuLDEQ, protocol: origin, obfs: http_post, protocol-param: "", obfs-param: ajax.microsoft.com, udp: true}
                    # onenode = '  - {name: \'' + newname + '\', server: ' + server + ', port: ' + str(port) + ', type: ssr, cipher: ' + cipher + ', password: ' + password + ', protocol: ' + protocol + ', obfs: ' + http_simple + ', obfs-param: ' + obfsparam + ', protocol-param: ' + protoparam + ', group: ' + group + '}'
                    onenode = '  - {name: \'' + newname + '\', server: ' + server + ', port: ' + str(
                        port) + ', type: ssr, cipher: ' + cipher + ', password: ' + password + ', protocol: ' + protocol + ', obfs: ' + http_simple + '}'
                else:
                    # print('Main-Line-723-已跳过-onenode:\n' + j)
                    return

                # 过滤无效和重复节点
                if (onenode != '' and newname != '' and clashurl.find(onenode) == -1 and clashname.find(
                        newname) == -1):

                    # Clash的cipher不支持则忽略
                    allcipher = 'chacha20-ietf xchacha20'
                    allcipher = allcipher.upper()
                    if (allcipher.find(cipher.upper()) > -1):
                        # LocalFile.write_LogFile(
                        #     'Main-Line-799-allcipher.find(cipher.upper())-j:' + j + '\ncipher:' + cipher)
                        print(f'第{nodecount}个不满足条件')
                        return
                    if (newname.find(u'省') > -1 or newname.find(u'上海') > -1 or newname.find(
                            u'北京') > -1 or newname.find(u'重庆') > -1 or newname.find(u'内蒙') > -1):
                        return
                    # ping 测试

                    # ping测试   portOpen(server, port)
                    # if ping(server):
                    if portOpen(server, port):
                        print(f"[ping {server}:{port}测试结果：成功]")

                    else:
                        print(f"[ping {server}:{port}测试结果：失败]")
                        return

                    nodecount = nodecount + 1
                    clashname = clashname + '  - \'' + newname + '\'\n'
                    clashurl = clashurl + onenode + '\n'
                    # openclashurl = openclashurl + onenode + '\n  udp: true\n'
                    # openclashurl = openclashurl + onenode[:-1] + ', udp: true}\n'
                    openclashurl = openclashurl + onenode + '\n'
                    clash_node_url = clash_node_url + '\n' + onenode.replace('  - {', '  - {"').replace('"',
                                                                                                        '').replace(
                        '\'', '').replace(': ', '": "').replace(', ', '", "').replace('}', '"}')
                    if (newname.find('伊朗') == -1 and newname.find(u'中非') == -1):
                        telename = telename + '  - \'' + newname + '\'\n'
                        proxies_url = proxies_url + onenode + '\n'
                    # print('Main-Line-740-已添加-onenode:\n' + onenode)
                    print(f'添加第{nodecount}个节点,{newname}:{server}')

                    v2ry_nodes = v2ry_nodes + nodestr + '\n'
                else:
                    print('')
                    # print('Main-Line-742-已过滤-newname:' + newname + '-clashurl.find(onenode):' + str( clashurl.find(onenode)) + '-clashname.find(newname):' + str(  clashname.find(newname)) + '\nonenode:' + onenode + '\n')
            else:
                print('\n[保留' + str(nodecount) + '条节点，忽略多余节点]:' + j)
    except Exception as ex:
        print(ex)
        #LocalFile.write_LogFile('Main-Line-669-j:' + j + '\nException:' + str(ex))


def write_clash_file():
    global clashurl
    global openclashurl
    global clash_node_url
    global proxies_url
    global clashname
    global telename
    global nodecount
    global datecont

    clashname = clashname.rstrip('\n')
    telename = telename.rstrip('\n')

    clashurl = clashurl.rstrip('\n')
    openclashurl = openclashurl.rstrip('\n')
    clash_node_url = clash_node_url.rstrip('\n')
    proxies_url = proxies_url.rstrip('\n')

    print('clashname:\n' + clashname)
    print('clashurl:\n' + clashurl)

    # 合并替换Clash节点信息，下载后回车行丢失
    # clash_1 = NetFile.down_res_file(resurl, 'clash-1.txt', 240, 120)
    # clash_2 = NetFile.down_res_file(resurl, 'clash-2.txt', 240, 120)
    if (clashname != ''):
        with open("./res/clash-1.txt", "r", encoding='utf-8') as f:  # 打开文件
            clash_1 = f.read()  # 读取文件
        with open("./res/clash-2.txt", "r", encoding='utf-8') as f:  # 打开文件
            clash_2 = f.read()  # 读取文件

        # 写入节点文件到本地ClashNode文件
        LocalFile.write_LocalFile('./o/proxies.txt', 'proxies:\n' + proxies_url)
        print('ClashNode-Proxies文件成功写入。(纯节点)')

        tmp = clash_1.replace("clash-url.txt", clashurl)
        tmp = tmp.replace("clash-name.txt", clashname)
        tmp = tmp.replace("tele-name.txt", telename)
        tmp = tmp.replace("clash-2.txt", clash_2)
        tmp = tmp.replace('\nexternal-ui: \'/usr/share/openclash/dashboard\'', '')
        # 写入节点文件到本地Clash文件
        LocalFile.write_LocalFile('./o/clash.yaml', tmp)
        print('Clash文件成功写入。')

        tmp = clash_1.replace("clash-url.txt", openclashurl)
        tmp = tmp.replace("clash-name.txt", clashname)
        tmp = tmp.replace("tele-name.txt", telename)
        tmp = tmp.replace("clash-2.txt", clash_2)
        # 写入节点文件到本地OpenClash文件
        LocalFile.write_LocalFile('./o/openclash.yaml', tmp)
        print('OpenClash文件成功写入。(添加UDP为True的参数)')

        tmp = 'proxies:' + clash_node_url
        # 写入节点文件到本地ClashNode文件
        LocalFile.write_LocalFile('./o/clashnode.txt', tmp)
        print('ClashNode文件成功写入。(纯节点)')


def node_to_carsh():
    # if os.path.exists('./o/allnode.txt'):
    #     allnodetxt = LocalFile.read_LocalFile('./o/allnode.txt')
    # else:
    #     allnodetxt = LocalFile.read_LocalFile('./node.txt')
    allnodetxt = LocalFile.read_LocalFile('./o/allnode.txt')
    allnodetxt = base64.b64decode(allnodetxt).decode('utf-8')

    if (len(allnodetxt) > 0):

        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
            futures = [executor.submit(node_handler, j) for j in allnodetxt.split('\n')]

        concurrent.futures.as_completed(futures)
        # for future in concurrent.futures.as_completed(futures):
        #     # merged_link = future.result()
        #     print(f'########  获取有效数量个数： {nodecount}')
        write_clash_file()
        write_v2ry_nodes()
    else:
        print('Main-Line-625:数据获取失败，暂停生成CLASH等链接。\nallnodetxt:' + allnodetxt)


def collect_urls(sub_links):
    write(sub_links)
    node_to_carsh()


def main(regetflag):
    if regetflag:
        sub_links = select_sub_urls(sub_url_arry)
        write(sub_links)
    # collect_urls(sub_links)
    node_to_carsh()
    # with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    #     futures = [executor.submit(select_nodes, url) for url in sub_links]
    #
    # for future in concurrent.futures.as_completed(futures):
    #     # merged_link = future.result()
    #     print(merged_link)
    # write(merged_link)


main(regetflag)
