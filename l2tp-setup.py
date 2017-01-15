#!/usr/bin/env python2.7

import os
import sys


def check_os_version():
    try:
        # Centos
        #    CentOS Linux release 7.2.1511 (Core)
        with open('/etc/redhat-release', 'r') as f:
            data = f.read()
            if data.find('CentOS') != -1 and data.find('release 7') != -1:
                return True
    except:
        return False

    return False


def get_ipaddr_list():
    f = os.popen("ifconfig -a | grep -w 'inet' | grep -v '128.0.01' | awk '{print $2;}'")
    addrs = f.readlines()
    f.close()

    temp = []
    for i in addrs:
        temp.append(i.strip(' \n'))
    return temp


def get_net_interface_list():
    f = os.popen('ifconfig | grep ": flags" | cut -d ":" -f1')
    interface_list = f.readlines()
    f.close()

    # Remove lo interface
    temp = []
    for i in interface_list:
        if i != 'ol':
            temp.append(i.strip(' \n'))

    return temp


def BackupFileIfExist(filepath):
    if os.path.exists(filepath):
        # If backup file is exist, remove it old backupfile
        backup_filepath = filepath + '.backup'
        if os.path.exists(backup_filepath):
            os.remove(backup_filepath)
        os.rename(filepath, filepath + '.backup')


def WriteFileWithContext(filepath, context):
    BackupFileIfExist(filepath)
    with open(filepath, 'w') as f:
        f.write(context)


class SetupInfo(object):
    ip_addr = ''
    interface_name = 'eth0'
    vpn_ip_range = '10.0.1'
    vpn_psk = 'mingoo'
    vpn_username = "mingoo"
    vpn_password = "mingoo"

    def PrintParameters(self):
        print "Setup parameter is: "
        print " server ip:\t%s" % self.ip_addr
        print " Server Local ip:\t%s.1" % self.vpn_ip_range
        print " Client Remote Ip Range:\t%s.10-%s.254" % (self.vpn_ip_range,
                                                          self.vpn_ip_range)
        print ""
        print "psk: %s" % self.vpn_psk
        print "username: %s" % self.vpn_username

    def GetDict(self):
        return {
            'server_ip': self.ip_addr,
            'interface_name': self.interface_name,
            'ip_range': self.vpn_ip_range,
            'psk': self.vpn_psk,
            'username': self.vpn_username,
            'password': self.vpn_password
        }


def RequireSetupInfo():

    setup_info = SetupInfo()

    # Get ipaddr from system
    ip_addrs = get_ipaddr_list()
    print 'System has following ipaddr: '
    for i in xrange(0, len(ip_addrs)):
        print ' %s). %s' % (i, ip_addrs[i])
    selected_id = raw_input('select a ip addr for vpn (eg. 1): ')

    selected_id = int(selected_id)
    if selected_id < 0 or selected_id >= len(ip_addrs):
        print 'choose a invalid ip'
        exit(-1)

    setup_info.ipaddr = ip_addrs[selected_id]

    # Get net interface name for vpn
    interface_list = get_net_interface_list()
    if len(interface_list) > 1:
        print '=================================='
        print 'Network Interface list:'
        for i in xrange(0, len(interface_list)):
            print ' %s). %s' % (i, interface_list[i])
        print 'Which network interface you want to listen for serv?'
        selected_id = int(raw_input('Please select one:'))
        if selected_id < 0 or selected_id >= len(interface_list):
            print 'Chose a invalid networ interface'
            exit(0)
        setup_info.interface_name = interface_list[selected_id]
    elif len(interface_list) == 1:
        setup_info.interface_name = interface_list[0]

    else:
        print "Can not find a valid net interface"
	exit(-1)

    print 'Use %s as default interface you want to listen for serv?' % (
        setup_info.interface_name)

    vpn_ip_range_tmp = raw_input(
        "Please input ip range(dfault is %s):" % setup_info.vpn_ip_range)
    if vpn_ip_range_tmp is not None and len(vpn_ip_range_tmp):
        setup_info.vpn_ip_range = "10.0.1"

    # Set pre PSK
    vpn_psk_tmp = raw_input(
        "Please input PSK(default is %s:" % setup_info.vpn_psk)
    if vpn_psk_tmp is not None and len(vpn_psk_tmp) > 0:
        setup_info.vpn_psk = vpn_psk_tmp

    # set vpn username
    vpn_username = raw_input(
        "Please input VPN username: ")
    if vpn_username is None or len(vpn_username) == 0:
        print "vpn username is invalid"
        exit(0)
    setup_info.vpn_username = vpn_username

    vpn_password = raw_input(
        "Please input VPN password: ")
    if vpn_password is None or len(vpn_password) == 0:
        print "VPN password is invalid"
        exit(0)

    vpn_password1 = raw_input(
        "Please input VPN password again: ")
    if vpn_password1 != vpn_password:
        print "Input password is not same"
        exit(-1)

    setup_info.vpn_password = vpn_password

    return setup_info


def SetupDependences():
    if 0 != os.system('yum -y update'):
        exit(-1)
    if 0 != os.system('yum install -y openswan ppp xl2tpd wget'):
        exit(-1)

    return True

ipsec_file_tpl = r'''# /etc/ipsec.conf - Libreswan IPsec configuration file
# This file:  /etc/ipsec.conf
#
# Enable when using this configuration file with openswan instead of libreswan
#version 2
#
# Manual:     ipsec.conf.5
# basic configuration
config setup
    # NAT-TRAVERSAL support, see README.NAT-Traversal
    nat_traversal=yes
    # exclude networks used on server side by adding %%v4:!a.b.c.0/24
    virtual_private=%%v4:10.0.0.0/8,%%v4:192.168.0.0/16,%%v4:172.16.0.0/12
    # OE is now off by default. Uncomment and change to on, to
    # enable.
    oe=off
    # which IPsec stack to use. auto will try netkey,
    # then klips then mast
    protostack=netkey
    force_keepalive=yes
    keep_alive=1800

conn L2TP-PSK-NAT
    rightsubnet=vhost:%%priv
    also=L2TP-PSK-noNAT

conn L2TP-PSK-noNAT
    authby=secret
    pfs=no
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=%(server_ip)s
    leftid=%(server_ip)s
    leftprotoport=17/1701
    right=%%any
    rightprotoport=17/%%any
    dpddelay=40
    dpdtimeout=130
    dpdaction=clear
    # For example connections, see your distribution's documentation # directory,
    # or the documentation which could be located at
    #  /usr/share/docs/libreswan-3.*/ or look at https://www.libreswan.org/
    #
    # There is also a lot of information in the manual page, "man ipsec.conf"

    # You may put your configuration (.conf) file in the "/etc/ipsec.d/" directory
    # by uncommenting this line
    # include /etc/ipsec.d/*.conf
'''

psk_config_tpl = r'''#include /etc/ipsec.d/*.secrets
%(server_ip)s %%any: PSK "%(psk)s"
'''

# For /etc/xl2tp/xl2tp.conf
xl2tpd_conf_tpl = r''';
; This is a minimal sample xl2tpd configuration file for use
; with L2TP over IPsec.
;
; The idea is to provide an L2TP daemon to which remote Windows L2TP/IPsec
; clients connect. In this example, the internal (protected) network
; is 192.168.1.0/24.  A special IP range within this network is reserved
; for the remote clients: 192.168.1.128/25
; (i.e. 192.168.1.128 ... 192.168.1.254)
;
; The listen-addr parameter can be used if you want to bind the L2TP daemon
; to a specific IP address instead of to all interfaces. For instance,
; you could bind it to the interface of the internal LAN (e.g. 192.168.1.98
; in the example below). Yet another IP address (local ip, e.g. 192.168.1.99)
; will be used by xl2tpd as its address on pppX interfaces.
[global]
; ipsec saref = yes
listen-addr = %(server_ip)s
auth file = /etc/ppp/chap-secrets
port = 1701
[lns default]
ip range = %(ip_range)s.10-%(ip_range)s.254
local ip = %(ip_range)s.1
refuse chap = yes
refuse pap = yes
require authentication = yes
name = L2TPVPN
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes'''


options_file_tpl = r'''#require-pap
#require-chap
#require-mschap
ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
mtu 1400
noccp
connect-delay 5000
# To allow authentication against a Windows domain EXAMPLE, and require the
# user to be in a group "VPN Users". Requires the samba-winbind package
# require-mschap-v2
# plugin winbind.so
# ntlm_auth-helper '/usr/bin/ntlm_auth --helper-protocol=ntlm-server-1
# --require-membership-of="EXAMPLE\VPN Users"'
# You need to join the domain on the server, for example using samba:
# http://rootmanager.com/ubuntu-ipsec-l2tp-windows-domain-auth/setting-up-openswan-xl2tpd-with-native-windows-clients-lucid.html
'''

# template for /etc/ppp/chap-secrets
chap_secrets_tpl = r'''# Secrets for authentication using CHAP
# client     server     secret               IP addresses
%(username)s          l2tpd     %(password)s               *
'''


def SetupConfig(setup_info):
    ''' Create config files '''

    setup_params = setup_info.GetDict()

    # Create ipsec.conf file
    WriteFileWithContext(
        '/etc/ipsec.conf',
        ipsec_file_tpl % setup_params)

    # Create PSK in config file
    WriteFileWithContext(
        '/etc/ipsec.secrets',
        psk_config_tpl % setup_params)

    # Create xl2tpd.conf file
    WriteFileWithContext(
        '/etc/xl2tpd/xl2tpd.conf',
        xl2tpd_conf_tpl % setup_params)

    # Create options.xl2tpd
    WriteFileWithContext(
        '/etc/ppp/options.xl2tpd',
        options_file_tpl % setup_params)

    # Create /etc/ppp/chap-secrets
    # write username and password
    WriteFileWithContext(
        '/etc/ppp/chap-secrets',
        chap_secrets_tpl % setup_params)


# file data template for /etc/sysctl.conf
sysctl_conf_tpl = r'''net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.%(interface_name)s.eth.rp_filter = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
'''


def SetupNetFoward(setup_info):
    setup_params = setup_info.GetDict()
    os.system('sysctl -w net.ipv4.ip_forward=1')
    os.system('sysctl -w net.ipv4.conf.all.rp_filter=0')
    os.system('sysctl -w net.ipv4.conf.default.rp_filter=0')
    os.system('sysctl -w net.ipv4.conf.%(interface_name)s.rp_filter=0' %
              setup_params)
    os.system('sysctl -w net.ipv4.conf.all.send_redirects=0')
    os.system('sysctl -w net.ipv4.conf.default.send_redirects=0')
    os.system('sysctl -w net.ipv4.conf.all.accept_redirects=0')
    os.system('sysctl -w net.ipv4.conf.default.accept_redirects=0')

    WriteFileWithContext(
        '/etc/sysctl.conf',
        sysctl_conf_tpl % setup_params)


# template for /usr/lib/firewalld/services/l2tpd.xml
l2tpd_xml = r'''<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>l2tpd</short>
  <description>L2TP IPSec</description>
  <port protocol="udp" port="500"/>
  <port protocol="udp" port="4500"/>
  <port protocol="udp" port="1701"/>
</service>
'''


def SetupFirewall(setup_info):
    WriteFileWithContext('/usr/lib/firewalld/services/l2tpd.xml', l2tpd_xml)

    commands = [
        'firewall-cmd --permanent --add-service=l2tpd',
        'firewall-cmd --permanent --add-service=ipsec',
        'firewall-cmd --permanent --add-masquerade',
        'firewall-cmd --reload',
        # iptables --table nat --append POSTROUTING --jump MASQUERADE
        # iptables -t nat -A POSTROUTING -s $iprange.0/24 -o $eth -j MASQUERADE
        # iptables -t nat -A POSTROUTING -s $iprange.0/24 -j SNAT --to-source $serverip
        # service iptables save
    ]

    for c in commands:
        os.system(c)


def SetupStartupWhenSytemStart():
    os.system('systemctl enable ipsec xl2tpd')
    os.system('systemctl restart ipsec xl2tpd')


def CheckSetupResult():
    os.system('ipsec verify')


def Main(args):
    # Require root to run this script
    if os.getuid() != 0:
        print 'You must be root to run this script!'
        exit(-1)

    if not check_os_version():
        print 'You current system is not CentOS 7'
        exit(-1)

    setup_info = RequireSetupInfo()

    raw_input('Input any button to start setup')

    SetupDependences()
    SetupConfig(setup_info)
    SetupNetFoward(setup_info)
    SetupFirewall(setup_info)
    SetupStartupWhenSytemStart()
    CheckSetupResult()


if __name__ == '__main__':
    Main(sys.argv)
